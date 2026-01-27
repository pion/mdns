// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package mdns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/pion/logging"
	"golang.org/x/net/dns/dnsmessage"
)

// qClassUnicastResponse is the bit flag for the unicast-response bit in the
// Question Section qclass field (RFC 6762, Section 18.12).
const qClassUnicastResponse = 1 << 15

var (
	errFailedToDecodeAddrFromAResource    = errors.New("failed to decode netip.Addr from A type Resource")
	errFailedToDecodeAddrFromAAAAResource = errors.New("failed to decode netip.Addr from AAAA type Resource")
	errUnhandledAnswerHeaderType          = errors.New("header for Answer had unhandled type")
)

// messageContext carries metadata about a received mDNS packet.
type messageContext struct {
	// source is the address the packet was received from.
	source *net.UDPAddr
	// ifIndex is the interface index the packet was received on (-1 if unknown).
	ifIndex int
	// pktDst is the destination address of the packet (for unicast detection).
	pktDst net.IP
	// timestamp is when the packet was received.
	timestamp time.Time
}

// questionWriter is the interface for sending DNS questions.
type questionWriter interface {
	writeQuestion(b []byte)
}

// client handles mDNS client operations (querying).
type client struct {
	log     logging.LeveledLogger
	name    string
	handler *answerHandler
	writer  questionWriter
	hasIPv4 bool
	hasIPv6 bool
}

// newClient creates a new mDNS client.
func newClient(
	log logging.LeveledLogger,
	name string,
	writer questionWriter,
	hasIPv4, hasIPv6 bool,
) *client {
	return &client{
		log:     log,
		name:    name,
		handler: newAnswerHandler(log, name),
		writer:  writer,
		hasIPv4: hasIPv4,
		hasIPv6: hasIPv6,
	}
}

// sendQuestion sends mDNS queries for the given name.
func (c *client) sendQuestion(name string) {
	packedName, err := dnsmessage.NewName(name)
	if err != nil {
		c.log.Warnf("[%s] failed to construct mDNS packet %v", c.name, err)

		return
	}

	// https://datatracker.ietf.org/doc/html/draft-ietf-rtcweb-mdns-ice-candidates-04#section-3.2.1
	//
	// 2.  Otherwise, resolve the candidate using mDNS.  The ICE agent
	//     SHOULD set the unicast-response bit of the corresponding mDNS
	//     query message; this minimizes multicast traffic, as the response
	//     is probably only useful to the querying node.
	//
	// 18.12.  Repurposing of Top Bit of qclass in Question Section
	//
	// In the Question Section of a Multicast DNS query, the top bit of the
	// qclass field is used to indicate that unicast responses are preferred
	// for this particular question.  (See Section 5.4.)
	//
	// We'll follow this up sending on our unicast based packet connections so that we can
	// get a unicast response back.
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{},
	}

	// limit what we ask for based on what IPv is available. In the future,
	// this could be an option since there's no reason you cannot get an
	// A record on an IPv6 sourced question and vice versa.
	if c.hasIPv4 {
		msg.Questions = append(msg.Questions, dnsmessage.Question{
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET | qClassUnicastResponse,
			Name:  packedName,
		})
	}
	if c.hasIPv6 {
		msg.Questions = append(msg.Questions, dnsmessage.Question{
			Type:  dnsmessage.TypeAAAA,
			Class: dnsmessage.ClassINET | qClassUnicastResponse,
			Name:  packedName,
		})
	}

	rawQuery, err := msg.Pack()
	if err != nil {
		c.log.Warnf("[%s] failed to construct mDNS packet %v", c.name, err)

		return
	}

	c.writer.writeQuestion(rawQuery)
}

// sendBrowseQuestion sends a PTR query for a DNS-SD service type.
func (c *client) sendBrowseQuestion(serviceName string) {
	packedName, err := dnsmessage.NewName(serviceName)
	if err != nil {
		c.log.Warnf("[%s] failed to construct browse query name %v", c.name, err)

		return
	}

	msg := dnsmessage.Message{
		Header: dnsmessage.Header{},
		Questions: []dnsmessage.Question{
			{
				Type:  dnsmessage.TypePTR,
				Class: dnsmessage.ClassINET,
				Name:  packedName,
			},
		},
	}

	rawQuery, err := msg.Pack()
	if err != nil {
		c.log.Warnf("[%s] failed to pack browse query %v", c.name, err)

		return
	}

	c.writer.writeQuestion(rawQuery)
}

// sendEnumerateQuestion sends a PTR query for the service type enumeration
// meta-query (RFC 6763 §9).
func (c *client) sendEnumerateQuestion(domain string) {
	name := serviceTypeEnumerationName + "." + domain + "."
	packedName, err := dnsmessage.NewName(name)
	if err != nil {
		c.log.Warnf("[%s] failed to construct enumerate query name %v", c.name, err)

		return
	}

	msg := dnsmessage.Message{
		Header: dnsmessage.Header{},
		Questions: []dnsmessage.Question{
			{
				Type:  dnsmessage.TypePTR,
				Class: dnsmessage.ClassINET,
				Name:  packedName,
			},
		},
	}

	rawQuery, err := msg.Pack()
	if err != nil {
		c.log.Warnf("[%s] failed to pack enumerate query %v", c.name, err)

		return
	}

	c.writer.writeQuestion(rawQuery)
}

// answerHandler processes incoming mDNS answers (client role).
// It matches answers against registered queries and delivers results.
// It also processes answers for active browse and enumerate sessions.
type answerHandler struct {
	mu                sync.RWMutex
	queries           []*query
	browseSessions    []*browseSession
	enumerateSessions []*enumerateSession
	log               logging.LeveledLogger
	name              string
}

// newAnswerHandler creates a new answerHandler.
func newAnswerHandler(log logging.LeveledLogger, name string) *answerHandler {
	return &answerHandler{
		log:  log,
		name: name,
	}
}

// registerQuery adds a query to be matched against incoming answers.
// Returns the query so it can be unregistered later.
func (h *answerHandler) registerQuery(nameWithSuffix string, resultChan chan queryResult) *query {
	q := &query{
		nameWithSuffix:  nameWithSuffix,
		queryResultChan: resultChan,
	}
	h.mu.Lock()
	h.queries = append(h.queries, q)
	h.mu.Unlock()

	return q
}

// unregisterQuery removes a query from the handler.
func (h *answerHandler) unregisterQuery(q *query) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := len(h.queries) - 1; i >= 0; i-- {
		if h.queries[i] == q {
			h.queries = append(h.queries[:i], h.queries[i+1:]...)
		}
	}
}

// registerBrowseSession adds a browse session to be matched against incoming answers.
func (h *answerHandler) registerBrowseSession(session *browseSession) {
	h.mu.Lock()
	h.browseSessions = append(h.browseSessions, session)
	h.mu.Unlock()
}

// unregisterBrowseSession removes a browse session from the handler.
func (h *answerHandler) unregisterBrowseSession(session *browseSession) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := len(h.browseSessions) - 1; i >= 0; i-- {
		if h.browseSessions[i] == session {
			h.browseSessions = append(h.browseSessions[:i], h.browseSessions[i+1:]...)
		}
	}
}

// registerEnumerateSession adds an enumerate session to be matched against incoming answers.
func (h *answerHandler) registerEnumerateSession(session *enumerateSession) {
	h.mu.Lock()
	h.enumerateSessions = append(h.enumerateSessions, session)
	h.mu.Unlock()
}

// unregisterEnumerateSession removes an enumerate session from the handler.
func (h *answerHandler) unregisterEnumerateSession(session *enumerateSession) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for i := len(h.enumerateSessions) - 1; i >= 0; i-- {
		if h.enumerateSessions[i] == session {
			h.enumerateSessions = append(h.enumerateSessions[:i], h.enumerateSessions[i+1:]...)
		}
	}
}

// handle processes a DNS message containing answers.
// It matches answers against registered name queries, active browse sessions,
// and active enumerate sessions.
//
//nolint:cyclop,gocognit
func (h *answerHandler) handle(ctx *messageContext, msg *dnsmessage.Message) {
	h.mu.RLock()
	queries := make([]*query, len(h.queries))
	copy(queries, h.queries)
	browseSessions := make([]*browseSession, len(h.browseSessions))
	copy(browseSessions, h.browseSessions)
	enumerateSessions := make([]*enumerateSession, len(h.enumerateSessions))
	copy(enumerateSessions, h.enumerateSessions)
	h.mu.RUnlock()

	// Process all records (Answers + Additionals) for browse and enumerate sessions.
	allRecords := make([]dnsmessage.Resource, 0, len(msg.Answers)+len(msg.Additionals))
	allRecords = append(allRecords, msg.Answers...)
	allRecords = append(allRecords, msg.Additionals...)

	for _, answer := range allRecords {
		// Match against browse sessions (all record types).
		for _, session := range browseSessions {
			session.processRecord(answer, ctx.source.Zone)
		}

		// Match against enumerate sessions (PTR only).
		for _, session := range enumerateSessions {
			session.processRecord(answer)
		}
	}

	// Match A/AAAA answers against registered name queries (existing behavior).
	for _, answer := range msg.Answers {
		if answer.Header.Type != dnsmessage.TypeA && answer.Header.Type != dnsmessage.TypeAAAA {
			continue
		}

		var answered []*query
		for _, q := range queries {
			queryCopy := q
			if !strings.EqualFold(queryCopy.nameWithSuffix, answer.Header.Name.String()) {
				continue
			}

			addr, err := addrFromAnswer(answer)
			if err != nil {
				h.log.Warnf("[%s] failed to parse mDNS answer %v", h.name, err)

				continue
			}

			resultAddr := *addr
			// DNS records don't contain IPv6 zones.
			// Trust that link-local addresses are from the source's interface.
			resultAddr = addrWithOptionalZone(resultAddr, ctx.source.Zone)

			select {
			case queryCopy.queryResultChan <- queryResult{answer.Header, resultAddr}:
				answered = append(answered, queryCopy)
			default:
			}
		}

		// Remove answered queries.
		h.mu.Lock()
		for queryIdx := len(h.queries) - 1; queryIdx >= 0; queryIdx-- {
			for answerIdx := len(answered) - 1; answerIdx >= 0; answerIdx-- {
				if h.queries[queryIdx] == answered[answerIdx] {
					h.queries = append(h.queries[:queryIdx], h.queries[queryIdx+1:]...)
					answered = append(answered[:answerIdx], answered[answerIdx+1:]...)

					break
				}
			}
		}
		h.mu.Unlock()
	}
}

// pendingInstance tracks a partially-resolved DNS-SD service instance.
// A browse session collects PTR → SRV + TXT → A/AAAA records before emitting
// a complete ServiceEvent.
type pendingInstance struct {
	instance string // from PTR rdata
	service  string
	domain   string
	host     string
	port     uint16
	priority uint16
	weight   uint16
	text     []txtKeyValue
	addr     netip.Addr
	hasSRV   bool
	hasTXT   bool
	hasAddr  bool
}

// isComplete returns true when all required records have been resolved.
func (p *pendingInstance) isComplete() bool {
	return p.hasSRV && p.hasTXT && p.hasAddr
}

// toServiceEvent converts a complete pending instance to a ServiceEvent.
func (p *pendingInstance) toServiceEvent() ServiceEvent {
	return ServiceEvent{
		Instance: ServiceInstance{
			Instance: p.instance,
			Service:  p.service,
			Domain:   p.domain,
			Host:     p.host,
			Port:     p.port,
			Priority: p.priority,
			Weight:   p.weight,
			Text:     p.text,
		},
		Addr: p.addr,
	}
}

// browseSession tracks the state of an active Browse call.
type browseSession struct {
	serviceType string // e.g. "_http._tcp"
	domain      string // e.g. "local"
	emit        func(ServiceEvent)
	seen        map[string]bool             // instance names already emitted
	pending     map[string]*pendingInstance // instances being assembled
	mu          sync.Mutex
	done        chan struct{}
	cancel      context.CancelFunc
}

// newBrowseSession creates a new browse session.
func newBrowseSession(ctx context.Context, serviceType string, emit func(ServiceEvent)) *browseSession {
	sessionCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})

	go func() {
		<-sessionCtx.Done()
		close(done)
	}()

	return &browseSession{
		serviceType: serviceType,
		domain:      "local",
		emit:        emit,
		seen:        make(map[string]bool),
		pending:     make(map[string]*pendingInstance),
		done:        done,
		cancel:      cancel,
	}
}

// serviceName returns the fully-qualified browse query name.
func (bs *browseSession) serviceName() string {
	return bs.serviceType + "." + bs.domain + "."
}

// processRecord updates the browse session with a received DNS resource record.
// Returns true if a new complete instance was emitted.
//
//nolint:cyclop
func (bs *browseSession) processRecord(answer dnsmessage.Resource, zone string) bool {
	bs.mu.Lock()
	defer bs.mu.Unlock()

	switch answer.Header.Type {
	case dnsmessage.TypePTR:
		bs.handlePTRRecord(answer)

		return false
	case dnsmessage.TypeSRV:
		return bs.handleSRVRecord(answer, zone)
	case dnsmessage.TypeTXT:
		return bs.handleTXTRecord(answer)
	case dnsmessage.TypeA, dnsmessage.TypeAAAA:
		return bs.handleAddressRecord(answer, zone)
	default:
		return false
	}
}

// handlePTRRecord processes a PTR answer for this browse session.
func (bs *browseSession) handlePTRRecord(answer dnsmessage.Resource) {
	target, err := parsePTRTarget(answer.Body)
	if err != nil {
		return
	}

	instance, service, domain, err := parseServiceInstanceName(target)
	if err != nil {
		return
	}

	if bs.seen[instance] {
		return
	}

	if _, exists := bs.pending[instance]; !exists {
		bs.pending[instance] = &pendingInstance{
			instance: instance,
			service:  service,
			domain:   domain,
		}
	}
}

// handleSRVRecord processes an SRV answer.
func (bs *browseSession) handleSRVRecord(answer dnsmessage.Resource, zone string) bool {
	target, port, priority, weight, err := parseSRVData(answer.Body)
	if err != nil {
		return false
	}

	inst := bs.findPendingByInstanceName(answer.Header.Name.String())
	if inst == nil {
		return false
	}

	inst.host = target
	inst.port = port
	inst.priority = priority
	inst.weight = weight
	inst.hasSRV = true

	return bs.tryEmit(inst, zone)
}

// handleTXTRecord processes a TXT answer.
func (bs *browseSession) handleTXTRecord(answer dnsmessage.Resource) bool {
	txts, err := parseTXTData(answer.Body)
	if err != nil {
		return false
	}

	inst := bs.findPendingByInstanceName(answer.Header.Name.String())
	if inst == nil {
		return false
	}

	inst.text = decodeTXTRecordStrings(txts)
	inst.hasTXT = true

	return bs.tryEmit(inst, "")
}

// handleAddressRecord processes an A or AAAA answer.
func (bs *browseSession) handleAddressRecord(answer dnsmessage.Resource, zone string) bool {
	addr, err := addrFromAnswer(answer)
	if err != nil {
		return false
	}

	resultAddr := addrWithOptionalZone(*addr, zone)

	// Match against any pending instance whose host matches this answer name.
	answerName := answer.Header.Name.String()
	emitted := false
	for _, inst := range bs.pending {
		if !inst.hasSRV {
			continue
		}
		if !strings.EqualFold(inst.host, answerName) {
			continue
		}

		inst.addr = resultAddr
		inst.hasAddr = true

		if bs.tryEmit(inst, zone) {
			emitted = true
		}
	}

	return emitted
}

// findPendingByInstanceName finds a pending instance matching the given FQDN.
func (bs *browseSession) findPendingByInstanceName(name string) *pendingInstance {
	for _, inst := range bs.pending {
		fqdn := inst.instance
		if inst.service != "" {
			fqdn = escapeInstanceName(inst.instance) + "." + inst.service + "." + inst.domain + "."
		}
		if strings.EqualFold(fqdn, name) {
			return inst
		}
	}

	return nil
}

// tryEmit fires the callback if the instance is complete and not yet emitted.
func (bs *browseSession) tryEmit(inst *pendingInstance, zone string) bool {
	if !inst.isComplete() {
		return false
	}
	if bs.seen[inst.instance] {
		return false
	}

	bs.seen[inst.instance] = true

	if zone != "" {
		inst.addr = addrWithOptionalZone(inst.addr, zone)
	}

	evt := inst.toServiceEvent()
	bs.emit(evt)
	delete(bs.pending, inst.instance)

	return true
}

// enumerateSession tracks the state of an active EnumerateServiceTypes call.
type enumerateSession struct {
	domain string
	emit   func(string)
	seen   map[string]bool
	mu     sync.Mutex
	done   chan struct{}
	cancel context.CancelFunc
}

// newEnumerateSession creates a new enumerate session.
func newEnumerateSession(ctx context.Context, emit func(string)) *enumerateSession {
	sessionCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})

	go func() {
		<-sessionCtx.Done()
		close(done)
	}()

	return &enumerateSession{
		domain: "local",
		emit:   emit,
		seen:   make(map[string]bool),
		done:   done,
		cancel: cancel,
	}
}

// processRecord handles a PTR answer for the service type enumeration meta-query.
func (es *enumerateSession) processRecord(answer dnsmessage.Resource) {
	if answer.Header.Type != dnsmessage.TypePTR {
		return
	}

	target, err := parsePTRTarget(answer.Body)
	if err != nil {
		return
	}

	// Target is like "_http._tcp.local." — extract the service type.
	target = strings.TrimSuffix(target, ".")
	parts := strings.SplitN(target, ".", 3)
	if len(parts) < 2 {
		return
	}
	serviceType := parts[0] + "." + parts[1]

	es.mu.Lock()
	defer es.mu.Unlock()

	if es.seen[serviceType] {
		return
	}
	es.seen[serviceType] = true

	es.emit(serviceType)
}

func addrFromAnswer(answer dnsmessage.Resource) (*netip.Addr, error) {
	switch answer.Header.Type {
	case dnsmessage.TypeA:
		if a, ok := answer.Body.(*dnsmessage.AResource); ok {
			addr, ok := netip.AddrFromSlice(a.A[:])
			if ok {
				addr = addr.Unmap() // do not want 4-in-6

				return &addr, nil
			}
		}

		return nil, errFailedToDecodeAddrFromAResource
	case dnsmessage.TypeAAAA:
		if a, ok := answer.Body.(*dnsmessage.AAAAResource); ok {
			addr, ok := netip.AddrFromSlice(a.AAAA[:])
			if ok {
				return &addr, nil
			}
		}

		return nil, errFailedToDecodeAddrFromAAAAResource
	default:
		return nil, errUnhandledAnswerHeaderType
	}
}
