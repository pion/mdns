// SPDX-FileCopyrightText: The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package mdns

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/pion/logging"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type ipToBytesError struct {
	addr         netip.Addr
	expectedType string
}

func (err ipToBytesError) Error() string {
	return fmt.Sprintf("ip (%s) is not %s", err.addr, err.expectedType)
}

// ipv4ToBytes converts an IPv4 address to a 4-byte array.
// Assumes ipv4-to-ipv6 mapping has been checked.
func ipv4ToBytes(ipAddr netip.Addr) ([4]byte, error) {
	if !ipAddr.Is4() {
		return [4]byte{}, ipToBytesError{ipAddr, "IPv4"}
	}

	md, err := ipAddr.MarshalBinary()
	if err != nil {
		return [4]byte{}, err
	}

	// net.IPs are stored in big endian / network byte order
	var out [4]byte
	copy(out[:], md)

	return out, nil
}

// ipv6ToBytes converts an IPv6 address to a 16-byte array.
// Assumes ipv4-to-ipv6 mapping has been checked.
func ipv6ToBytes(ipAddr netip.Addr) ([16]byte, error) {
	if !ipAddr.Is6() {
		return [16]byte{}, ipToBytesError{ipAddr, "IPv6"}
	}
	md, err := ipAddr.MarshalBinary()
	if err != nil {
		return [16]byte{}, err
	}

	// net.IPs are stored in big endian / network byte order
	var out [16]byte
	copy(out[:], md)

	return out, nil
}

// answerWriter is the interface for sending DNS answers.
type answerWriter interface {
	writeAnswer(ifIndex int, b []byte, hasLoopbackData, hasIPv6Zone bool, unicastDst *net.UDPAddr)
}

// server handles mDNS server operations (responding to queries).
type server struct {
	log     logging.LeveledLogger
	name    string
	handler *questionHandler
	writer  answerWriter
	ttl     uint32

	mu                         sync.RWMutex
	services                   []ServiceInstance
	txtAnnouncementGeneration  uint64
	txtAnnouncementGenerations map[registeredServiceKey]uint64
}

type registeredServiceKey struct {
	instance string
	service  string
}

// newServer creates a new mDNS server.
func newServer(
	log logging.LeveledLogger,
	name string,
	writer answerWriter,
	localNames []string,
	localAddress net.IP,
	ifaces map[int]netInterface,
	hasIPv4 bool,
	dstAddr4, dstAddr6 *net.UDPAddr,
	ttl uint32,
	services []ServiceInstance,
	allowedRecordTypes []dnsmessage.Type,
) *server {
	srv := &server{
		log:      log,
		name:     name,
		writer:   writer,
		ttl:      ttl,
		services: services,
	}
	srv.handler = newQuestionHandler(
		localNames,
		localAddress,
		ifaces,
		hasIPv4,
		srv, // server implements answerSender
		log,
		name,
		dstAddr4,
		dstAddr6,
		allowedRecordTypes,
	)

	return srv
}

// registerService adds a DNS-SD service to the server.
func (s *server) registerService(svc ServiceInstance) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.services = append(s.services, svc)
}

// updateTXT replaces a registered service's TXT data and sends the first
// cache-flushed announcement.
// https://www.rfc-editor.org/rfc/rfc6762.html#section-8.3
func (s *server) updateTXT(instance, service string, text []TXTEntry) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.services {
		if s.services[i].Instance != instance || s.services[i].Service != service {
			continue
		}
		if txtEntriesEqual(s.services[i].Text, text) {
			return 0, nil
		}

		updated := s.services[i]
		updated.Text = cloneTXTEntries(text)

		txtStrings, err := encodeTXTRecordStrings(updated.Text)
		if err != nil {
			return 0, err
		}
		rawAnnouncement, err := s.packTXTAnnouncement(&updated, txtStrings)
		if err != nil {
			return 0, err
		}

		s.txtAnnouncementGeneration++
		if s.txtAnnouncementGeneration == 0 {
			s.txtAnnouncementGeneration++
		}
		if s.txtAnnouncementGenerations == nil {
			s.txtAnnouncementGenerations = make(map[registeredServiceKey]uint64)
		}
		generation := s.txtAnnouncementGeneration
		s.txtAnnouncementGenerations[registeredServiceKey{instance: instance, service: service}] = generation

		s.services[i] = updated
		s.writer.writeAnswer(-1, rawAnnouncement, false, false, nil)

		return generation, nil
	}

	return 0, errServiceNotFound
}

func (s *server) repeatTXTAnnouncement(instance, service string, generation uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := registeredServiceKey{instance: instance, service: service}
	if s.txtAnnouncementGenerations[key] != generation {
		return nil
	}
	for i := range s.services {
		if s.services[i].Instance != instance || s.services[i].Service != service {
			continue
		}

		txtStrings, err := encodeTXTRecordStrings(s.services[i].Text)
		if err != nil {
			return err
		}
		rawAnnouncement, err := s.packTXTAnnouncement(&s.services[i], txtStrings)
		if err != nil {
			return err
		}
		s.writer.writeAnswer(-1, rawAnnouncement, false, false, nil)

		return nil
	}

	return nil
}

func (s *server) packTXTAnnouncement(svc *ServiceInstance, txtStrings []string) ([]byte, error) {
	txtRecord, err := buildTXTResource(svc.serviceInstanceName(), txtStrings, s.ttl)
	if err != nil {
		return nil, err
	}
	txtRecord.Header.Class |= rrClassCacheFlush

	return (&dnsmessage.Message{
		Header:  dnsmessage.Header{Response: true, Authoritative: true},
		Answers: []dnsmessage.Resource{txtRecord},
	}).Pack()
}

// unregisterService removes a DNS-SD service from the server by instance+service match.
func (s *server) unregisterService(instance, service string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := len(s.services) - 1; i >= 0; i-- {
		if s.services[i].Instance == instance && s.services[i].Service == service {
			s.services = append(s.services[:i], s.services[i+1:]...)
			delete(s.txtAnnouncementGenerations, registeredServiceKey{instance: instance, service: service})

			return
		}
	}
}

// getServices returns a snapshot of registered services.
func (s *server) getServices() []ServiceInstance {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]ServiceInstance, len(s.services))
	copy(out, s.services)

	return out
}

// sendAnswer implements answerSender: it builds the response to one question
// and hands it to the writer. Nothing is sent when the queried name owns no
// record of the answer types, as a responder only sends positive responses
// (RFC 6762 §6).
func (s *server) sendAnswer(
	queryID uint16, question dnsmessage.Question, ifIndex int,
	match nameMatch, dst *net.UDPAddr, isUnicast bool,
) {
	msg, addrs, err := s.createAnswer(queryID, question, &match, isUnicast)
	if err != nil {
		s.log.Warnf("[%s] failed to create mDNS answer %v", s.name, err)

		return
	}
	if len(msg.Answers) == 0 {
		return
	}

	rawAnswer, err := msg.Pack()
	if err != nil {
		s.log.Warnf("[%s] failed to construct mDNS packet %v", s.name, err)

		return
	}

	// The addresses carried in the message decide how it may be delivered:
	// loopback addresses only over a loopback interface and zoned addresses
	// only over IPv6 (see writeAnswer).
	var hasLoopbackData, hasIPv6Zone bool
	for _, addr := range addrs {
		hasLoopbackData = hasLoopbackData || addr.IsLoopback()
		hasIPv6Zone = hasIPv6Zone || (addr.Is6() && addr.Zone() != "")
	}

	s.log.Debugf("[%s] sending response for %s on ifc %d to %s", s.name, question.Name, ifIndex, dst)
	s.writer.writeAnswer(ifIndex, rawAnswer, hasLoopbackData, hasIPv6Zone, dst)
}

// serverConfig holds the configuration for a Server.
// This is populated by applying ServerOption functions.
type serverConfig struct {
	// name is the name of the server used for logging purposes.
	name string

	// localNames are the names that we will generate answers for
	// when we get questions.
	localNames []string

	// localAddress will override the published address with the given IP
	// when set. Otherwise, the automatically determined address will be used.
	localAddress net.IP

	// loggerFactory is used to create a logger for the server.
	loggerFactory logging.LoggerFactory

	// includeLoopback will include loopback interfaces to be eligible for answers.
	includeLoopback bool

	// interfaces will override the interfaces used for answers.
	interfaces []net.Interface

	// allowedRecordTypes limits which DNS record types the server will process.
	// If empty (default), all record types are allowed - no filtering is applied.
	// For WebRTC/ICE legacy behavior, set to {dnsmessage.TypeA, dnsmessage.TypeAAAA}.
	allowedRecordTypes []dnsmessage.Type

	// responseTTL is the TTL (in seconds) for DNS response records.
	// Defaults to 120 seconds per RFC 6762 recommendation.
	responseTTL uint32

	// services are the DNS-SD services to advertise (RFC 6763).
	services []ServiceInstance

	// cacheRefresh enables proactive cache refresh per RFC 6762 §5.2.
	// When true, actively-monitored records are re-queried at 80/85/90/95%
	// of their TTL. Defaults to true for NewServer, false for legacy Server.
	cacheRefresh bool

	// refreshCheckInterval is how often the refresh loop checks for
	// records due for refresh. Zero means use defaultRefreshCheckInterval.
	refreshCheckInterval time.Duration

	// queryInterval is how ofen the client check records due for query.
	// Zero means use defaultQueryInterval.
	queryInterval time.Duration
}

// NewServer creates a new mDNS server with the given options.
//
// At least one of the multicast packet connections must be non-nil.
// The presence of each IP type of PacketConn will dictate what kinds
// of questions are sent for queries. That is, if an ipv6.PacketConn is
// provided, then AAAA questions will be sent. A questions will only be
// sent if an ipv4.PacketConn is also provided.
//
// Example:
//
//	// Create multicast listeners
//	addr4, _ := net.ResolveUDPAddr("udp4", mdns.DefaultAddressIPv4)
//	l4, _ := net.ListenUDP("udp4", addr4)
//
//	addr6, _ := net.ResolveUDPAddr("udp6", mdns.DefaultAddressIPv6)
//	l6, _ := net.ListenUDP("udp6", addr6)
//
//	// Create server with options
//	server, err := mdns.NewServer(
//	    ipv4.NewPacketConn(l4),
//	    ipv6.NewPacketConn(l6),
//	    mdns.WithLocalNames("myservice.local"),
//	)
//
//nolint:gocognit,gocyclo,cyclop,maintidx
func NewServer(
	multicastPktConnV4 *ipv4.PacketConn,
	multicastPktConnV6 *ipv6.PacketConn,
	opts ...ServerOption,
) (*Conn, error) {
	// Apply options to config
	cfg := &serverConfig{cacheRefresh: true}
	for _, opt := range opts {
		if err := opt.applyServer(cfg); err != nil {
			return nil, err
		}
	}

	loggerFactory := cfg.loggerFactory
	if loggerFactory == nil {
		loggerFactory = logging.NewDefaultLoggerFactory()
	}
	log := loggerFactory.NewLogger("mdns")

	// Default TTL per RFC 6762 recommendation
	if cfg.responseTTL == 0 {
		cfg.responseTTL = responseTTL
	}

	conn := &Conn{
		queryInterval:        cfg.queryInterval,
		log:                  log,
		cache:                newCache(time.Now),
		stopBackground:       make(chan struct{}),
		cacheRefresh:         cfg.cacheRefresh,
		refreshCheckInterval: cfg.refreshCheckInterval,
		closed:               make(chan any),
	}
	conn.name = cfg.name
	if conn.name == "" {
		conn.name = fmt.Sprintf("%p", &conn)
	}

	if multicastPktConnV4 == nil && multicastPktConnV6 == nil {
		return nil, errNoPacketConn
	}

	ifaces := cfg.interfaces
	if ifaces == nil {
		var err error
		ifaces, err = net.Interfaces()
		if err != nil {
			return nil, err
		}
	}

	var unicastPktConnV4 *ipv4.PacketConn
	{
		addr4, err := net.ResolveUDPAddr("udp4", "0.0.0.0:0")
		if err != nil {
			return nil, err
		}

		unicastConnV4, err := net.ListenUDP("udp4", addr4)
		if err != nil {
			log.Warnf(
				"[%s] failed to listen on unicast IPv4 %s: %s; will not be able to receive unicast responses on IPv4",
				conn.name, addr4, err,
			)
		} else {
			unicastPktConnV4 = ipv4.NewPacketConn(unicastConnV4)
		}
	}

	var unicastPktConnV6 *ipv6.PacketConn
	{
		addr6, err := net.ResolveUDPAddr("udp6", "[::]:")
		if err != nil {
			return nil, err
		}

		unicastConnV6, err := net.ListenUDP("udp6", addr6)
		if err != nil {
			log.Warnf(
				"[%s] failed to listen on unicast IPv6 %s: %s; will not be able to receive unicast responses on IPv6",
				conn.name, addr6, err,
			)
		} else {
			unicastPktConnV6 = ipv6.NewPacketConn(unicastConnV6)
		}
	}

	multicastGroup4 := net.IPv4(224, 0, 0, 251)
	multicastGroupAddr4 := &net.UDPAddr{IP: multicastGroup4}

	// FF02::FB
	multicastGroup6 := net.IP{0xff, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xfb}
	multicastGroupAddr6 := &net.UDPAddr{IP: multicastGroup6}

	inboundBufferSize := 0
	joinErrCount := 0
	ifacesToUse := make(map[int]netInterface, len(ifaces))
	for i := range ifaces {
		ifc := ifaces[i]
		if !cfg.includeLoopback && ifc.Flags&net.FlagLoopback == net.FlagLoopback {
			continue
		}
		if ifc.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		var supportsV4, supportsV6 bool
		ifcIPAddrs := make([]netip.Addr, 0, len(addrs))
		for _, addr := range addrs {
			var ipToConv net.IP
			switch addr := addr.(type) {
			case *net.IPNet:
				ipToConv = addr.IP
			case *net.IPAddr:
				ipToConv = addr.IP
			default:
				continue
			}

			ipAddr, ok := netip.AddrFromSlice(ipToConv)
			if !ok {
				continue
			}
			if multicastPktConnV4 != nil {
				// don't want mapping since we also support IPv4/A
				ipAddr = ipAddr.Unmap()
			}
			ipAddr = addrWithOptionalZone(ipAddr, ifc.Name)

			if ipAddr.Is6() && !ipAddr.Is4In6() {
				supportsV6 = true
			} else {
				// we'll claim we support v4 but defer if we send it or not
				// based on IPv4-to-IPv6 mapping rules later (search for Is4In6 below)
				supportsV4 = true
			}
			ifcIPAddrs = append(ifcIPAddrs, ipAddr)
		}
		if !supportsV4 && !supportsV6 {
			continue
		}

		var atLeastOneJoin bool
		if supportsV4 && multicastPktConnV4 != nil {
			if err := multicastPktConnV4.JoinGroup(&ifc, multicastGroupAddr4); err == nil {
				atLeastOneJoin = true
			}
		}
		if supportsV6 && multicastPktConnV6 != nil {
			if err := multicastPktConnV6.JoinGroup(&ifc, multicastGroupAddr6); err == nil {
				atLeastOneJoin = true
			}
		}
		if !atLeastOneJoin {
			joinErrCount++

			continue
		}

		ifacesToUse[ifc.Index] = netInterface{
			Interface:  ifc,
			ipAddrs:    ifcIPAddrs,
			supportsV4: supportsV4,
			supportsV6: supportsV6,
		}
		if ifc.MTU > inboundBufferSize {
			inboundBufferSize = ifc.MTU
		}
	}

	if len(ifacesToUse) == 0 {
		return nil, errNoUsableInterfaces
	}
	if inboundBufferSize == 0 {
		return nil, errNoPositiveMTUFound
	}
	if inboundBufferSize > maxPacketSize {
		inboundBufferSize = maxPacketSize
	}
	if joinErrCount >= len(ifaces) {
		return nil, errJoiningMulticastGroup
	}

	dstAddr4, err := net.ResolveUDPAddr("udp4", destinationAddress4)
	if err != nil {
		return nil, err
	}

	dstAddr6, err := net.ResolveUDPAddr("udp6", destinationAddress6)
	if err != nil {
		return nil, err
	}

	var localNames []string
	for _, l := range cfg.localNames {
		localNames = append(localNames, l+".")
	}

	conn.dstAddr4 = dstAddr4
	conn.dstAddr6 = dstAddr6
	conn.localNames = localNames
	conn.ifaces = ifacesToUse

	conn.multicastPktConnV4 = configurePacketConn4(multicastPktConnV4, conn.name, "multicast", log)
	conn.multicastPktConnV6 = configurePacketConn6(multicastPktConnV6, conn.name, "multicast", log)
	conn.unicastPktConnV4 = configurePacketConn4(unicastPktConnV4, conn.name, "unicast", log)
	conn.unicastPktConnV6 = configurePacketConn6(unicastPktConnV6, conn.name, "unicast", log)

	// Create client and server for processing messages
	conn.client = newClient(
		log,
		conn.name,
		conn, // Conn implements questionWriter
		multicastPktConnV4 != nil,
		multicastPktConnV6 != nil,
		conn.cache,
	)
	// Ensure each service has the host set to the server's hostname.
	for i := range cfg.services {
		if cfg.services[i].Host == "" && len(localNames) > 0 {
			cfg.services[i].Host = localNames[0]
		}
	}

	conn.server = newServer(
		log,
		conn.name,
		conn, // Conn implements answerWriter
		localNames,
		cfg.localAddress,
		ifacesToUse,
		multicastPktConnV4 != nil,
		dstAddr4,
		dstAddr6,
		cfg.responseTTL,
		cfg.services,
		cfg.allowedRecordTypes,
	)

	if cfg.includeLoopback {
		// Enable loopback for efficient self-messaging without going through the network stack.
		enableLoopback4(multicastPktConnV4, conn.name, "multicast", log)
		enableLoopback6(multicastPktConnV6, conn.name, "multicast", log)
		enableLoopback4(unicastPktConnV4, conn.name, "unicast", log)
		enableLoopback6(unicastPktConnV6, conn.name, "unicast", log)
	}

	// https://www.rfc-editor.org/rfc/rfc6762.html#section-17
	// Multicast DNS messages carried by UDP may be up to the IP MTU of the
	// physical interface, less the space required for the IP header (20
	// bytes for IPv4; 40 bytes for IPv6) and the UDP header (8 bytes).
	started := make(chan struct{})
	go conn.start(started, inboundBufferSize-20-8, cfg)
	<-started

	return conn, nil
}

// Server establishes a mDNS connection over an existing conn.
//
// Deprecated: Use NewServer with functional options instead.
// This function is retained for backward compatibility with existing code.
//
// This function applies WebRTC/ICE legacy behavior by default, only processing
// A and AAAA record types. The equivalent NewServer call is:
//
//	conn, err := mdns.NewServer(
//	    ipv4.NewPacketConn(l4),
//	    ipv6.NewPacketConn(l6),
//	    mdns.WithLocalNames("example.local"),
//	    mdns.WithRecordTypes(dnsmessage.TypeA, dnsmessage.TypeAAAA),
//	)
//
// For full mDNS/DNS-SD support (all record types), omit WithRecordTypes.
func Server(
	multicastPktConnV4 *ipv4.PacketConn,
	multicastPktConnV6 *ipv6.PacketConn,
	config *Config,
) (*Conn, error) {
	if config == nil {
		return nil, errNilConfig
	}

	// Convert legacy Config to ServerOptions
	opts := []ServerOption{
		// Legacy behavior: only handle A/AAAA records (WebRTC/ICE compatibility)
		WithRecordTypes(dnsmessage.TypeA, dnsmessage.TypeAAAA),
		// Legacy behavior: no proactive cache refresh.
		WithCacheRefresh(false),
	}
	if config.Name != "" {
		opts = append(opts, WithName(config.Name))
	}
	if len(config.LocalNames) > 0 {
		opts = append(opts, WithLocalNames(config.LocalNames...))
	}
	if config.LocalAddress != nil {
		opts = append(opts, WithLocalAddress(config.LocalAddress))
	}
	if config.LoggerFactory != nil {
		opts = append(opts, WithLoggerFactory(config.LoggerFactory))
	}
	if config.IncludeLoopback {
		opts = append(opts, WithIncludeLoopback(true))
	}
	if len(config.Interfaces) > 0 {
		opts = append(opts, WithInterfaces(config.Interfaces...))
	}
	if config.QueryInterval != 0 {
		opts = append(opts, WithQueryInterval(config.QueryInterval))
	}

	conn, err := NewServer(multicastPktConnV4, multicastPktConnV6, opts...)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

// nameMatch is everything this responder owns under one queried name, as
// found by the question handler, together with what the response built from
// it may contain: the record types and the local addresses of its address
// records. Every question is answered from one of these; for qtype ANY the
// types cover every served type (RFC 6762 §6.5).
type nameMatch struct {
	// types lists the record types the response may contain: the question's
	// type or, for qtype ANY, every served type, as far as the record-type
	// filter allows.
	types []dnsmessage.Type
	// addrs are the local addresses to answer with, at most one per family.
	addrs []netip.Addr
	// host is set when the name is one of the local host names, which own
	// the address records.
	host bool
	// serviceTypes lists the registered service types when the name is the
	// service type enumeration name (RFC 6763 §9), which owns one PTR per
	// type.
	serviceTypes []string
	// browse holds the instances advertised under the name as a plain or
	// subtype browse name, each owning a PTR (RFC 6763 §4, §7.1).
	browse []browseMatch
	// instances holds the instances whose Service Instance Name is the
	// name, which owns their SRV and TXT records.
	instances []*ServiceInstance
}

// browseMatch pairs a service instance with the browse name it matched,
// in the instance's own casing, which owns the PTR answer.
type browseMatch struct {
	svc     *ServiceInstance
	ptrName string
}

// empty reports whether the responder owns nothing under the name.
func (m *nameMatch) empty() bool {
	return !m.host && len(m.serviceTypes) == 0 && len(m.browse) == 0 && len(m.instances) == 0
}

// allows reports whether records of the given type may be answered.
func (m *nameMatch) allows(rtype dnsmessage.Type) bool {
	return slices.Contains(m.types, rtype)
}

// carries reports whether the response may carry address records of the
// given type: as answers, or as the additionals of a PTR or SRV answer
// (RFC 6763 §12.1, §12.2).
func (m *nameMatch) carries(addrType dnsmessage.Type) bool {
	return m.allows(addrType) || m.allows(dnsmessage.TypePTR) || m.allows(dnsmessage.TypeSRV)
}

// hostAddrs returns the addresses whose address record type may be answered.
func (m *nameMatch) hostAddrs() []netip.Addr {
	var addrs []netip.Addr
	for _, addr := range m.addrs {
		if m.allows(addressRecordType(addr)) {
			addrs = append(addrs, addr)
		}
	}

	return addrs
}

// addressRecordType returns the record type that carries the address.
func addressRecordType(addr netip.Addr) dnsmessage.Type {
	if addr.Is4() {
		return dnsmessage.TypeA
	}

	return dnsmessage.TypeAAAA
}

// resourceKey identifies a record by owner name (case-insensitive), type and
// rdata, so a response can avoid carrying the same record twice.
type resourceKey struct {
	name  string
	rtype dnsmessage.Type
	rdata string
}

// response accumulates the records of one response message. A record is
// added at most once, so additionals never repeat an answer or each other,
// e.g. the address record of a host shared by several instances.
type response struct {
	answers     []dnsmessage.Resource
	additionals []dnsmessage.Resource
	seen        map[resourceKey]struct{}
	// addrs are the addresses carried in address records, which decide how
	// the message may be delivered (loopback and IPv6 zone restrictions).
	addrs []netip.Addr
}

func newResponse() *response {
	return &response{seen: make(map[resourceKey]struct{})}
}

// add records the resource and reports whether it was new.
func (r *response) add(res dnsmessage.Resource) bool {
	key := resourceKey{
		name:  strings.ToLower(res.Header.Name.String()),
		rtype: res.Header.Type,
		rdata: res.Body.GoString(),
	}
	if _, dup := r.seen[key]; dup {
		return false
	}
	r.seen[key] = struct{}{}

	return true
}

// addAnswer adds the resource to the answer section unless it is already
// in the response.
func (r *response) addAnswer(res dnsmessage.Resource) bool {
	if !r.add(res) {
		return false
	}
	r.answers = append(r.answers, res)

	return true
}

// addAdditional adds the resource to the additional section unless it is
// already in the response.
func (r *response) addAdditional(res dnsmessage.Resource) bool {
	if !r.add(res) {
		return false
	}
	r.additionals = append(r.additionals, res)

	return true
}

// createAnswer builds the response to one question: every record the
// responder owns under the queried name, of a type the match allows, is an
// answer, followed by the additional records RFC 6763 §12 recommends for
// those answers. It also returns the addresses carried in address records.
func (s *server) createAnswer(
	queryID uint16, question dnsmessage.Question, match *nameMatch, isUnicast bool,
) (dnsmessage.Message, []netip.Addr, error) {
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:            queryID,
			Response:      true,
			Authoritative: true,
		},
	}

	// Legacy and unicast responses repeat the question (RFC 6762 §6.7).
	if isUnicast {
		msg.Questions = []dnsmessage.Question{question}
	}

	resp := newResponse()

	if err := s.addHostAnswers(resp, question.Name.String(), match); err != nil {
		return dnsmessage.Message{}, nil, err
	}
	if err := s.addServiceTypeAnswers(resp, match); err != nil {
		return dnsmessage.Message{}, nil, err
	}
	for _, browse := range match.browse {
		if err := s.addBrowseAnswer(resp, browse, match); err != nil {
			return dnsmessage.Message{}, nil, err
		}
	}
	for _, svc := range match.instances {
		if err := s.addInstanceAnswers(resp, svc, match); err != nil {
			return dnsmessage.Message{}, nil, err
		}
	}

	msg.Answers = resp.answers
	msg.Additionals = resp.additionals

	return msg, resp.addrs, nil
}

// addHostAnswers adds the A/AAAA answers for a local host name. They are
// owned by the name as asked (RFC 6762 §6.2) and recommend no additionals
// (RFC 6763 §12.4).
func (s *server) addHostAnswers(resp *response, qname string, match *nameMatch) error {
	if !match.host {
		return nil
	}

	return s.addAddressRecords(resp, qname, match.hostAddrs(), resp.addAnswer)
}

// addServiceTypeAnswers adds the service type enumeration PTRs (RFC 6763
// §9), one per registered service type, which recommend no additionals.
func (s *server) addServiceTypeAnswers(resp *response, match *nameMatch) error {
	if !match.allows(dnsmessage.TypePTR) {
		return nil
	}

	for _, serviceType := range match.serviceTypes {
		ptrRec, err := buildPTRResource(serviceTypeEnumerationName+".local.", serviceType, browseTTL)
		if err != nil {
			return err
		}
		resp.addAnswer(ptrRec)
	}

	return nil
}

// addBrowseAnswer adds the PTR answer for a plain or subtype browse name
// with its SRV, TXT and address additionals (RFC 6763 §12.1).
func (s *server) addBrowseAnswer(resp *response, browse browseMatch, match *nameMatch) error {
	if !match.allows(dnsmessage.TypePTR) {
		return nil
	}

	ptrRec, err := buildPTRResource(browse.ptrName, browse.svc.serviceInstanceName(), browseTTL)
	if err != nil {
		return err
	}
	resp.addAnswer(ptrRec)

	srvRec, err := s.buildSRVRecord(browse.svc)
	if err != nil {
		return err
	}
	resp.addAdditional(srvRec)

	txtRec, err := s.buildTXTRecord(browse.svc)
	if err != nil {
		return err
	}
	resp.addAdditional(txtRec)

	return s.addAddressRecords(resp, browse.svc.Host, match.addrs, resp.addAdditional)
}

// addInstanceAnswers adds the SRV and TXT answers for a Service Instance
// Name. The SRV answer brings the address additionals (RFC 6763 §12.2); the
// TXT answer brings none (§12.3).
func (s *server) addInstanceAnswers(resp *response, svc *ServiceInstance, match *nameMatch) error {
	if match.allows(dnsmessage.TypeSRV) {
		srvRec, err := s.buildSRVRecord(svc)
		if err != nil {
			return err
		}
		resp.addAnswer(srvRec)

		if err := s.addAddressRecords(resp, svc.Host, match.addrs, resp.addAdditional); err != nil {
			return err
		}
	}

	if match.allows(dnsmessage.TypeTXT) {
		txtRec, err := s.buildTXTRecord(svc)
		if err != nil {
			return err
		}
		resp.addAnswer(txtRec)
	}

	return nil
}

// addAddressRecords builds an A or AAAA record owned by name for each
// address and adds it to the response through add (as answer or additional).
func (s *server) addAddressRecords(
	resp *response, name string, addrs []netip.Addr, add func(dnsmessage.Resource) bool,
) error {
	for _, addr := range addrs {
		addrRec, err := s.buildAddressResource(name, addr)
		if err != nil {
			return err
		}
		if add(addrRec) {
			resp.addrs = append(resp.addrs, addr)
		}
	}

	return nil
}

// buildSRVRecord creates the SRV record of a service instance.
func (s *server) buildSRVRecord(svc *ServiceInstance) (dnsmessage.Resource, error) {
	return buildSRVResource(svc.serviceInstanceName(), svc.Host, svc.Port, svc.Priority, svc.Weight, s.ttl)
}

// buildTXTRecord creates the TXT record of a service instance.
func (s *server) buildTXTRecord(svc *ServiceInstance) (dnsmessage.Resource, error) {
	txtStrings, err := encodeTXTRecordStrings(svc.Text)
	if err != nil {
		return dnsmessage.Resource{}, err
	}

	return buildTXTResource(svc.serviceInstanceName(), txtStrings, s.ttl)
}

// buildAddressResource creates an A or AAAA resource for the given host and address.
func (s *server) buildAddressResource(host string, addr netip.Addr) (dnsmessage.Resource, error) {
	if addr.Is4() {
		return buildAResource(host, addr, s.ttl)
	}

	return buildAAAAResource(host, addr, s.ttl)
}

// answerSender is the callback interface for sending DNS answers.
type answerSender interface {
	sendAnswer(
		queryID uint16, question dnsmessage.Question, ifIndex int,
		match nameMatch, dst *net.UDPAddr, isUnicast bool,
	)
	getServices() []ServiceInstance
}

// questionHandler processes incoming mDNS questions (server role).
// It matches questions against configured local names and sends answers.
type questionHandler struct {
	localNames         []string
	localAddress       net.IP
	ifaces             map[int]netInterface
	hasIPv4            bool
	sender             answerSender
	log                logging.LeveledLogger
	name               string
	dstAddr4           *net.UDPAddr
	dstAddr6           *net.UDPAddr
	allowedRecordTypes []dnsmessage.Type
}

// newQuestionHandler creates a new questionHandler.
func newQuestionHandler(
	localNames []string,
	localAddress net.IP,
	ifaces map[int]netInterface,
	hasIPv4 bool,
	sender answerSender,
	log logging.LeveledLogger,
	name string,
	dstAddr4, dstAddr6 *net.UDPAddr,
	allowedRecordTypes []dnsmessage.Type,
) *questionHandler {
	return &questionHandler{
		localNames:         localNames,
		localAddress:       localAddress,
		ifaces:             ifaces,
		hasIPv4:            hasIPv4,
		sender:             sender,
		log:                log,
		name:               name,
		dstAddr4:           dstAddr4,
		dstAddr6:           dstAddr6,
		allowedRecordTypes: allowedRecordTypes,
	}
}

// isRecordTypeAllowed checks if the given record type is allowed by the filter.
// If no filter is configured (empty slice), all types are allowed.
func (h *questionHandler) isRecordTypeAllowed(qtype dnsmessage.Type) bool {
	if len(h.allowedRecordTypes) == 0 {
		return true
	}

	return slices.Contains(h.allowedRecordTypes, qtype)
}

// handle processes a DNS message containing questions. Each question is
// answered with the records this responder owns under the queried name, of
// the types the question asks for.
func (h *questionHandler) handle(ctx *messageContext, msg *dnsmessage.Message) {
	for _, question := range msg.Questions {
		types := h.answerTypes(question.Type)
		if len(types) == 0 {
			continue
		}

		// Determine if we should reply via unicast
		// https://datatracker.ietf.org/doc/html/rfc6762#section-6
		isQU := (question.Class & qClassUnicastResponse) != 0
		isLegacy := ctx.source.Port != 5353 // legacy query (Section 6.7)
		isDirect := len(ctx.pktDst) != 0 && // direct unicast query
			!ctx.pktDst.Equal(h.dstAddr4.IP) &&
			!ctx.pktDst.Equal(h.dstAddr6.IP)
		shouldReplyUnicast := isQU || isLegacy || isDirect

		var dst *net.UDPAddr
		if shouldReplyUnicast {
			dst = ctx.source
		}

		h.answer(ctx, msg.Header.ID, question, types, dst, shouldReplyUnicast)
	}
}

// answerTypes returns the record types a question may be answered with: its
// own type or, for qtype ANY, every type this responder serves (RFC 6762
// §6.5), as far as the record-type filter allows. The filter thus applies to
// the answer types and never needs to list ANY itself.
func (h *questionHandler) answerTypes(qtype dnsmessage.Type) []dnsmessage.Type {
	var types []dnsmessage.Type
	for _, rtype := range []dnsmessage.Type{
		dnsmessage.TypeA, dnsmessage.TypeAAAA, dnsmessage.TypePTR, dnsmessage.TypeSRV, dnsmessage.TypeTXT,
	} {
		if (qtype == rtype || qtype == dnsmessage.TypeALL) && h.isRecordTypeAllowed(rtype) {
			types = append(types, rtype)
		}
	}

	return types
}

// answer responds to one question with every record this responder owns
// under the queried name, of the given types, in a single message together
// with the RFC 6763 §12 additionals for each answer (RFC 6762 §6.4).
func (h *questionHandler) answer(
	ctx *messageContext, queryID uint16, question dnsmessage.Question,
	types []dnsmessage.Type, dst *net.UDPAddr, isUnicast bool,
) {
	match := h.matchName(question.Name.String(), h.sender.getServices())
	if match.empty() {
		return
	}
	match.types = types
	match.addrs = h.resolveAddresses(ctx, &match, dst)

	h.sender.sendAnswer(queryID, question, ctx.ifIndex, match, dst, isUnicast)
}

// matchName collects what this responder owns under qname: whether it is a
// local host name or the service type enumeration name, and the instances
// advertised under it as a plain or subtype browse name or whose Service
// Instance Name it is. Names match case-insensitively.
func (h *questionHandler) matchName(qname string, services []ServiceInstance) nameMatch {
	var match nameMatch

	match.host = slices.ContainsFunc(h.localNames, func(localName string) bool {
		return strings.EqualFold(localName, qname)
	})

	if strings.EqualFold(serviceTypeEnumerationName+".local.", qname) {
		match.serviceTypes = uniqueServiceTypes(services)
	}

	for i := range services {
		svc := &services[i]

		if ptrName, ok := svc.matchBrowseName(qname); ok {
			match.browse = append(match.browse, browseMatch{svc: svc, ptrName: ptrName})

			continue
		}

		if strings.EqualFold(svc.serviceInstanceName(), qname) {
			match.instances = append(match.instances, svc)
		}
	}

	return match
}

// uniqueServiceTypes returns the service types of the instances, each once
// (case-insensitively) in registration order. Subtypes are not service
// types and are never enumerated (RFC 6763 §9).
func uniqueServiceTypes(services []ServiceInstance) []string {
	seen := make(map[string]struct{}, len(services))
	var types []string
	for i := range services {
		serviceType := services[i].serviceName()
		if _, dup := seen[strings.ToLower(serviceType)]; dup {
			continue
		}
		seen[strings.ToLower(serviceType)] = struct{}{}
		types = append(types, serviceType)
	}

	return types
}

// resolveAddresses returns the local addresses the response may carry: the
// IPv4 and IPv6 address this responder would use to answer an A and an AAAA
// question from the same context, for each family the match carries. A
// link-local IPv6 address carries a zone, which confines delivery of the
// whole message to IPv6 (see writeAnswer), so it is left out when an IPv4
// address is carried too; a querier that needs it can ask for AAAA directly.
func (h *questionHandler) resolveAddresses(ctx *messageContext, match *nameMatch, dst *net.UDPAddr) []netip.Addr {
	var addrs []netip.Addr

	if match.carries(dnsmessage.TypeA) {
		if addr4 := h.resolveLocalAddress(ctx, true, dst); addr4 != nil {
			addrs = append(addrs, *addr4)
		}
	}

	if match.carries(dnsmessage.TypeAAAA) {
		if addr6 := h.resolveLocalAddress(ctx, false, dst); addr6 != nil && (len(addrs) == 0 || addr6.Zone() == "") {
			addrs = append(addrs, *addr6)
		}
	}

	return addrs
}

// resolveLocalAddress determines the appropriate local address to respond with.
//
//nolint:gocognit,gocyclo,cyclop,nestif
func (h *questionHandler) resolveLocalAddress(ctx *messageContext, queryWantsV4 bool, dst *net.UDPAddr) *netip.Addr {
	var localAddress *netip.Addr
	var err error

	if h.localAddress != nil {
		// Use configured local address
		ipAddr, ok := netip.AddrFromSlice(h.localAddress)
		if !ok {
			h.log.Warnf("[%s] failed to convert config.localAddress '%s' to netip.Addr", h.name, h.localAddress)

			return nil
		}
		if h.hasIPv4 {
			ipAddr = ipAddr.Unmap()
		}
		localAddress = &ipAddr
	} else {
		// Derive address from interface or source
		if ctx.ifIndex != -1 {
			localAddress = h.selectAddressFromInterface(ctx.ifIndex, queryWantsV4)
		}

		if ctx.ifIndex == -1 || localAddress == nil {
			localAddress, err = interfaceForRemote(ctx.source.String())
			if err != nil {
				h.log.Warnf("[%s] failed to get local interface to communicate with %s: %v", h.name, ctx.source.String(), err)

				return nil
			}
		}
	}

	// Validate address matches query type
	if queryWantsV4 {
		if !localAddress.Is4() {
			h.log.Debugf("[%s] have IPv6 address %s to respond with but question is for A not AAAA", h.name, localAddress)

			return nil
		}
	} else {
		if !localAddress.Is6() {
			h.log.Debugf("[%s] have IPv4 address %s to respond with but question is for AAAA not A", h.name, localAddress)

			return nil
		}
		if !isSupportedIPv6(*localAddress, !h.hasIPv4) {
			h.log.Debugf("[%s] got local interface address but not a supported IPv6 address %v", h.name, localAddress)

			return nil
		}
	}

	// Check for link-local address being sent to IPv4 destination
	if dst != nil && len(dst.IP) == net.IPv4len &&
		localAddress.Is6() &&
		localAddress.Zone() != "" &&
		(localAddress.IsLinkLocalUnicast() || localAddress.IsLinkLocalMulticast()) {
		h.log.Debugf("[%s] refusing to send link-local address %s to an IPv4 destination %s", h.name, localAddress, dst)

		return nil
	}

	return localAddress
}

// selectAddressFromInterface selects an appropriate address from the interface.
//
//nolint:gocognit,cyclop,nestif
func (h *questionHandler) selectAddressFromInterface(ifIndex int, queryWantsV4 bool) *netip.Addr {
	ifc, ok := h.ifaces[ifIndex]
	if !ok {
		h.log.Warnf("[%s] no interface for %d", h.name, ifIndex)

		return nil
	}

	var selectedAddrs []netip.Addr
	for _, addr := range ifc.ipAddrs {
		addrCopy := addr

		if queryWantsV4 {
			if addrCopy.Is4In6() {
				addrCopy = addrCopy.Unmap()
			}
			if !addrCopy.Is4() {
				continue
			}
		} else {
			if !addrCopy.Is6() {
				continue
			}
			if !isSupportedIPv6(addrCopy, !h.hasIPv4) {
				h.log.Debugf("[%s] interface %d address not a supported IPv6 address %s", h.name, ifIndex, &addrCopy)

				continue
			}
		}

		selectedAddrs = append(selectedAddrs, addrCopy)
	}

	if len(selectedAddrs) == 0 {
		h.log.Debugf(
			"[%s] failed to find suitable IP for interface %d; deriving address from source instead",
			h.name, ifIndex,
		)

		return nil
	}

	// Choose the best match
	var choice *netip.Addr
	for _, option := range selectedAddrs {
		optCopy := option
		if option.Is4() {
			choice = &optCopy

			break
		}
		if choice == nil || !optCopy.Is4In6() {
			choice = &optCopy
		}
		if !optCopy.Is4In6() {
			break
		}
	}

	return choice
}

func isSupportedIPv6(addr netip.Addr, ipv6Only bool) bool {
	if !addr.Is6() {
		return false
	}
	// IPv4-mapped-IPv6 addresses cannot be connected to unless
	// unmapped.
	if !ipv6Only && addr.Is4In6() {
		return false
	}

	return true
}
