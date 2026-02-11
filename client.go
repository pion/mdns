// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package mdns

import (
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

// answerHandler processes incoming mDNS answers (client role).
// It matches answers against registered queries and delivers results.
type answerHandler struct {
	mu      sync.RWMutex
	queries []*query
	log     logging.LeveledLogger
	name    string
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

// handle processes a DNS message containing answers.
// It matches answers against registered queries and sends results.
//
//nolint:cyclop
func (h *answerHandler) handle(ctx *messageContext, msg *dnsmessage.Message) {
	h.mu.RLock()
	queries := make([]*query, len(h.queries))
	copy(queries, h.queries)
	h.mu.RUnlock()

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

		// Remove answered queries
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
