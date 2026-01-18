// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
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
	for _, answer := range msg.Answers {
		if answer.Header.Type != dnsmessage.TypeA && answer.Header.Type != dnsmessage.TypeAAAA {
			continue
		}

		h.mu.Lock()
		queries := make([]*query, len(h.queries))
		copy(queries, h.queries)
		h.mu.Unlock()

		var answered []*query
		for _, q := range queries {
			queryCopy := q
			if !strings.EqualFold(queryCopy.nameWithSuffix, answer.Header.Name.String()) {
				continue
			}

			addr, err := addrFromAnswer(answer)
			if err != nil {
				h.log.Warnf("[%s] failed to parse mDNS answer %v", h.name, err)

				return
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
					queryIdx--

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
