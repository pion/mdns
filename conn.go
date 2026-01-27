// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package mdns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/pion/logging"
	"golang.org/x/net/dns/dnsmessage"
)

// Conn represents a mDNS Server.
type Conn struct {
	mu   sync.RWMutex
	name string
	log  logging.LeveledLogger

	multicastPktConnV4 ipPacketConn
	multicastPktConnV6 ipPacketConn
	dstAddr4           *net.UDPAddr
	dstAddr6           *net.UDPAddr

	unicastPktConnV4 ipPacketConn
	unicastPktConnV6 ipPacketConn

	queryInterval time.Duration
	localNames    []string
	ifaces        map[int]netInterface

	// client handles query operations
	client *client
	// server handles response operations
	server *server

	closed chan any
}

type query struct {
	nameWithSuffix  string
	queryResultChan chan queryResult
}

type queryResult struct {
	answer dnsmessage.ResourceHeader
	addr   netip.Addr
}

const (
	defaultQueryInterval = time.Second
	destinationAddress4  = "224.0.0.251:5353"
	destinationAddress6  = "[FF02::FB]:5353"
	maxMessageRecords    = 3
	responseTTL          = 120
	// maxPacketSize is the maximum size of a mdns packet.
	// From RFC 6762:
	// Even when fragmentation is used, a Multicast DNS packet, including IP
	// and UDP headers, MUST NOT exceed 9000 bytes.
	// https://datatracker.ietf.org/doc/html/rfc6762#section-17
	maxPacketSize = 9000
)

var (
	errNoPositiveMTUFound = errors.New("no positive MTU found")
	errNoPacketConn       = errors.New("must supply at least a multicast IPv4 or IPv6 PacketConn")
	errNoUsableInterfaces = errors.New("no usable interfaces found for mDNS")
	errFailedToClose      = errors.New("failed to close mDNS Conn")
)

type netInterface struct {
	net.Interface
	ipAddrs    []netip.Addr
	supportsV4 bool
	supportsV6 bool
}

// Close closes the mDNS Conn.
func (c *Conn) Close() error { //nolint:cyclop
	select {
	case <-c.closed:
		return nil
	default:
	}

	// Once on go1.20, can use errors.Join
	var errs []error
	if c.multicastPktConnV4 != nil {
		if err := c.multicastPktConnV4.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if c.multicastPktConnV6 != nil {
		if err := c.multicastPktConnV6.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if c.unicastPktConnV4 != nil {
		if err := c.unicastPktConnV4.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if c.unicastPktConnV6 != nil {
		if err := c.unicastPktConnV6.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) == 0 {
		<-c.closed

		return nil
	}

	rtrn := errFailedToClose
	for _, err := range errs {
		rtrn = fmt.Errorf("%w\n%w", err, rtrn)
	}

	return rtrn
}

// Register adds a DNS-SD service instance to the server.
// The service will be advertised in response to PTR, SRV, and TXT queries.
// Returns an error if the connection is closed or has no server.
func (c *Conn) Register(svc ServiceInstance) error {
	select {
	case <-c.closed:
		return errConnectionClosed
	default:
	}

	if c.server == nil {
		return errConnectionClosed
	}

	if err := validateInstanceName(svc.Instance); err != nil {
		return err
	}

	if err := validateServiceName(svc.Service); err != nil {
		return err
	}

	if svc.Domain == "" {
		svc.Domain = "local"
	}

	if svc.Host == "" && len(c.localNames) > 0 {
		svc.Host = c.localNames[0]
	}

	c.server.registerService(svc)

	return nil
}

// Unregister removes a DNS-SD service instance from the server.
// The instance is identified by its Instance name and Service type.
func (c *Conn) Unregister(instance, service string) {
	if c.server == nil {
		return
	}

	c.server.unregisterService(instance, service)
}

// Query sends mDNS Queries for the following name until
// either the Context is canceled/expires or we get a result
//
// Deprecated: Use QueryAddr instead as it supports the easier to use netip.Addr.
func (c *Conn) Query(ctx context.Context, name string) (dnsmessage.ResourceHeader, net.Addr, error) {
	header, addr, err := c.QueryAddr(ctx, name)
	if err != nil {
		return header, nil, err
	}

	return header, &net.IPAddr{
		IP:   addr.AsSlice(),
		Zone: addr.Zone(),
	}, nil
}

// QueryAddr sends mDNS Queries for the following name until
// either the Context is canceled/expires or we get a result.
func (c *Conn) QueryAddr(ctx context.Context, name string) (dnsmessage.ResourceHeader, netip.Addr, error) {
	select {
	case <-c.closed:
		return dnsmessage.ResourceHeader{}, netip.Addr{}, errConnectionClosed
	default:
	}

	if c.client == nil {
		return dnsmessage.ResourceHeader{}, netip.Addr{}, errConnectionClosed
	}

	nameWithSuffix := name + "."
	queryChan := make(chan queryResult, 1)
	q := c.client.handler.registerQuery(nameWithSuffix, queryChan)
	defer c.client.handler.unregisterQuery(q)

	ticker := time.NewTicker(c.queryInterval)
	defer ticker.Stop()

	c.client.sendQuestion(nameWithSuffix)
	for {
		select {
		case <-ticker.C:
			c.client.sendQuestion(nameWithSuffix)
		case <-c.closed:
			return dnsmessage.ResourceHeader{}, netip.Addr{}, errConnectionClosed
		case res := <-queryChan:
			// Given https://datatracker.ietf.org/doc/html/draft-ietf-mmusic-mdns-ice-candidates#section-3.2.2-2
			// An ICE agent SHOULD ignore candidates where the hostname resolution returns more than one IP address.
			//
			// We will take the first we receive which could result in a race between two suitable addresses where
			// one is better than the other (e.g. localhost vs LAN).
			return res.answer, res.addr, nil
		case <-ctx.Done():
			return dnsmessage.ResourceHeader{}, netip.Addr{}, errContextElapsed
		}
	}
}

// writeQuestion sends a DNS question to all interfaces.
// It prefers unicast connections if available, falling back to multicast.
//
//nolint:gocognit,cyclop,nestif
func (c *Conn) writeQuestion(b []byte) {
	for ifcIdx := range c.ifaces {
		ifc := c.ifaces[ifcIdx]

		// We'll write via unicast if we can in case the responder chooses to respond to the address
		// the request came from (i.e. not respecting unicast-response bit). If we were to use the
		// multicast packet conn here, we'd be writing from a specific multicast address which won't
		// be able to receive unicast traffic (it only works when listening on 0.0.0.0/[::]).
		if c.unicastPktConnV4 == nil && c.unicastPktConnV6 == nil {
			c.log.Debugf("[%s] writing question to multicast IPv4/6 %s", c.name, c.dstAddr4)
			if ifc.supportsV4 && c.multicastPktConnV4 != nil {
				if _, err := c.multicastPktConnV4.WriteTo(b, &ifc.Interface, nil, c.dstAddr4); err != nil {
					c.log.Warnf("[%s] failed to send mDNS packet (multicast) on IPv4 interface %d: %v", c.name, ifc.Index, err)
				}
			}
			if ifc.supportsV6 && c.multicastPktConnV6 != nil {
				if _, err := c.multicastPktConnV6.WriteTo(b, &ifc.Interface, nil, c.dstAddr6); err != nil {
					c.log.Warnf("[%s] failed to send mDNS packet (multicast) on IPv6 interface %d: %v", c.name, ifc.Index, err)
				}
			}
		}
		if ifc.supportsV4 && c.unicastPktConnV4 != nil {
			c.log.Debugf("[%s] writing question to unicast IPv4 %s", c.name, c.dstAddr4)
			if _, err := c.unicastPktConnV4.WriteTo(b, &ifc.Interface, nil, c.dstAddr4); err != nil {
				c.log.Warnf("[%s] failed to send mDNS packet (unicast) on interface %d: %v", c.name, ifc.Index, err)
			}
		}
		if ifc.supportsV6 && c.unicastPktConnV6 != nil {
			c.log.Debugf("[%s] writing question to unicast IPv6 %s", c.name, c.dstAddr6)
			if _, err := c.unicastPktConnV6.WriteTo(b, &ifc.Interface, nil, c.dstAddr6); err != nil {
				c.log.Warnf("[%s] failed to send mDNS packet (unicast) on interface %d: %v", c.name, ifc.Index, err)
			}
		}
	}
}

// writeAnswer sends a DNS answer, optionally to a specific interface or unicast destination.
//
//nolint:gocognit,gocyclo,cyclop
func (c *Conn) writeAnswer(
	ifIndex int,
	b []byte,
	hasLoopbackData bool,
	hasIPv6Zone bool,
	unicastDst *net.UDPAddr,
) {
	var dst4, dst6 net.Addr
	if unicastDst == nil {
		dst4 = c.dstAddr4
		dst6 = c.dstAddr6
	} else {
		if unicastDst.IP.To4() == nil {
			dst6 = unicastDst
		} else {
			dst4 = unicastDst
		}
	}

	if ifIndex != -1 { //nolint:nestif
		ifc, ok := c.ifaces[ifIndex]
		if !ok {
			c.log.Warnf("[%s] no interface for %d", c.name, ifIndex)

			return
		}
		if hasLoopbackData && ifc.Flags&net.FlagLoopback == 0 {
			// avoid accidentally tricking the destination that itself is the same as us
			c.log.Debugf("[%s] interface is not loopback %d", c.name, ifIndex)

			return
		}

		c.log.Debugf("[%s] writing answer to IPv4: %v, IPv6: %v", c.name, dst4, dst6)

		if ifc.supportsV4 && c.multicastPktConnV4 != nil && dst4 != nil {
			if !hasIPv6Zone {
				if _, err := c.multicastPktConnV4.WriteTo(b, &ifc.Interface, nil, dst4); err != nil {
					c.log.Warnf("[%s] failed to send mDNS packet on IPv4 interface %d: %v", c.name, ifIndex, err)
				}
			} else {
				c.log.Debugf("[%s] refusing to send mDNS packet with IPv6 zone over IPv4", c.name)
			}
		}
		if ifc.supportsV6 && c.multicastPktConnV6 != nil && dst6 != nil {
			if _, err := c.multicastPktConnV6.WriteTo(b, &ifc.Interface, nil, dst6); err != nil {
				c.log.Warnf("[%s] failed to send mDNS packet on IPv6 interface %d: %v", c.name, ifIndex, err)
			}
		}

		return
	}

	for ifcIdx := range c.ifaces {
		ifc := c.ifaces[ifcIdx]
		if hasLoopbackData {
			c.log.Debugf("[%s] Refusing to send loopback data with non-specific interface", c.name)

			continue
		}

		c.log.Debugf("[%s] writing answer to IPv4: %v, IPv6: %v", c.name, dst4, dst6)

		if ifc.supportsV4 && c.multicastPktConnV4 != nil && dst4 != nil {
			if !hasIPv6Zone {
				if _, err := c.multicastPktConnV4.WriteTo(b, &ifc.Interface, nil, dst4); err != nil {
					c.log.Warnf("[%s] failed to send mDNS packet (multicast) on IPv4 interface %d: %v", c.name, ifIndex, err)
				}
			} else {
				c.log.Debugf("[%s] refusing to send mDNS packet with IPv6 zone over IPv4", c.name)
			}
		}
		if ifc.supportsV6 && c.multicastPktConnV6 != nil && dst6 != nil {
			if _, err := c.multicastPktConnV6.WriteTo(b, &ifc.Interface, nil, dst6); err != nil {
				c.log.Warnf("[%s] failed to send mDNS packet (multicast) on IPv6 interface %d: %v", c.name, ifIndex, err)
			}
		}
	}
}

func (c *Conn) readLoop(name string, pktConn ipPacketConn, inboundBufferSize int, _ *serverConfig) {
	b := make([]byte, inboundBufferSize)

	for {
		n, cm, src, err := pktConn.ReadFrom(b)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			c.log.Warnf("[%s] failed to ReadFrom %q %v", c.name, src, err)

			continue
		}
		c.log.Debugf("[%s] got read on %s from %s", c.name, name, src)

		var ifIndex int
		var pktDst net.IP
		if cm != nil {
			ifIndex = cm.IfIndex
			pktDst = cm.Dst
		} else {
			ifIndex = -1
		}
		srcAddr, ok := src.(*net.UDPAddr)
		if !ok {
			c.log.Warnf("[%s] expected source address %s to be UDP but got %", c.name, src, src)

			continue
		}

		func() {
			var msg dnsmessage.Message
			err := msg.Unpack(b[:n])
			if err != nil {
				c.log.Warnf("[%s] failed to parse mDNS packet %v", c.name, err)

				return
			}

			ctx := &messageContext{
				source:    srcAddr,
				ifIndex:   ifIndex,
				pktDst:    pktDst,
				timestamp: time.Now(),
			}

			// Questions are often echoed with answers, therefore
			// If we have more questions than answers it is a question we might need to respond to
			if len(msg.Questions) > len(msg.Answers) {
				if c.server != nil {
					c.server.handler.handle(ctx, &msg)
				}
			} else {
				if c.client != nil {
					c.client.handler.handle(ctx, &msg)
				}
			}
		}()
	}
}

func (c *Conn) start(started chan<- struct{}, inboundBufferSize int, config *serverConfig) {
	defer func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		close(c.closed)
	}()

	var numReaders int
	readerStarted := make(chan struct{})
	readerEnded := make(chan struct{})

	if c.multicastPktConnV4 != nil {
		numReaders++
		go func() {
			defer func() {
				readerEnded <- struct{}{}
			}()
			readerStarted <- struct{}{}
			c.readLoop("multi4", c.multicastPktConnV4, inboundBufferSize, config)
		}()
	}
	if c.multicastPktConnV6 != nil {
		numReaders++
		go func() {
			defer func() {
				readerEnded <- struct{}{}
			}()
			readerStarted <- struct{}{}
			c.readLoop("multi6", c.multicastPktConnV6, inboundBufferSize, config)
		}()
	}
	if c.unicastPktConnV4 != nil {
		numReaders++
		go func() {
			defer func() {
				readerEnded <- struct{}{}
			}()
			readerStarted <- struct{}{}
			c.readLoop("uni4", c.unicastPktConnV4, inboundBufferSize, config)
		}()
	}
	if c.unicastPktConnV6 != nil {
		numReaders++
		go func() {
			defer func() {
				readerEnded <- struct{}{}
			}()
			readerStarted <- struct{}{}
			c.readLoop("uni6", c.unicastPktConnV6, inboundBufferSize, config)
		}()
	}
	for i := 0; i < numReaders; i++ {
		<-readerStarted
	}
	close(started)
	for i := 0; i < numReaders; i++ {
		<-readerEnded
	}
}

func addrWithOptionalZone(addr netip.Addr, zone string) netip.Addr {
	if zone == "" {
		return addr
	}
	if addr.Is6() && (addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast()) {
		return addr.WithZone(zone)
	}

	return addr
}
