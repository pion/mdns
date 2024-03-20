// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package mdns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/pion/logging"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Conn represents a mDNS Server
type Conn struct {
	mu  sync.RWMutex
	log logging.LeveledLogger

	multicastPktConnV4 ipPacketConn
	multicastPktConnV6 ipPacketConn
	dstAddr4           *net.UDPAddr
	dstAddr6           *net.UDPAddr

	unicastPktConnV4 ipPacketConn
	unicastPktConnV6 ipPacketConn

	queryInterval time.Duration
	localNames    []string
	queries       []*query
	ifaces        map[int]netInterface

	closed chan interface{}
}

type query struct {
	nameWithSuffix  string
	queryResultChan chan queryResult
}

type queryResult struct {
	answer dnsmessage.ResourceHeader
	addr   net.Addr
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
	ips        []net.IP
	supportsV4 bool
	supportsV6 bool
}

// Server establishes a mDNS connection over an existing conn.
// Either one or both of the multicast packet conns should be provided,
//
//nolint:gocognit
func Server(
	multicastPktConnV4 *ipv4.PacketConn,
	multicastPktConnV6 *ipv6.PacketConn,
	config *Config,
) (*Conn, error) {
	if config == nil {
		return nil, errNilConfig
	}
	loggerFactory := config.LoggerFactory
	if loggerFactory == nil {
		loggerFactory = logging.NewDefaultLoggerFactory()
	}
	log := loggerFactory.NewLogger("mdns")

	if multicastPktConnV4 == nil && multicastPktConnV6 == nil {
		return nil, errNoPacketConn
	}

	ifaces := config.Interfaces
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
			log.Warnf("failed to listen on unicast IPv4 %s: %s; will not be able to receive unicast responses on IPv4", addr4, err)
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
			log.Warnf("failed to listen on unicast IPv6 %s: %s; will not be able to receive unicast responses on IPv6", addr6, err)
		} else {
			unicastPktConnV6 = ipv6.NewPacketConn(unicastConnV6)
		}
	}

	mutlicastGroup4 := net.IPv4(224, 0, 0, 251)
	multicastGroupAddr4 := &net.UDPAddr{IP: mutlicastGroup4}

	// FF02::FB
	mutlicastGroup6 := net.IP{0xff, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xfb}
	multicastGroupAddr6 := &net.UDPAddr{IP: mutlicastGroup6}

	inboundBufferSize := 0
	joinErrCount := 0
	ifacesToUse := make(map[int]netInterface, len(ifaces))
	for i := range ifaces {
		ifc := ifaces[i]
		if !config.IncludeLoopback && ifc.Flags&net.FlagLoopback == net.FlagLoopback {
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
		ifcIPs := make([]net.IP, 0, len(addrs))
		for _, addr := range addrs {
			var ip net.IP
			switch addr := addr.(type) {
			case *net.IPNet:
				ip = addr.IP
			case *net.IPAddr:
				ip = addr.IP
			default:
				continue
			}
			if ip.To4() == nil {
				supportsV6 = true
			} else {
				supportsV4 = true
			}
			ifcIPs = append(ifcIPs, ip)
		}
		if !(supportsV4 || supportsV6) {
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
			ips:        ifcIPs,
			supportsV4: supportsV4,
			supportsV6: supportsV6,
		}
		if ifc.MTU > inboundBufferSize {
			inboundBufferSize = ifc.MTU
		}
		if supportsV4 && unicastPktConnV4 != nil {
			if err := unicastPktConnV4.JoinGroup(&ifc, multicastGroupAddr4); err != nil {
				log.Debugf("failed to JoinGroup on unicast IPv4 connection for interface %d: %v", ifc.Index, err)
			}
		}
		if supportsV6 && unicastPktConnV6 != nil {
			if err := unicastPktConnV6.JoinGroup(&ifc, multicastGroupAddr6); err != nil {
				log.Debugf("failed to JoinGroup on unicast IPv6 connection for interface %d: %v", ifc.Index, err)
			}
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
	for _, l := range config.LocalNames {
		localNames = append(localNames, l+".")
	}

	c := &Conn{
		queryInterval: defaultQueryInterval,
		dstAddr4:      dstAddr4,
		dstAddr6:      dstAddr6,
		localNames:    localNames,
		ifaces:        ifacesToUse,
		log:           log,
		closed:        make(chan interface{}),
	}
	if config.QueryInterval != 0 {
		c.queryInterval = config.QueryInterval
	}

	if multicastPktConnV4 != nil {
		if err := multicastPktConnV4.SetControlMessage(ipv4.FlagInterface, true); err != nil {
			c.log.Warnf("failed to SetControlMessage(ipv4.FlagInterface) on multicast IPv4 PacketConn %v", err)
		}
		if err := multicastPktConnV4.SetControlMessage(ipv4.FlagDst, true); err != nil {
			c.log.Warnf("failed to SetControlMessage(ipv4.FlagDst) on multicast IPv4 PacketConn %v", err)
		}
		c.multicastPktConnV4 = ipPacketConn4{multicastPktConnV4, log}
	}
	if multicastPktConnV6 != nil {
		if err := multicastPktConnV6.SetControlMessage(ipv6.FlagInterface, true); err != nil {
			c.log.Warnf("failed to SetControlMessage(ipv6.FlagInterface) on multicast IPv6 PacketConn %v", err)
		}
		if err := multicastPktConnV6.SetControlMessage(ipv6.FlagDst, true); err != nil {
			c.log.Warnf("failed to SetControlMessage(ipv6.FlagInterface) on multicast IPv6 PacketConn %v", err)
		}
		c.multicastPktConnV6 = ipPacketConn6{multicastPktConnV6, log}
	}
	if unicastPktConnV4 != nil {
		if err := unicastPktConnV4.SetControlMessage(ipv4.FlagInterface, true); err != nil {
			c.log.Warnf("failed to SetControlMessage(ipv4.FlagInterface) on unicast IPv4 PacketConn %v", err)
		}
		if err := unicastPktConnV4.SetControlMessage(ipv4.FlagDst, true); err != nil {
			c.log.Warnf("failed to SetControlMessage(ipv4.FlagInterface) on unicast IPv4 PacketConn %v", err)
		}
		c.unicastPktConnV4 = ipPacketConn4{unicastPktConnV4, log}
	}
	if unicastPktConnV6 != nil {
		if err := unicastPktConnV6.SetControlMessage(ipv6.FlagInterface, true); err != nil {
			c.log.Warnf("failed to SetControlMessage(ipv6.FlagInterface) on unicast IPv6 PacketConn %v", err)
		}
		if err := unicastPktConnV6.SetControlMessage(ipv6.FlagDst, true); err != nil {
			c.log.Warnf("failed to SetControlMessage(ipv6.FlagInterface) on unicast IPv6 PacketConn %v", err)
		}
		c.unicastPktConnV6 = ipPacketConn6{unicastPktConnV6, log}
	}

	if config.IncludeLoopback {
		// this is an efficient way for us to send ourselves a message faster instead of it going
		// further out into the network stack.
		if multicastPktConnV4 != nil {
			if err := multicastPktConnV4.SetMulticastLoopback(true); err != nil {
				c.log.Warnf("failed to SetMulticastLoopback(true) on multicast IPv4 PacketConn %v; this may cause inefficient network path communications", err)
			}
		}
		if multicastPktConnV6 != nil {
			if err := multicastPktConnV6.SetMulticastLoopback(true); err != nil {
				c.log.Warnf("failed to SetMulticastLoopback(true) on multicast IPv6 PacketConn %v; this may cause inefficient network path communications", err)
			}
		}
		if unicastPktConnV4 != nil {
			if err := unicastPktConnV4.SetMulticastLoopback(true); err != nil {
				c.log.Warnf("failed to SetMulticastLoopback(true) on unicast IPv4 PacketConn %v; this may cause inefficient network path communications", err)
			}
		}
		if unicastPktConnV6 != nil {
			if err := unicastPktConnV6.SetMulticastLoopback(true); err != nil {
				c.log.Warnf("failed to SetMulticastLoopback(true) on unicast IPv6 PacketConn %v; this may cause inefficient network path communications", err)
			}
		}
	}

	// https://www.rfc-editor.org/rfc/rfc6762.html#section-17
	// Multicast DNS messages carried by UDP may be up to the IP MTU of the
	// physical interface, less the space required for the IP header (20
	// bytes for IPv4; 40 bytes for IPv6) and the UDP header (8 bytes).
	started := make(chan struct{})
	go c.start(started, inboundBufferSize-20-8, config)
	<-started
	return c, nil
}

// Close closes the mDNS Conn
func (c *Conn) Close() error {
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
		rtrn = fmt.Errorf("%w\n%s", err, rtrn.Error())
	}
	return rtrn
}

// Query sends mDNS Queries for the following name until
// either the Context is canceled/expires or we get a result
func (c *Conn) Query(ctx context.Context, name string) (dnsmessage.ResourceHeader, net.Addr, error) {
	select {
	case <-c.closed:
		return dnsmessage.ResourceHeader{}, nil, errConnectionClosed
	default:
	}

	nameWithSuffix := name + "."

	queryChan := make(chan queryResult, 1)
	query := &query{nameWithSuffix, queryChan}
	c.mu.Lock()
	c.queries = append(c.queries, query)
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		for i := len(c.queries) - 1; i >= 0; i-- {
			if c.queries[i] == query {
				c.queries = append(c.queries[:i], c.queries[i+1:]...)
			}
		}
	}()

	ticker := time.NewTicker(c.queryInterval)
	defer ticker.Stop()

	c.sendQuestion(nameWithSuffix)
	for {
		select {
		case <-ticker.C:
			c.sendQuestion(nameWithSuffix)
		case <-c.closed:
			return dnsmessage.ResourceHeader{}, nil, errConnectionClosed
		case res := <-queryChan:
			// Given https://datatracker.ietf.org/doc/html/draft-ietf-mmusic-mdns-ice-candidates#section-3.2.2-2
			// An ICE agent SHOULD ignore candidates where the hostname resolution returns more than one IP address.
			//
			// We will take the first we receive which could result in a race between two suitable addresses where
			// one is better than the other (e.g. localhost vs LAN).
			return res.answer, res.addr, nil
		case <-ctx.Done():
			return dnsmessage.ResourceHeader{}, nil, errContextElapsed
		}
	}
}

type ipToBytesError struct {
	ip           net.IP
	expectedType string
}

func (err ipToBytesError) Error() string {
	return fmt.Sprintf("ip (%s) is not %s", err.ip, err.expectedType)
}

func ipv4ToBytes(ip net.IP) ([4]byte, error) {
	rawIP := ip.To4()
	if rawIP == nil {
		return [4]byte{}, ipToBytesError{ip, "IPv4"}
	}

	// net.IPs are stored in big endian / network byte order
	var out [4]byte
	copy(out[:], rawIP[:])
	return out, nil
}

func ipv6ToBytes(ip net.IP) ([16]byte, error) {
	rawIP := ip.To16()
	if rawIP == nil {
		return [16]byte{}, ipToBytesError{ip, "IPv6"}
	}

	// net.IPs are stored in big endian / network byte order
	var out [16]byte
	copy(out[:], rawIP[:])
	return out, nil
}

func interfaceForRemote(remote string) (net.IP, error) {
	conn, err := net.Dial("udp", remote)
	if err != nil {
		return nil, err
	}

	localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, errFailedCast
	}

	if err := conn.Close(); err != nil {
		return nil, err
	}

	return localAddr.IP, nil
}

type writeType byte

const (
	writeTypeQuestion writeType = iota
	writeTypeAnswer
)

func (c *Conn) sendQuestion(name string) {
	packedName, err := dnsmessage.NewName(name)
	if err != nil {
		c.log.Warnf("failed to construct mDNS packet %v", err)
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
	if c.multicastPktConnV4 != nil {
		msg.Questions = append(msg.Questions, dnsmessage.Question{
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET | (1 << 15),
			Name:  packedName,
		})
	}
	if c.multicastPktConnV6 != nil {
		msg.Questions = append(msg.Questions, dnsmessage.Question{
			Type:  dnsmessage.TypeAAAA,
			Class: dnsmessage.ClassINET | (1 << 15),
			Name:  packedName,
		})
	}

	rawQuery, err := msg.Pack()
	if err != nil {
		c.log.Warnf("failed to construct mDNS packet %v", err)
		return
	}

	c.writeToSocket(0, rawQuery, false, writeTypeQuestion, nil)
}

func (c *Conn) writeToSocket(ifIndex int, b []byte, hasLoopbackData bool, wType writeType, unicastDst *net.UDPAddr) { //nolint:gocognit
	var dst4, dst6 net.Addr
	if wType == writeTypeAnswer {
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
	}

	if ifIndex != 0 {
		if wType == writeTypeQuestion {
			c.log.Errorf("Unexpected question using specific interface index %d; dropping question", ifIndex)
			return
		}

		ifc, ok := c.ifaces[ifIndex]
		if !ok {
			c.log.Warnf("no interface for %d", ifIndex)
			return
		}
		if hasLoopbackData && ifc.Flags&net.FlagLoopback == 0 {
			// avoid accidentally tricking the destination that itself is the same as us
			c.log.Debugf("interface is not loopback %d", ifIndex)
			return
		}

		c.log.Debugf("writing answer to IPv4: %v, IPv6: %v", dst4, dst6)

		if ifc.supportsV4 && c.multicastPktConnV4 != nil && dst4 != nil {
			if _, err := c.multicastPktConnV4.WriteTo(b, &ifc.Interface, nil, dst4); err != nil {
				c.log.Warnf("failed to send mDNS packet on IPv4 interface %d: %v", ifIndex, err)
			}
		}
		if ifc.supportsV6 && c.multicastPktConnV6 != nil && dst6 != nil {
			if _, err := c.multicastPktConnV6.WriteTo(b, &ifc.Interface, nil, dst6); err != nil {
				c.log.Warnf("failed to send mDNS packet on IPv6 interface %d: %v", ifIndex, err)
			}
		}

		return
	}
	for ifcIdx := range c.ifaces {
		ifc := c.ifaces[ifcIdx]
		if hasLoopbackData {
			c.log.Debug("Refusing to send loopback data with non-specific interface")
			continue
		}

		if wType == writeTypeQuestion {
			// we'll write via unicast if we can in case the responder chooses to respond to the address the request
			// came from (i.e. not respecting unicast-response bit). If we were to use the multicast packet
			// conn here, we'd be writing from a specific multicast address which won't be able to receive unicast
			// traffic (it only works when listening on 0.0.0.0/[::]).
			if c.unicastPktConnV4 == nil && c.unicastPktConnV6 == nil {
				c.log.Debugf("writing question to multicast IPv4/6 %s", c.dstAddr4)
				if ifc.supportsV4 && c.multicastPktConnV4 != nil {
					if _, err := c.multicastPktConnV4.WriteTo(b, &ifc.Interface, nil, c.dstAddr4); err != nil {
						c.log.Warnf("failed to send mDNS packet (multicast) on IPv4 interface %d: %v", ifc.Index, err)
					}
				}
				if ifc.supportsV6 && c.multicastPktConnV6 != nil {
					if _, err := c.multicastPktConnV6.WriteTo(b, &ifc.Interface, nil, c.dstAddr6); err != nil {
						c.log.Warnf("failed to send mDNS packet (multicast) on IPv6 interface %d: %v", ifc.Index, err)
					}
				}
			}
			if ifc.supportsV4 && c.unicastPktConnV4 != nil {
				c.log.Debugf("writing question to unicast IPv4 %s", c.dstAddr4)
				if _, err := c.unicastPktConnV4.WriteTo(b, &ifc.Interface, nil, c.dstAddr4); err != nil {
					c.log.Warnf("failed to send mDNS packet (unicast) on interface %d: %v", ifc.Index, err)
				}
			}
			if ifc.supportsV6 && c.unicastPktConnV6 != nil {
				c.log.Debugf("writing question to unicast IPv6 %s", c.dstAddr6)
				if _, err := c.unicastPktConnV6.WriteTo(b, &ifc.Interface, nil, c.dstAddr6); err != nil {
					c.log.Warnf("failed to send mDNS packet (unicast) on interface %d: %v", ifc.Index, err)
				}
			}
		} else {
			c.log.Debugf("writing answer to IPv4: %s, IPv6: %s", dst4, dst6)

			if ifc.supportsV4 && c.multicastPktConnV4 != nil && dst4 != nil {
				if _, err := c.multicastPktConnV4.WriteTo(b, &ifc.Interface, nil, dst4); err != nil {
					c.log.Warnf("failed to send mDNS packet (multicast) on IPv4 interface %d: %v", ifIndex, err)
				}
			}
			if ifc.supportsV6 && c.multicastPktConnV6 != nil && dst6 != nil {
				if _, err := c.multicastPktConnV6.WriteTo(b, &ifc.Interface, nil, dst6); err != nil {
					c.log.Warnf("failed to send mDNS packet (multicast) on IPv6 interface %d: %v", ifIndex, err)
				}
			}
		}
	}
}

func createAnswer(id uint16, name string, addr net.IP) (dnsmessage.Message, error) {
	packedName, err := dnsmessage.NewName(name)
	if err != nil {
		return dnsmessage.Message{}, err
	}

	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:            id,
			Response:      true,
			Authoritative: true,
		},
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Class: dnsmessage.ClassINET,
					Name:  packedName,
					TTL:   responseTTL,
				},
			},
		},
	}

	if len(addr) == net.IPv4len {
		ipBuf, err := ipv4ToBytes(addr)
		if err != nil {
			return dnsmessage.Message{}, err
		}
		msg.Answers[0].Header.Type = dnsmessage.TypeA
		msg.Answers[0].Body = &dnsmessage.AResource{
			A: ipBuf,
		}
	} else if len(addr) == net.IPv6len {
		ipBuf, err := ipv6ToBytes(addr)
		if err != nil {
			return dnsmessage.Message{}, err
		}
		msg.Answers[0].Header.Type = dnsmessage.TypeAAAA
		msg.Answers[0].Body = &dnsmessage.AAAAResource{
			AAAA: ipBuf,
		}
	}

	return msg, nil
}

func (c *Conn) sendAnswer(queryID uint16, name string, ifIndex int, result net.IP, dst *net.UDPAddr) {
	answer, err := createAnswer(queryID, name, result)
	if err != nil {
		c.log.Warnf("failed to create mDNS answer %v", err)
		return
	}

	rawAnswer, err := answer.Pack()
	if err != nil {
		c.log.Warnf("failed to construct mDNS packet %v", err)
		return
	}

	c.writeToSocket(ifIndex, rawAnswer, result.IsLoopback(), writeTypeAnswer, dst)
}

type ipControlMessage struct {
	IfIndex int
	Dst     net.IP
}

type ipPacketConn interface {
	ReadFrom(b []byte) (n int, cm *ipControlMessage, src net.Addr, err error)
	WriteTo(b []byte, via *net.Interface, cm *ipControlMessage, dst net.Addr) (n int, err error)
	Close() error
}

type ipPacketConn4 struct {
	conn *ipv4.PacketConn
	log  logging.LeveledLogger
}

func (c ipPacketConn4) ReadFrom(b []byte) (n int, cm *ipControlMessage, src net.Addr, err error) {
	n, cm4, src, err := c.conn.ReadFrom(b)
	if err != nil || cm4 == nil {
		return n, nil, src, err
	}
	return n, &ipControlMessage{IfIndex: cm4.IfIndex, Dst: cm4.Dst}, src, err
}

func (c ipPacketConn4) WriteTo(b []byte, via *net.Interface, cm *ipControlMessage, dst net.Addr) (n int, err error) {
	var cm4 *ipv4.ControlMessage
	if cm != nil {
		cm4 = &ipv4.ControlMessage{
			IfIndex: cm.IfIndex,
		}
	}
	if err := c.conn.SetMulticastInterface(via); err != nil {
		c.log.Warnf("failed to set multicast interface for %d: %v", via.Index, err)
		return 0, err
	}
	return c.conn.WriteTo(b, cm4, dst)
}

func (c ipPacketConn4) Close() error {
	return c.conn.Close()
}

type ipPacketConn6 struct {
	conn *ipv6.PacketConn
	log  logging.LeveledLogger
}

func (c ipPacketConn6) ReadFrom(b []byte) (n int, cm *ipControlMessage, src net.Addr, err error) {
	n, cm6, src, err := c.conn.ReadFrom(b)
	if err != nil || cm6 == nil {
		return n, nil, src, err
	}
	return n, &ipControlMessage{IfIndex: cm6.IfIndex, Dst: cm6.Dst}, src, err
}

func (c ipPacketConn6) WriteTo(b []byte, via *net.Interface, cm *ipControlMessage, dst net.Addr) (n int, err error) {
	var cm6 *ipv6.ControlMessage
	if cm != nil {
		cm6 = &ipv6.ControlMessage{
			IfIndex: cm.IfIndex,
		}
	}
	if err := c.conn.SetMulticastInterface(via); err != nil {
		c.log.Warnf("failed to set multicast interface for %d: %v", via.Index, err)
		return 0, err
	}
	return c.conn.WriteTo(b, cm6, dst)
}

func (c ipPacketConn6) Close() error {
	return c.conn.Close()
}

func (c *Conn) readLoop(name string, pktConn ipPacketConn, inboundBufferSize int, config *Config) { //nolint:gocognit
	b := make([]byte, inboundBufferSize)
	p := dnsmessage.Parser{}

	for {
		n, cm, src, err := pktConn.ReadFrom(b)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			c.log.Warnf("failed to ReadFrom %q %v", src, err)
			continue
		}
		c.log.Debugf("got read on %s from %s", name, src)

		var ifIndex int
		var pktDst net.IP
		if cm != nil {
			ifIndex = cm.IfIndex
			pktDst = cm.Dst
		}
		srcAddr, ok := src.(*net.UDPAddr)
		if !ok {
			c.log.Warnf("expected source address %s to be UDP but got %", src, src)
			continue
		}

		func() {
			header, err := p.Start(b[:n])
			if err != nil {
				c.log.Warnf("failed to parse mDNS packet %v", err)
				return
			}

			for i := 0; i <= maxMessageRecords; i++ {
				q, err := p.Question()
				if errors.Is(err, dnsmessage.ErrSectionDone) {
					break
				} else if err != nil {
					c.log.Warnf("failed to parse mDNS packet %v", err)
					return
				}

				if q.Type != dnsmessage.TypeA && q.Type != dnsmessage.TypeAAAA {
					continue
				}

				// https://datatracker.ietf.org/doc/html/rfc6762#section-6
				// The destination UDP port in all Multicast DNS responses MUST be 5353,
				// and the destination address MUST be the mDNS IPv4 link-local
				// multicast address 224.0.0.251 or its IPv6 equivalent FF02::FB, except
				// when generating a reply to a query that explicitly requested a
				// unicast response
				shouldUnicastResponse := (q.Class&(1<<15)) != 0 || // via the unicast-response bit
					srcAddr.Port != 5353 || // by virtue of being a legacy query (Section 6.7), or
					(len(pktDst) != 0 && !(pktDst.Equal(c.dstAddr4.IP) || // by virtue of being a direct unicast query
						pktDst.Equal(c.dstAddr6.IP)))
				var dst *net.UDPAddr
				if shouldUnicastResponse {
					dst = srcAddr
				}

				queryWantsV4 := q.Type == dnsmessage.TypeA

				for _, localName := range c.localNames {
					if localName == q.Name.String() {
						var localAddress net.IP
						if config.LocalAddress != nil {
							localAddress = config.LocalAddress
						} else {
							// prefer the address of the interface if we know its index, but otherwise
							// derive it from the address we read from. We do this because even if
							// multicast loopback is in use or we send from a loopback interface,
							// there are still cases where the IP packet will contain the wrong
							// source IP (e.g. a LAN interface).
							// For example, we can have a packet that has:
							// Source: 192.168.65.3
							// Destination: 224.0.0.251
							// Interface Index: 1
							// Interface Addresses @ 1: [127.0.0.1/8 ::1/128]
							if ifIndex != 0 {
								ifc, ok := c.ifaces[ifIndex]
								if !ok {
									c.log.Warnf("no interface for %d", ifIndex)
									return
								}
								var selectedIP net.IP
								for _, ip := range ifc.ips {
									ipCopy := ip
									ipIsV6 := ipCopy.To4() == nil

									// Query must match family (A for IPv4 and AAAA IPv6)
									if queryWantsV4 == ipIsV6 {
										continue
									}

									if ipIsV6 && !isSupportedIPv6(ipCopy, c.multicastPktConnV4 == nil) {
										c.log.Debugf("interface %d address not a supported IPv6 address %s", ifIndex, ipCopy)
										continue
									}

									selectedIP = ipCopy
									break
								}
								if selectedIP == nil {
									c.log.Debugf("failed to find suitable IP for interface %d; deriving address from source address instead", ifIndex)
								} else {
									localAddress = selectedIP
								}
							}
							if ifIndex == 0 || localAddress == nil {
								localAddress, err = interfaceForRemote(src.String())
								if err != nil {
									c.log.Warnf("failed to get local interface to communicate with %s: %v", src.String(), err)
									continue
								}
							}
						}
						if queryWantsV4 {
							localAddress = localAddress.To4()
							if localAddress == nil {
								c.log.Debugf("have IPv6 address %s to respond with but not question is for A not AAAA", localAddress)
								continue
							}
						} else {
							localAddress = localAddress.To16()
							if localAddress == nil {
								c.log.Debugf("have IPv4 address %s to respond with but not question is for AAAA not A", localAddress)
								continue
							}
							if !isSupportedIPv6(localAddress, c.multicastPktConnV4 == nil) {
								c.log.Debugf("got local interface address but not a supported IPv6 address %s", localAddress)
								continue
							}
						}
						c.sendAnswer(header.ID, q.Name.String(), ifIndex, localAddress, dst)
					}
				}
			}

			for i := 0; i <= maxMessageRecords; i++ {
				a, err := p.AnswerHeader()
				if errors.Is(err, dnsmessage.ErrSectionDone) {
					return
				}
				if err != nil {
					c.log.Warnf("failed to parse mDNS packet %v", err)
					return
				}

				if a.Type != dnsmessage.TypeA && a.Type != dnsmessage.TypeAAAA {
					continue
				}

				c.mu.Lock()
				queries := make([]*query, len(c.queries))
				copy(queries, c.queries)
				c.mu.Unlock()

				var answered []*query
				for _, query := range queries {
					queryCopy := query
					if queryCopy.nameWithSuffix == a.Name.String() {
						ip, err := ipFromAnswerHeader(a, p)
						if err != nil {
							c.log.Warnf("failed to parse mDNS answer %v", err)
							return
						}

						select {
						case queryCopy.queryResultChan <- queryResult{a, &net.IPAddr{
							IP: ip,
						}}:
							answered = append(answered, queryCopy)
						default:
						}
					}
				}

				c.mu.Lock()
				for queryIdx := len(c.queries) - 1; queryIdx >= 0; queryIdx-- {
					for answerIdx := len(answered) - 1; answerIdx >= 0; answerIdx-- {
						if c.queries[queryIdx] == answered[answerIdx] {
							c.queries = append(c.queries[:queryIdx], c.queries[queryIdx+1:]...)
							answered = append(answered[:answerIdx], answered[answerIdx+1:]...)
							queryIdx--
							break
						}
					}
				}
				c.mu.Unlock()
			}
		}()
	}
}

func (c *Conn) start(started chan<- struct{}, inboundBufferSize int, config *Config) {
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

func ipFromAnswerHeader(a dnsmessage.ResourceHeader, p dnsmessage.Parser) (ip []byte, err error) {
	if a.Type == dnsmessage.TypeA {
		resource, err := p.AResource()
		if err != nil {
			return nil, err
		}
		ip = resource.A[:]
	} else {
		resource, err := p.AAAAResource()
		if err != nil {
			return nil, err
		}
		ip = resource.AAAA[:]
	}

	return
}

func isSupportedIPv6(ip net.IP, ipv6Only bool) bool {
	if len(ip) != net.IPv6len ||
		// IPv4-mapped IPv6 addresses cannot be connected to
		(!ipv6Only && isZeros(ip[0:10]) && ip[10] == 0xff && ip[11] == 0xff) {
		return false
	}
	return true
}

func isZeros(ip net.IP) bool {
	for i := 0; i < len(ip); i++ {
		if ip[i] != 0 {
			return false
		}
	}
	return true
}
