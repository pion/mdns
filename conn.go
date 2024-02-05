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
	"go.uber.org/multierr"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Conn represents a mDNS Server
type Conn struct {
	mu  sync.RWMutex
	log logging.LeveledLogger

	multicastPktConnV4 ipPacketConn
	dstAddr4           *net.UDPAddr
	dstAddr6           *net.UDPAddr

	unicastPktConnV4 ipPacketConn
	unicastPktConnV6 ipPacketConn

	queryInterval time.Duration
	localNames    []string
	queries       []*query
	ifaces        []net.Interface

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

var errNoPositiveMTUFound = errors.New("no positive MTU found")

// Server establishes a mDNS connection over an existing conn.
//
// Currently, the server only supports listening on an IPv4 connection, but internally
// it supports answering with IPv6 AAAA records if this were ever to change.
func Server(multicastPktConnV4 *ipv4.PacketConn, config *Config) (*Conn, error) { //nolint:gocognit
	if config == nil {
		return nil, errNilConfig
	}
	loggerFactory := config.LoggerFactory
	if loggerFactory == nil {
		loggerFactory = logging.NewDefaultLoggerFactory()
	}
	log := loggerFactory.NewLogger("mdns")

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
	ifacesToUse := make([]net.Interface, 0, len(ifaces))
	for i := range ifaces {
		ifc := ifaces[i]
		if !config.IncludeLoopback && ifc.Flags&net.FlagLoopback == net.FlagLoopback {
			continue
		}
		if err := multicastPktConnV4.JoinGroup(&ifc, multicastGroupAddr4); err != nil {
			joinErrCount++
			continue
		}

		ifacesToUse = append(ifacesToUse, ifc)
		if ifc.MTU > inboundBufferSize {
			inboundBufferSize = ifc.MTU
		}
		if unicastPktConnV4 != nil {
			if err := unicastPktConnV4.JoinGroup(&ifc, multicastGroupAddr4); err != nil {
				log.Warnf("Failed to JoinGroup on unicast IPv4 connection %v", err)
			}
		}
		if unicastPktConnV6 != nil {
			if err := unicastPktConnV6.JoinGroup(&ifc, multicastGroupAddr6); err != nil {
				log.Warnf("Failed to JoinGroup on unicast IPv6 connection %v", err)
			}
		}
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

	localNames := []string{}
	for _, l := range config.LocalNames {
		localNames = append(localNames, l+".")
	}

	c := &Conn{
		queryInterval:      defaultQueryInterval,
		multicastPktConnV4: ipPacketConn4{multicastPktConnV4, log},
		unicastPktConnV4:   ipPacketConn4{unicastPktConnV4, log},
		unicastPktConnV6:   ipPacketConn6{unicastPktConnV6, log},
		dstAddr4:           dstAddr4,
		dstAddr6:           dstAddr6,
		localNames:         localNames,
		ifaces:             ifacesToUse,
		log:                log,
		closed:             make(chan interface{}),
	}
	if config.QueryInterval != 0 {
		c.queryInterval = config.QueryInterval
	}

	if err := multicastPktConnV4.SetControlMessage(ipv4.FlagInterface, true); err != nil {
		c.log.Warnf("Failed to SetControlMessage(ipv4.FlagInterface) on multicast IPv4 PacketConn %v", err)
	}
	if unicastPktConnV4 != nil {
		if err := unicastPktConnV4.SetControlMessage(ipv4.FlagInterface, true); err != nil {
			c.log.Warnf("Failed to SetControlMessage(ipv4.FlagInterface) on unicast IPv4 PacketConn %v", err)
		}
	}
	if unicastPktConnV6 != nil {
		if err := unicastPktConnV6.SetControlMessage(ipv6.FlagInterface, true); err != nil {
			c.log.Warnf("Failed to SetControlMessage(ipv6.FlagInterface) on unicast IPv6 PacketConn %v", err)
		}
	}

	if config.IncludeLoopback {
		// this is an efficient way for us to send ourselves a message faster instead of it going
		// further out into the network stack.
		if err := multicastPktConnV4.SetMulticastLoopback(true); err != nil {
			c.log.Warnf("Failed to SetMulticastLoopback(true) on multicast IPv4 PacketConn %v; this may cause inefficient network path communications", err)
		}
		if unicastPktConnV4 != nil {
			if err := unicastPktConnV4.SetMulticastLoopback(true); err != nil {
				c.log.Warnf("Failed to SetMulticastLoopback(true) on unicast IPv4 PacketConn %v; this may cause inefficient network path communications", err)
			}
		}
		if unicastPktConnV6 != nil {
			if err := unicastPktConnV6.SetMulticastLoopback(true); err != nil {
				c.log.Warnf("Failed to SetMulticastLoopback(true) on unicast IPv6 PacketConn %v; this may cause inefficient network path communications", err)
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

	var errs error
	if err := c.multicastPktConnV4.Close(); err != nil {
		errs = multierr.Combine(errs, err)
	}

	if c.unicastPktConnV4 != nil {
		if err := c.unicastPktConnV4.Close(); err != nil {
			errs = multierr.Combine(errs, err)
		}
	}

	if c.unicastPktConnV6 != nil {
		if err := c.unicastPktConnV6.Close(); err != nil {
			errs = multierr.Combine(errs, err)
		}
	}
	if errs != nil {
		return errs
	}

	<-c.closed
	return nil
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
		c.log.Warnf("Failed to construct mDNS packet %v", err)
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
		Questions: []dnsmessage.Question{
			{
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET | (1 << 15),
				Name:  packedName,
			},
		},
	}

	rawQuery, err := msg.Pack()
	if err != nil {
		c.log.Warnf("Failed to construct mDNS packet %v", err)
		return
	}

	c.writeToSocket(0, rawQuery, false, writeTypeQuestion, nil)
}

func (c *Conn) writeToSocket(ifIndex int, b []byte, srcIfcIsLoopback bool, wType writeType, dst net.Addr) { //nolint:gocognit
	if wType == writeTypeAnswer && dst == nil {
		c.log.Error("Writing an answer must specify a destination address")
		return
	}

	if ifIndex != 0 {
		if wType == writeTypeQuestion {
			c.log.Errorf("Unexpected question using specific interface index %d; dropping question", ifIndex)
			return
		}

		ifc, err := net.InterfaceByIndex(ifIndex)
		if err != nil {
			c.log.Warnf("Failed to get interface for %d: %v", ifIndex, err)
			return
		}
		if srcIfcIsLoopback && ifc.Flags&net.FlagLoopback == 0 {
			// avoid accidentally tricking the destination that itself is the same as us
			c.log.Warnf("Interface is not loopback %d", ifIndex)
			return
		}

		//nolint:godox
		// TODO(https://github.com/pion/mdns/issues/69): ipv6
		c.log.Debugf("writing answer to %s", dst)
		if _, err := c.multicastPktConnV4.WriteTo(b, ifc, nil, dst); err != nil {
			c.log.Warnf("Failed to send mDNS packet on interface %d: %v", ifIndex, err)
		}

		return
	}
	for ifcIdx := range c.ifaces {
		if srcIfcIsLoopback && c.ifaces[ifcIdx].Flags&net.FlagLoopback == 0 {
			// avoid accidentally tricking the destination that itself is the same as us
			continue
		}

		if wType == writeTypeQuestion {
			// we'll write via unicast if we can in case the responder chooses to respond to the address the request
			// came from (i.e. not respecting unicast-response bit). If we were to use the multicast packet
			// conn here, we'd be writing from a specific multicast address which won't be able to receive unicast
			// traffic (it only works when listening on 0.0.0.0/[::]).
			if c.unicastPktConnV4 == nil && c.unicastPktConnV6 == nil {
				c.log.Debugf("writing question to multicast IPv4 %s", c.dstAddr4)
				if _, err := c.multicastPktConnV4.WriteTo(b, &c.ifaces[ifcIdx], nil, c.dstAddr4); err != nil {
					c.log.Warnf("Failed to send mDNS packet on interface %d: %v", c.ifaces[ifcIdx].Index, err)
				}
			}
			if c.unicastPktConnV4 != nil {
				c.log.Debugf("writing question to unicast IPv4 %s", c.dstAddr4)
				if _, err := c.unicastPktConnV4.WriteTo(b, &c.ifaces[ifcIdx], nil, c.dstAddr4); err != nil {
					c.log.Warnf("Failed to send mDNS packet on interface %d: %v", c.ifaces[ifcIdx].Index, err)
				}
			}
			if c.unicastPktConnV6 != nil {
				c.log.Debugf("writing question to unicast IPv6 %s", c.dstAddr6)
				if _, err := c.unicastPktConnV6.WriteTo(b, &c.ifaces[ifcIdx], nil, c.dstAddr6); err != nil {
					c.log.Warnf("Failed to send mDNS packet on interface %d: %v", c.ifaces[ifcIdx].Index, err)
				}
			}
		} else {
			//nolint:godox
			// TODO(https://github.com/pion/mdns/issues/69): ipv6
			c.log.Debugf("writing answer to %s", dst)
			if _, err := c.multicastPktConnV4.WriteTo(b, &c.ifaces[ifcIdx], nil, dst); err != nil {
				c.log.Warnf("Failed to send mDNS packet on interface %d: %v", c.ifaces[ifcIdx].Index, err)
			}
		}
	}
}

func createAnswer(name string, addr net.IP) (dnsmessage.Message, error) {
	packedName, err := dnsmessage.NewName(name)
	if err != nil {
		return dnsmessage.Message{}, err
	}

	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			Response:      true,
			Authoritative: true,
		},
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					Name:  packedName,
					TTL:   responseTTL,
				},
			},
		},
	}

	if ip4 := addr.To4(); ip4 != nil {
		ipBuf, err := ipv4ToBytes(addr)
		if err != nil {
			return dnsmessage.Message{}, err
		}
		msg.Answers[0].Body = &dnsmessage.AResource{
			A: ipBuf,
		}
	} else {
		ipBuf, err := ipv6ToBytes(addr)
		if err != nil {
			return dnsmessage.Message{}, err
		}
		msg.Answers[0].Body = &dnsmessage.AAAAResource{
			AAAA: ipBuf,
		}
	}

	return msg, nil
}

func (c *Conn) sendAnswer(name string, ifIndex int, result net.IP, dst net.Addr) {
	answer, err := createAnswer(name, result)
	if err != nil {
		c.log.Warnf("Failed to create mDNS answer %v", err)
		return
	}

	rawAnswer, err := answer.Pack()
	if err != nil {
		c.log.Warnf("Failed to construct mDNS packet %v", err)
		return
	}

	c.writeToSocket(ifIndex, rawAnswer, result.IsLoopback(), writeTypeAnswer, dst)
}

type ipControlMessage struct {
	IfIndex int
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
	return n, &ipControlMessage{IfIndex: cm4.IfIndex}, src, err
}

func (c ipPacketConn4) WriteTo(b []byte, via *net.Interface, cm *ipControlMessage, dst net.Addr) (n int, err error) {
	var cm4 *ipv4.ControlMessage
	if cm != nil {
		cm4 = &ipv4.ControlMessage{
			IfIndex: cm.IfIndex,
		}
	}
	if err := c.conn.SetMulticastInterface(via); err != nil {
		c.log.Warnf("Failed to set multicast interface for %d: %v", via.Index, err)
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
	return n, &ipControlMessage{IfIndex: cm6.IfIndex}, src, err
}

func (c ipPacketConn6) WriteTo(b []byte, via *net.Interface, cm *ipControlMessage, dst net.Addr) (n int, err error) {
	var cm6 *ipv6.ControlMessage
	if cm != nil {
		cm6 = &ipv6.ControlMessage{
			IfIndex: cm.IfIndex,
		}
	}
	if err := c.conn.SetMulticastInterface(via); err != nil {
		c.log.Warnf("Failed to set multicast interface for %d: %v", via.Index, err)
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
			c.log.Warnf("Failed to ReadFrom %q %v", src, err)
			continue
		}
		c.log.Debugf("got read on %s from %s", name, src)

		var ifIndex int
		if cm != nil {
			ifIndex = cm.IfIndex
		}
		srcAddr, ok := src.(*net.UDPAddr)
		if !ok {
			c.log.Warnf("Expected source address %s to be UDP but got %", src, src)
			continue
		}
		srcIP := srcAddr.IP
		srcIsIPv4 := srcIP.To4() != nil

		func() {
			c.mu.RLock()
			defer c.mu.RUnlock()

			if _, err := p.Start(b[:n]); err != nil {
				c.log.Warnf("Failed to parse mDNS packet %v", err)
				return
			}

			for i := 0; i <= maxMessageRecords; i++ {
				q, err := p.Question()
				if errors.Is(err, dnsmessage.ErrSectionDone) {
					break
				} else if err != nil {
					c.log.Warnf("Failed to parse mDNS packet %v", err)
					return
				}
				shouldUnicastResponse := (q.Class & (1 << 15)) != 0
				//nolint:godox
				// TODO(https://github.com/pion/mdns/issues/69): ipv6 here
				dst := c.dstAddr4
				if shouldUnicastResponse {
					dst = srcAddr
				}

				for _, localName := range c.localNames {
					if localName == q.Name.String() {
						if config.LocalAddress != nil {
							c.sendAnswer(q.Name.String(), ifIndex, config.LocalAddress, dst)
						} else {
							var localAddress net.IP

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
								ifc, netErr := net.InterfaceByIndex(ifIndex)
								if netErr != nil {
									c.log.Warnf("Failed to get interface for %d: %v", ifIndex, netErr)
									continue
								}
								addrs, addrsErr := ifc.Addrs()
								if addrsErr != nil {
									c.log.Warnf("Failed to get addresses for interface %d: %v", ifIndex, addrsErr)
									continue
								}
								if len(addrs) == 0 {
									c.log.Warnf("Expected more than one address for interface %d", ifIndex)
									continue
								}
								var selectedIP net.IP
								for _, addr := range addrs {
									var ip net.IP
									switch addr := addr.(type) {
									case *net.IPNet:
										ip = addr.IP
									case *net.IPAddr:
										ip = addr.IP
									default:
										c.log.Warnf("Failed to determine address type %T from interface %d", addr, ifIndex)
										continue
									}

									// match up respective IP types
									if ipv4 := ip.To4(); ipv4 == nil {
										if srcIsIPv4 {
											continue
										} else if !isSupportedIPv6(ip) {
											continue
										}
									} else if !srcIsIPv4 {
										continue
									}
									selectedIP = ip
									break
								}
								if selectedIP == nil {
									c.log.Warnf("Failed to find suitable IP for interface %d; deriving address from source address instead", ifIndex)
								} else {
									localAddress = selectedIP
								}
							} else if ifIndex == 0 || localAddress == nil {
								localAddress, err = interfaceForRemote(src.String())
								if err != nil {
									c.log.Warnf("Failed to get local interface to communicate with %s: %v", src.String(), err)
									continue
								}
							}

							c.sendAnswer(q.Name.String(), ifIndex, localAddress, dst)
						}
					}
				}
			}

			for i := 0; i <= maxMessageRecords; i++ {
				a, err := p.AnswerHeader()
				if errors.Is(err, dnsmessage.ErrSectionDone) {
					return
				}
				if err != nil {
					c.log.Warnf("Failed to parse mDNS packet %v", err)
					return
				}

				if a.Type != dnsmessage.TypeA && a.Type != dnsmessage.TypeAAAA {
					continue
				}

				for i := len(c.queries) - 1; i >= 0; i-- {
					if c.queries[i].nameWithSuffix == a.Name.String() {
						ip, err := ipFromAnswerHeader(a, p)
						if err != nil {
							c.log.Warnf("Failed to parse mDNS answer %v", err)
							return
						}

						c.queries[i].queryResultChan <- queryResult{a, &net.IPAddr{
							IP: ip,
						}}
						c.queries = append(c.queries[:i], c.queries[i+1:]...)
					}
				}
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

// The conditions of invalidation written below are defined in
// https://tools.ietf.org/html/rfc8445#section-5.1.1.1
func isSupportedIPv6(ip net.IP) bool {
	if len(ip) != net.IPv6len ||
		isZeros(ip[0:12]) || // !(IPv4-compatible IPv6)
		ip[0] == 0xfe && ip[1]&0xc0 == 0xc0 || // !(IPv6 site-local unicast)
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() {
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
