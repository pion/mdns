// SPDX-FileCopyrightText: The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package mdns

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/pion/logging"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

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
	cfg := &serverConfig{}
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

	conn := &Conn{
		queryInterval: defaultQueryInterval,
		log:           log,
		closed:        make(chan any),
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

	conn, err := NewServer(multicastPktConnV4, multicastPktConnV6, opts...)
	if err != nil {
		return nil, err
	}

	// Apply QueryInterval from legacy config (used for client queries)
	if config.QueryInterval != 0 {
		conn.queryInterval = config.QueryInterval
	}

	return conn, nil
}
