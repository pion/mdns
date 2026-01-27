// SPDX-FileCopyrightText: The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package mdns

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"

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

// createAnswer creates a DNS answer message for an A or AAAA query.
func (s *server) createAnswer(id uint16, question dnsmessage.Question, addr netip.Addr,
	isUnicast bool,
) (dnsmessage.Message, error) {
	packedName, err := dnsmessage.NewName(question.Name.String())
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
					TTL:   s.ttl,
				},
			},
		},
	}

	// include question in answer if specified for this answer (such as unicast: Spec 6.7.)
	if isUnicast {
		msg.Questions = []dnsmessage.Question{question}
	}

	if addr.Is4() {
		ipBuf, err := ipv4ToBytes(addr)
		if err != nil {
			return dnsmessage.Message{}, err
		}
		msg.Answers[0].Header.Type = dnsmessage.TypeA
		msg.Answers[0].Body = &dnsmessage.AResource{
			A: ipBuf,
		}
	} else if addr.Is6() {
		// we will lose the zone here, but the receiver can reconstruct it
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

	mu       sync.RWMutex
	services []ServiceInstance
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

// unregisterService removes a DNS-SD service from the server by instance+service match.
func (s *server) unregisterService(instance, service string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := len(s.services) - 1; i >= 0; i-- {
		if s.services[i].Instance == instance && s.services[i].Service == service {
			s.services = append(s.services[:i], s.services[i+1:]...)

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

// sendAnswer implements answerSender interface.
func (s *server) sendAnswer(
	queryID uint16, question dnsmessage.Question, ifIndex int,
	addr netip.Addr, dst *net.UDPAddr, isUnicast bool,
) {
	answer, err := s.createAnswer(queryID, question, addr, isUnicast)
	if err != nil {
		s.log.Warnf("[%s] failed to create mDNS answer %v", s.name, err)

		return
	}

	rawAnswer, err := answer.Pack()
	if err != nil {
		s.log.Warnf("[%s] failed to construct mDNS packet %v", s.name, err)

		return
	}

	s.writer.writeAnswer(
		ifIndex,
		rawAnswer,
		addr.IsLoopback(),
		addr.Is6() && addr.Zone() != "",
		dst,
	)
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

	// Default TTL per RFC 6762 recommendation
	if cfg.responseTTL == 0 {
		cfg.responseTTL = responseTTL
	}

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

	// Create client and server for processing messages
	conn.client = newClient(
		log,
		conn.name,
		conn, // Conn implements questionWriter
		multicastPktConnV4 != nil,
		multicastPktConnV6 != nil,
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

// sendServiceAnswer builds and sends a DNS-SD response for a service instance.
// Per RFC 6763 §12, additional records are included:
//   - PTR answer → SRV + TXT additional, plus A/AAAA for the host
//   - SRV answer → A/AAAA additional for the host
func (s *server) sendServiceAnswer(
	queryID uint16, question dnsmessage.Question, ifIndex int,
	svc *ServiceInstance, addr netip.Addr, dst *net.UDPAddr, isUnicast bool,
) {
	msg, err := s.createServiceAnswer(queryID, question, svc, addr, isUnicast)
	if err != nil {
		s.log.Warnf("[%s] failed to create DNS-SD answer %v", s.name, err)

		return
	}

	rawAnswer, err := msg.Pack()
	if err != nil {
		s.log.Warnf("[%s] failed to pack DNS-SD answer %v", s.name, err)

		return
	}

	s.writer.writeAnswer(
		ifIndex,
		rawAnswer,
		addr.IsLoopback(),
		addr.Is6() && addr.Zone() != "",
		dst,
	)
}

// createServiceAnswer builds a DNS message for a DNS-SD service query.
//
//nolint:cyclop
func (s *server) createServiceAnswer(
	queryID uint16, question dnsmessage.Question,
	svc *ServiceInstance, addr netip.Addr, isUnicast bool,
) (dnsmessage.Message, error) {
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:            queryID,
			Response:      true,
			Authoritative: true,
		},
	}

	if isUnicast {
		msg.Questions = []dnsmessage.Question{question}
	}

	instanceName := svc.serviceInstanceName()
	svcName := svc.serviceName()

	switch question.Type {
	case dnsmessage.TypePTR:
		// PTR answer: service name → instance name
		ptrRec, err := buildPTRResource(svcName, instanceName, browseTTL)
		if err != nil {
			return dnsmessage.Message{}, err
		}
		msg.Answers = []dnsmessage.Resource{ptrRec}

		// Additional: SRV + TXT + address records (RFC 6763 §12.1)
		additional, err := s.buildServiceAdditional(svc, instanceName, addr)
		if err != nil {
			return dnsmessage.Message{}, err
		}
		msg.Additionals = additional

	case dnsmessage.TypeSRV:
		// SRV answer
		srvRec, err := buildSRVResource(instanceName, svc.Host, svc.Port, svc.Priority, svc.Weight, s.ttl)
		if err != nil {
			return dnsmessage.Message{}, err
		}
		msg.Answers = []dnsmessage.Resource{srvRec}

		// Additional: address records (RFC 6763 §12.2)
		addrRec, err := s.buildAddressResource(svc.Host, addr)
		if err != nil {
			return dnsmessage.Message{}, err
		}
		msg.Additionals = []dnsmessage.Resource{addrRec}

	case dnsmessage.TypeTXT:
		// TXT answer
		txtStrings, err := encodeTXTRecordStrings(svc.Text)
		if err != nil {
			return dnsmessage.Message{}, err
		}
		txtRec, err := buildTXTResource(instanceName, txtStrings, s.ttl)
		if err != nil {
			return dnsmessage.Message{}, err
		}
		msg.Answers = []dnsmessage.Resource{txtRec}

	default:
		return dnsmessage.Message{}, errUnhandledServiceQuestionType
	}

	return msg, nil
}

// buildServiceAdditional creates the additional records for a PTR response.
func (s *server) buildServiceAdditional(
	svc *ServiceInstance, instanceName string, addr netip.Addr,
) ([]dnsmessage.Resource, error) {
	var additional []dnsmessage.Resource

	srvRec, err := buildSRVResource(instanceName, svc.Host, svc.Port, svc.Priority, svc.Weight, s.ttl)
	if err != nil {
		return nil, err
	}
	additional = append(additional, srvRec)

	txtStrings, err := encodeTXTRecordStrings(svc.Text)
	if err != nil {
		return nil, err
	}
	txtRec, err := buildTXTResource(instanceName, txtStrings, s.ttl)
	if err != nil {
		return nil, err
	}
	additional = append(additional, txtRec)

	addrRec, err := s.buildAddressResource(svc.Host, addr)
	if err != nil {
		return nil, err
	}
	additional = append(additional, addrRec)

	return additional, nil
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
		addr netip.Addr, dst *net.UDPAddr, isUnicast bool,
	)
	sendServiceAnswer(
		queryID uint16, question dnsmessage.Question, ifIndex int,
		svc *ServiceInstance, addr netip.Addr, dst *net.UDPAddr, isUnicast bool,
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

	for _, allowed := range h.allowedRecordTypes {
		if allowed == qtype {
			return true
		}
	}

	return false
}

// handle processes a DNS message containing questions.
// It iterates through questions and sends answers for matching local names
// and registered DNS-SD services.
//
//nolint:gocognit,gocyclo,cyclop
func (h *questionHandler) handle(ctx *messageContext, msg *dnsmessage.Message) {
	for _, question := range msg.Questions {
		if !h.isRecordTypeAllowed(question.Type) {
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

		switch question.Type {
		case dnsmessage.TypeA, dnsmessage.TypeAAAA:
			h.handleAddressQuestion(ctx, msg.Header.ID, question, dst, shouldReplyUnicast)
		case dnsmessage.TypePTR:
			h.handlePTRQuestion(ctx, msg.Header.ID, question, dst, shouldReplyUnicast)
		case dnsmessage.TypeSRV, dnsmessage.TypeTXT:
			h.handleServiceRecordQuestion(ctx, msg.Header.ID, question, dst, shouldReplyUnicast)
		default:
			continue
		}
	}
}

// handleAddressQuestion processes A/AAAA questions against local names.
func (h *questionHandler) handleAddressQuestion(
	ctx *messageContext, queryID uint16, question dnsmessage.Question,
	dst *net.UDPAddr, isUnicast bool,
) {
	queryWantsV4 := question.Type == dnsmessage.TypeA

	for _, localName := range h.localNames {
		if !strings.EqualFold(localName, question.Name.String()) {
			continue
		}

		localAddress := h.resolveLocalAddress(ctx, queryWantsV4, dst)
		if localAddress == nil {
			continue
		}

		h.log.Debugf(
			"[%s] sending response for %s on ifc %d of %s to %s",
			h.name, question.Name, ctx.ifIndex, *localAddress, dst,
		)
		h.sender.sendAnswer(queryID, question, ctx.ifIndex, *localAddress, dst, isUnicast)
	}
}

// handlePTRQuestion processes PTR questions for DNS-SD service browsing and
// service type enumeration.
func (h *questionHandler) handlePTRQuestion(
	ctx *messageContext, queryID uint16, question dnsmessage.Question,
	dst *net.UDPAddr, isUnicast bool,
) {
	services := h.sender.getServices()
	qname := question.Name.String()

	for i := range services {
		svc := &services[i]
		svcName := svc.serviceName()

		if !strings.EqualFold(svcName, qname) {
			continue
		}

		// Resolve an address for the additional records.
		localAddress := h.resolveLocalAddress(ctx, true, dst)
		if localAddress == nil {
			localAddress = h.resolveLocalAddress(ctx, false, dst)
		}
		if localAddress == nil {
			continue
		}

		h.log.Debugf("[%s] sending PTR response for %s on ifc %d to %s", h.name, qname, ctx.ifIndex, dst)
		h.sender.sendServiceAnswer(queryID, question, ctx.ifIndex, svc, *localAddress, dst, isUnicast)
	}
}

// handleServiceRecordQuestion processes SRV/TXT questions against registered services.
func (h *questionHandler) handleServiceRecordQuestion(
	ctx *messageContext, queryID uint16, question dnsmessage.Question,
	dst *net.UDPAddr, isUnicast bool,
) {
	services := h.sender.getServices()
	qname := question.Name.String()

	for i := range services {
		svc := &services[i]
		instanceName := svc.serviceInstanceName()

		if !strings.EqualFold(instanceName, qname) {
			continue
		}

		localAddress := h.resolveLocalAddress(ctx, true, dst)
		if localAddress == nil {
			localAddress = h.resolveLocalAddress(ctx, false, dst)
		}
		if localAddress == nil {
			continue
		}

		h.log.Debugf("[%s] sending %v response for %s on ifc %d to %s",
			h.name, question.Type, qname, ctx.ifIndex, dst)
		h.sender.sendServiceAnswer(queryID, question, ctx.ifIndex, svc, *localAddress, dst, isUnicast)
	}
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
