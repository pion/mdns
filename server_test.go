// SPDX-FileCopyrightText: The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package mdns

import (
	"net"
	"net/netip"
	"testing"

	"github.com/pion/logging"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func TestWithName(t *testing.T) {
	cfg := &serverConfig{}
	opt := WithName("test-server")
	err := opt.applyServer(cfg)

	assert.NoError(t, err)
	assert.Equal(t, "test-server", cfg.name)
}

func TestWithLocalNames(t *testing.T) {
	cfg := &serverConfig{}
	opt := WithLocalNames("foo.local", "bar.local")
	err := opt.applyServer(cfg)

	assert.NoError(t, err)
	assert.Equal(t, []string{"foo.local", "bar.local"}, cfg.localNames)
}

func TestWithLocalAddress(t *testing.T) {
	cfg := &serverConfig{}
	ip := net.ParseIP("192.168.1.100")
	opt := WithLocalAddress(ip)
	err := opt.applyServer(cfg)

	assert.NoError(t, err)
	assert.Equal(t, ip, cfg.localAddress)
}

func TestWithLoggerFactory(t *testing.T) {
	cfg := &serverConfig{}
	factory := logging.NewDefaultLoggerFactory()
	opt := WithLoggerFactory(factory)
	err := opt.applyServer(cfg)

	assert.NoError(t, err)
	assert.Equal(t, factory, cfg.loggerFactory)
}

func TestWithIncludeLoopback(t *testing.T) {
	cfg := &serverConfig{}

	// Test setting to true
	opt := WithIncludeLoopback(true)
	err := opt.applyServer(cfg)
	assert.NoError(t, err)
	assert.True(t, cfg.includeLoopback)

	// Test setting to false
	opt = WithIncludeLoopback(false)
	err = opt.applyServer(cfg)
	assert.NoError(t, err)
	assert.False(t, cfg.includeLoopback)
}

func TestWithInterfaces(t *testing.T) {
	cfg := &serverConfig{}
	ifaces := []net.Interface{
		{Index: 1, Name: "eth0"},
		{Index: 2, Name: "eth1"},
	}
	opt := WithInterfaces(ifaces...)
	err := opt.applyServer(cfg)

	assert.NoError(t, err)
	assert.Equal(t, ifaces, cfg.interfaces)
}

func TestWithRecordTypes(t *testing.T) {
	cfg := &serverConfig{}

	// Test setting specific record types (legacy WebRTC/ICE behavior)
	opt := WithRecordTypes(dnsmessage.TypeA, dnsmessage.TypeAAAA)
	err := opt.applyServer(cfg)
	assert.NoError(t, err)
	assert.Equal(t, []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA}, cfg.allowedRecordTypes)

	// Test empty (future DNS-SD behavior - all types allowed)
	cfg2 := &serverConfig{}
	assert.Empty(t, cfg2.allowedRecordTypes)
}

func TestSharedOptionsWorkWithClientConfig(t *testing.T) {
	// Verify shared options implement both interfaces
	clientCfg := &clientConfig{}

	err := WithName("client").applyClient(clientCfg)
	assert.NoError(t, err)
	assert.Equal(t, "client", clientCfg.name)

	factory := logging.NewDefaultLoggerFactory()
	err = WithLoggerFactory(factory).applyClient(clientCfg)
	assert.NoError(t, err)
	assert.Equal(t, factory, clientCfg.loggerFactory)

	err = WithIncludeLoopback(true).applyClient(clientCfg)
	assert.NoError(t, err)
	assert.True(t, clientCfg.includeLoopback)

	ifaces := []net.Interface{{Index: 1, Name: "eth0"}}
	err = WithInterfaces(ifaces...).applyClient(clientCfg)
	assert.NoError(t, err)
	assert.Equal(t, ifaces, clientCfg.interfaces)
}

func TestMultipleOptionsApplied(t *testing.T) {
	cfg := &serverConfig{}
	factory := logging.NewDefaultLoggerFactory()
	ip := net.ParseIP("10.0.0.1")
	ifaces := []net.Interface{{Index: 1, Name: "eth0"}}

	// Apply multiple options
	opts := []ServerOption{
		WithName("multi-test"),
		WithLoggerFactory(factory),
		WithLocalNames("service.local"),
		WithLocalAddress(ip),
		WithIncludeLoopback(true),
		WithInterfaces(ifaces...),
		WithRecordTypes(dnsmessage.TypeA),
		WithResponseTTL(300),
	}

	for _, opt := range opts {
		err := opt.applyServer(cfg)
		assert.NoError(t, err)
	}

	assert.Equal(t, "multi-test", cfg.name)
	assert.Equal(t, factory, cfg.loggerFactory)
	assert.Equal(t, []string{"service.local"}, cfg.localNames)
	assert.Equal(t, ip, cfg.localAddress)
	assert.True(t, cfg.includeLoopback)
	assert.Equal(t, ifaces, cfg.interfaces)
	assert.Equal(t, []dnsmessage.Type{dnsmessage.TypeA}, cfg.allowedRecordTypes)
	assert.Equal(t, uint32(300), cfg.responseTTL)
}

func TestServerConfigDefaults(t *testing.T) {
	cfg := &serverConfig{}

	// Verify zero-value defaults
	assert.Empty(t, cfg.name)
	assert.Empty(t, cfg.localNames)
	assert.Nil(t, cfg.localAddress)
	assert.Nil(t, cfg.loggerFactory)
	assert.False(t, cfg.includeLoopback)
	assert.Nil(t, cfg.interfaces)
	assert.Empty(t, cfg.allowedRecordTypes)
}

func TestClientConfigDefaults(t *testing.T) {
	cfg := &clientConfig{}

	// Verify zero-value defaults
	assert.Empty(t, cfg.name)
	assert.Zero(t, cfg.queryInterval)
	assert.Nil(t, cfg.loggerFactory)
	assert.False(t, cfg.includeLoopback)
	assert.Nil(t, cfg.interfaces)
}

func TestWithLocalAddressIPv6(t *testing.T) {
	cfg := &serverConfig{}
	ip := net.ParseIP("::1")
	opt := WithLocalAddress(ip)
	err := opt.applyServer(cfg)

	assert.NoError(t, err)
	assert.Equal(t, ip, cfg.localAddress)
	assert.True(t, cfg.localAddress.To4() == nil, "expected IPv6 address")
}

func TestWithLocalNamesEmpty(t *testing.T) {
	cfg := &serverConfig{}
	opt := WithLocalNames()
	err := opt.applyServer(cfg)

	assert.NoError(t, err)
	assert.Empty(t, cfg.localNames)
}

func TestWithInterfacesEmpty(t *testing.T) {
	cfg := &serverConfig{}
	opt := WithInterfaces()
	err := opt.applyServer(cfg)

	assert.NoError(t, err)
	assert.Empty(t, cfg.interfaces)
}

func TestWithRecordTypesEmpty(t *testing.T) {
	cfg := &serverConfig{}
	opt := WithRecordTypes()
	err := opt.applyServer(cfg)

	assert.NoError(t, err)
	assert.Empty(t, cfg.allowedRecordTypes)
}

func TestWithResponseTTL(t *testing.T) {
	cfg := &serverConfig{}

	err := WithResponseTTL(300).applyServer(cfg)
	assert.NoError(t, err)
	assert.Equal(t, uint32(300), cfg.responseTTL)
}

func TestWithResponseTTLZero(t *testing.T) {
	cfg := &serverConfig{}

	err := WithResponseTTL(0).applyServer(cfg)
	assert.ErrorIs(t, err, errResponseTTLZero)
	assert.Zero(t, cfg.responseTTL)
}

func TestOptionsImplementInterfaces(t *testing.T) {
	// Verify compile-time interface compliance by assigning to interface variables.
	// This test ensures the option types correctly implement their interfaces.
	var serverOpt ServerOption
	var clientOpt ClientOption

	// Shared options implement both interfaces
	serverOpt = WithName("test")
	clientOpt = WithName("test")
	_ = serverOpt
	_ = clientOpt

	serverOpt = WithLoggerFactory(logging.NewDefaultLoggerFactory())
	clientOpt = WithLoggerFactory(logging.NewDefaultLoggerFactory())
	_ = serverOpt
	_ = clientOpt

	serverOpt = WithIncludeLoopback(false)
	clientOpt = WithIncludeLoopback(false)
	_ = serverOpt
	_ = clientOpt

	ifaces := []net.Interface{{Index: 1, Name: "eth0"}}
	serverOpt = WithInterfaces(ifaces...)
	clientOpt = WithInterfaces(ifaces...)
	_ = serverOpt
	_ = clientOpt

	// Server-only options
	serverOpt = WithLocalNames("test.local")
	_ = serverOpt

	serverOpt = WithLocalAddress(net.ParseIP("127.0.0.1"))
	_ = serverOpt

	serverOpt = WithRecordTypes(dnsmessage.TypeA)
	_ = serverOpt

	serverOpt = WithResponseTTL(120)
	_ = serverOpt

	// If this test compiles and runs, the interfaces are satisfied
}

func TestNewServerErrorNoUsableInterfaces(t *testing.T) {
	// Interface with no addresses and down flag - should be skipped
	ifaces := []net.Interface{
		{Index: 1, Name: "dummy0", Flags: 0}, // not up
	}

	sock := createListener4(t)
	defer func() { _ = sock.Close() }()

	_, err := NewServer(ipv4.NewPacketConn(sock), nil,
		WithInterfaces(ifaces...),
	)
	assert.Error(t, err)
}

func TestNewServerErrorNoPacketConn(t *testing.T) {
	_, err := NewServer(nil, nil)
	assert.Error(t, err)
}

func TestNewServerWithDownInterface(t *testing.T) {
	// Interface that is down should be skipped
	ifaces := []net.Interface{
		{Index: 1, Name: "down0", Flags: 0, MTU: 1500}, // FlagUp not set
	}

	sock := createListener4(t)
	defer func() { _ = sock.Close() }()

	_, err := NewServer(ipv4.NewPacketConn(sock), nil,
		WithInterfaces(ifaces...),
	)
	// Should fail because no usable interfaces
	assert.Error(t, err)
}

func TestNewServerWithLoopbackExcluded(t *testing.T) {
	// When IncludeLoopback is false (default), loopback interfaces should be skipped
	ifaces := []net.Interface{
		{Index: 1, Name: "lo", Flags: net.FlagUp | net.FlagLoopback, MTU: 65536},
	}

	sock := createListener4(t)
	defer func() { _ = sock.Close() }()

	_, err := NewServer(ipv4.NewPacketConn(sock), nil,
		WithInterfaces(ifaces...),
		WithIncludeLoopback(false),
	)
	// Should fail because loopback is the only interface and it's excluded
	assert.Error(t, err)
}

func TestNewServerWithZeroMTU(t *testing.T) {
	// Interface with MTU=0 would trigger errNoPositiveMTUFound if it could join multicast.
	// Since fake interfaces can't join multicast groups, this tests the "no usable interfaces" path.
	ifaces := []net.Interface{
		{Index: 999, Name: "fake0", Flags: net.FlagUp | net.FlagMulticast, MTU: 0},
	}

	sock := createListener4(t)
	defer func() { _ = sock.Close() }()

	_, err := NewServer(ipv4.NewPacketConn(sock), nil,
		WithInterfaces(ifaces...),
	)
	// Will fail - either no usable interfaces or MTU error
	assert.Error(t, err)
}

func TestNewServerIncludeLoopbackDualStack(t *testing.T) {
	// Test IncludeLoopback with both IPv4 and IPv6 to cover SetMulticastLoopback paths.
	// This covers lines 322, 330, 340, 349 in server.go.
	sock4 := createListener4(t)
	sock6 := createListener6(t)

	server, err := NewServer(
		ipv4.NewPacketConn(sock4),
		ipv6.NewPacketConn(sock6),
		WithIncludeLoopback(true),
	)
	if err != nil {
		// May fail on some systems where loopback can't join multicast
		t.Skipf("could not create dual-stack server with IncludeLoopback: %v", err)
	}

	assert.NoError(t, server.Close())
}

func TestNewServerIncludeLoopbackIPv4Only(t *testing.T) {
	// Test IncludeLoopback with IPv4 only
	sock4 := createListener4(t)

	server, err := NewServer(
		ipv4.NewPacketConn(sock4),
		nil,
		WithIncludeLoopback(true),
	)
	if err != nil {
		t.Skipf("could not create IPv4 server with IncludeLoopback: %v", err)
	}

	assert.NoError(t, server.Close())
}

func TestNewServerIncludeLoopbackIPv6Only(t *testing.T) {
	// Test IncludeLoopback with IPv6 only
	sock6 := createListener6(t)

	server, err := NewServer(
		nil,
		ipv6.NewPacketConn(sock6),
		WithIncludeLoopback(true),
	)
	if err != nil {
		t.Skipf("could not create IPv6 server with IncludeLoopback: %v", err)
	}

	assert.NoError(t, server.Close())
}

// mockAnswerSender records calls to sendAnswer for testing.
type mockAnswerSender struct {
	calls        []mockAnswerCall
	serviceCalls []mockServiceAnswerCall
	services     []ServiceInstance
}

type mockAnswerCall struct {
	queryID   uint16
	question  dnsmessage.Question
	ifIndex   int
	addr      netip.Addr
	dst       *net.UDPAddr
	isUnicast bool
}

type mockServiceAnswerCall struct {
	queryID   uint16
	question  dnsmessage.Question
	ifIndex   int
	svc       *ServiceInstance
	addr      netip.Addr
	dst       *net.UDPAddr
	isUnicast bool
}

func (m *mockAnswerSender) sendAnswer(
	queryID uint16, question dnsmessage.Question, ifIndex int,
	addr netip.Addr, dst *net.UDPAddr, isUnicast bool,
) {
	m.calls = append(m.calls, mockAnswerCall{
		queryID:   queryID,
		question:  question,
		ifIndex:   ifIndex,
		addr:      addr,
		dst:       dst,
		isUnicast: isUnicast,
	})
}

func (m *mockAnswerSender) sendServiceAnswer(
	queryID uint16, question dnsmessage.Question, ifIndex int,
	svc *ServiceInstance, addr netip.Addr, dst *net.UDPAddr, isUnicast bool,
) {
	m.serviceCalls = append(m.serviceCalls, mockServiceAnswerCall{
		queryID:   queryID,
		question:  question,
		ifIndex:   ifIndex,
		svc:       svc,
		addr:      addr,
		dst:       dst,
		isUnicast: isUnicast,
	})
}

func (m *mockAnswerSender) getServices() []ServiceInstance {
	return m.services
}

// questionHandlerTestSetup holds common test fixtures for questionHandler tests.
type questionHandlerTestSetup struct {
	handler *questionHandler
	sender  *mockAnswerSender
}

// newQuestionHandlerTestSetup creates a standard test setup with IPv4 support.
func newQuestionHandlerTestSetup(localNames []string, localAddr net.IP) *questionHandlerTestSetup {
	return newQuestionHandlerTestSetupWithTypes(localNames, localAddr, nil)
}

// newQuestionHandlerTestSetupWithTypes creates a test setup with specific allowed record types.
func newQuestionHandlerTestSetupWithTypes(
	localNames []string, localAddr net.IP, allowedTypes []dnsmessage.Type,
) *questionHandlerTestSetup {
	log := logging.NewDefaultLoggerFactory().NewLogger("test")
	sender := &mockAnswerSender{}
	ifaces := map[int]netInterface{
		1: {Interface: net.Interface{Index: 1, Flags: net.FlagMulticast | net.FlagUp}, supportsV4: true},
	}

	handler := newQuestionHandler(
		localNames,
		localAddr,
		ifaces,
		true,
		sender,
		log,
		"test",
		&net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353},
		&net.UDPAddr{IP: net.ParseIP("FF02::FB"), Port: 5353},
		allowedTypes,
	)

	return &questionHandlerTestSetup{handler: handler, sender: sender}
}

// newTestMessageContext creates a standard messageContext for testing.
func newTestMessageContext(sourcePort int) *messageContext {
	return &messageContext{
		source:  &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: sourcePort},
		ifIndex: 1,
	}
}

// newTestQuestion creates a DNS question message for testing.
func newTestQuestion(name string, qtype dnsmessage.Type, class dnsmessage.Class) *dnsmessage.Message {
	return &dnsmessage.Message{
		Header: dnsmessage.Header{ID: 1234},
		Questions: []dnsmessage.Question{
			{
				Name:  dnsmessage.MustNewName(name),
				Type:  qtype,
				Class: class,
			},
		},
	}
}

// newQuestionHandlerTestSetupIPv6 creates a test setup for IPv6-only handlers.
func newQuestionHandlerTestSetupIPv6(localNames []string, localAddr net.IP) *questionHandlerTestSetup {
	log := logging.NewDefaultLoggerFactory().NewLogger("test")
	sender := &mockAnswerSender{}
	ifaces := map[int]netInterface{
		1: {Interface: net.Interface{Index: 1, Flags: net.FlagMulticast | net.FlagUp}, supportsV4: false},
	}

	handler := newQuestionHandler(
		localNames,
		localAddr,
		ifaces,
		false, // IPv6 only
		sender,
		log,
		"test",
		&net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353},
		&net.UDPAddr{IP: net.ParseIP("FF02::FB"), Port: 5353},
		nil, // no record type filter
	)

	return &questionHandlerTestSetup{handler: handler, sender: sender}
}

func TestQuestionHandlerMatchingName(t *testing.T) {
	setup := newQuestionHandlerTestSetup([]string{"test.local."}, net.ParseIP("192.168.1.100"))
	msgCtx := newTestMessageContext(5353)
	msg := newTestQuestion("test.local.", dnsmessage.TypeA, dnsmessage.ClassINET)

	setup.handler.handle(msgCtx, msg)

	assert.Len(t, setup.sender.calls, 1)
	assert.Equal(t, uint16(1234), setup.sender.calls[0].queryID)
	assert.Equal(t, netip.MustParseAddr("192.168.1.100"), setup.sender.calls[0].addr)
	assert.False(t, setup.sender.calls[0].isUnicast) // Multicast response (port 5353, no QU bit)
}

func TestQuestionHandlerNonMatchingName(t *testing.T) {
	setup := newQuestionHandlerTestSetup([]string{"test.local."}, net.ParseIP("192.168.1.100"))
	msgCtx := newTestMessageContext(5353)
	msg := newTestQuestion("other.local.", dnsmessage.TypeA, dnsmessage.ClassINET)

	setup.handler.handle(msgCtx, msg)

	assert.Empty(t, setup.sender.calls, "should not send answer for non-matching name")
}

func TestQuestionHandlerCaseInsensitive(t *testing.T) {
	setup := newQuestionHandlerTestSetup([]string{"TEST.LOCAL."}, net.ParseIP("192.168.1.100"))
	msgCtx := newTestMessageContext(5353)
	msg := newTestQuestion("test.local.", dnsmessage.TypeA, dnsmessage.ClassINET)

	setup.handler.handle(msgCtx, msg)

	assert.Len(t, setup.sender.calls, 1, "should match case-insensitively")
}

func TestQuestionHandlerSkipsNonAddressTypesWhenFiltered(t *testing.T) {
	// With legacy allowedRecordTypes filter (A/AAAA only), PTR should be skipped.
	setup := newQuestionHandlerTestSetupWithTypes(
		[]string{"test.local."}, net.ParseIP("192.168.1.100"),
		[]dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA},
	)
	msgCtx := newTestMessageContext(5353)
	msg := newTestQuestion("test.local.", dnsmessage.TypePTR, dnsmessage.ClassINET)

	setup.handler.handle(msgCtx, msg)

	assert.Empty(t, setup.sender.calls, "should not respond to PTR questions when filtered")
	assert.Empty(t, setup.sender.serviceCalls, "should not respond to PTR questions when filtered")
}

func TestQuestionHandlerUnicastResponseBit(t *testing.T) {
	setup := newQuestionHandlerTestSetup([]string{"test.local."}, net.ParseIP("192.168.1.100"))
	msgCtx := newTestMessageContext(5353)
	// Set the unicast-response (QU) bit (bit 15 of class)
	msg := newTestQuestion("test.local.", dnsmessage.TypeA, dnsmessage.ClassINET|(1<<15))

	setup.handler.handle(msgCtx, msg)

	assert.Len(t, setup.sender.calls, 1)
	assert.True(t, setup.sender.calls[0].isUnicast, "should reply unicast when QU bit is set")
	assert.Equal(t, msgCtx.source, setup.sender.calls[0].dst, "unicast reply should go to source")
}

func TestQuestionHandlerLegacyQuery(t *testing.T) {
	setup := newQuestionHandlerTestSetup([]string{"test.local."}, net.ParseIP("192.168.1.100"))
	// Legacy query: source port is not 5353
	msgCtx := newTestMessageContext(12345)
	msg := newTestQuestion("test.local.", dnsmessage.TypeA, dnsmessage.ClassINET)

	setup.handler.handle(msgCtx, msg)

	assert.Len(t, setup.sender.calls, 1)
	assert.True(t, setup.sender.calls[0].isUnicast, "should reply unicast for legacy query")
	assert.Equal(t, msgCtx.source, setup.sender.calls[0].dst, "unicast reply should go to source")
}

func TestQuestionHandlerMultipleQuestions(t *testing.T) {
	setup := newQuestionHandlerTestSetup([]string{"test1.local.", "test2.local."}, net.ParseIP("192.168.1.100"))
	msgCtx := newTestMessageContext(5353)

	msg := &dnsmessage.Message{
		Header: dnsmessage.Header{ID: 1234},
		Questions: []dnsmessage.Question{
			{Name: dnsmessage.MustNewName("test1.local."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
			{Name: dnsmessage.MustNewName("test2.local."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
			{Name: dnsmessage.MustNewName("other.local."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
		},
	}

	setup.handler.handle(msgCtx, msg)

	// Should respond to test1.local and test2.local but not other.local
	assert.Len(t, setup.sender.calls, 2)
}

func TestQuestionHandlerAddressTypeMismatch(t *testing.T) {
	// Configure IPv6 local address but receive IPv4 (A) query
	setup := newQuestionHandlerTestSetup([]string{"test.local."}, net.ParseIP("::1"))
	msgCtx := newTestMessageContext(5353)
	msg := newTestQuestion("test.local.", dnsmessage.TypeA, dnsmessage.ClassINET)

	setup.handler.handle(msgCtx, msg)

	// Should not send answer - IPv6 address can't answer A query
	assert.Empty(t, setup.sender.calls, "should not answer A query with IPv6 address")
}

func TestQuestionHandlerIPv6Query(t *testing.T) {
	// Configure global IPv6 address
	setup := newQuestionHandlerTestSetupIPv6([]string{"test.local."}, net.ParseIP("2001:db8::1"))
	msgCtx := &messageContext{
		source:  &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 5353},
		ifIndex: 1,
	}
	msg := newTestQuestion("test.local.", dnsmessage.TypeAAAA, dnsmessage.ClassINET)

	setup.handler.handle(msgCtx, msg)

	assert.Len(t, setup.sender.calls, 1)
	assert.Equal(t, netip.MustParseAddr("2001:db8::1"), setup.sender.calls[0].addr)
}

// ---------------------------------------------------------------------------
// DNS-SD: WithService option
// ---------------------------------------------------------------------------

func TestWithServiceValid(t *testing.T) {
	cfg := &serverConfig{}
	opt := WithService(ServiceInstance{
		Instance: "My Web",
		Service:  "_http._tcp",
		Port:     8080,
	})
	err := opt.applyServer(cfg)

	assert.NoError(t, err)
	assert.Len(t, cfg.services, 1)
	assert.Equal(t, "My Web", cfg.services[0].Instance)
	assert.Equal(t, "local", cfg.services[0].Domain, "should default domain to local")
}

func TestWithServiceExplicitDomain(t *testing.T) {
	cfg := &serverConfig{}
	opt := WithService(ServiceInstance{
		Instance: "My Web",
		Service:  "_http._tcp",
		Domain:   "example.com",
		Port:     8080,
	})
	err := opt.applyServer(cfg)

	assert.NoError(t, err)
	assert.Equal(t, "example.com", cfg.services[0].Domain)
}

func TestWithServiceInvalidInstance(t *testing.T) {
	cfg := &serverConfig{}
	opt := WithService(ServiceInstance{
		Instance: "", // empty
		Service:  "_http._tcp",
		Port:     8080,
	})
	err := opt.applyServer(cfg)

	assert.ErrorIs(t, err, errInstanceNameEmpty)
	assert.Empty(t, cfg.services)
}

func TestWithServiceInvalidServiceName(t *testing.T) {
	cfg := &serverConfig{}
	opt := WithService(ServiceInstance{
		Instance: "My Web",
		Service:  "http._tcp", // missing underscore
		Port:     8080,
	})
	err := opt.applyServer(cfg)

	assert.ErrorIs(t, err, errInvalidServiceName)
	assert.Empty(t, cfg.services)
}

func TestWithServiceMultiple(t *testing.T) {
	cfg := &serverConfig{}

	err := WithService(ServiceInstance{
		Instance: "Web Server",
		Service:  "_http._tcp",
		Port:     80,
	}).applyServer(cfg)
	assert.NoError(t, err)

	err = WithService(ServiceInstance{
		Instance: "Printer",
		Service:  "_ipp._tcp",
		Port:     631,
	}).applyServer(cfg)
	assert.NoError(t, err)

	assert.Len(t, cfg.services, 2)
}

// ---------------------------------------------------------------------------
// DNS-SD: PTR question handling
// ---------------------------------------------------------------------------

func TestPTRQuestionMatchesService(t *testing.T) {
	setup := newQuestionHandlerTestSetup([]string{"myhost.local."}, net.ParseIP("192.168.1.100"))
	setup.sender.services = []ServiceInstance{
		{Instance: "My Web", Service: "_http._tcp", Domain: "local", Host: "myhost.local.", Port: 8080},
	}
	msgCtx := newTestMessageContext(5353)
	msg := newTestQuestion("_http._tcp.local.", dnsmessage.TypePTR, dnsmessage.ClassINET)

	setup.handler.handle(msgCtx, msg)

	assert.Len(t, setup.sender.serviceCalls, 1)
	assert.Equal(t, "My Web", setup.sender.serviceCalls[0].svc.Instance)
	assert.Equal(t, dnsmessage.TypePTR, setup.sender.serviceCalls[0].question.Type)
}

func TestPTRQuestionCaseInsensitive(t *testing.T) {
	setup := newQuestionHandlerTestSetup([]string{"myhost.local."}, net.ParseIP("192.168.1.100"))
	setup.sender.services = []ServiceInstance{
		{Instance: "My Web", Service: "_http._tcp", Domain: "local", Host: "myhost.local.", Port: 8080},
	}
	msgCtx := newTestMessageContext(5353)
	msg := newTestQuestion("_HTTP._TCP.local.", dnsmessage.TypePTR, dnsmessage.ClassINET)

	setup.handler.handle(msgCtx, msg)

	assert.Len(t, setup.sender.serviceCalls, 1)
}

func TestPTRQuestionNoMatch(t *testing.T) {
	setup := newQuestionHandlerTestSetup([]string{"myhost.local."}, net.ParseIP("192.168.1.100"))
	setup.sender.services = []ServiceInstance{
		{Instance: "My Web", Service: "_http._tcp", Domain: "local", Host: "myhost.local.", Port: 8080},
	}
	msgCtx := newTestMessageContext(5353)
	msg := newTestQuestion("_ipp._tcp.local.", dnsmessage.TypePTR, dnsmessage.ClassINET)

	setup.handler.handle(msgCtx, msg)

	assert.Empty(t, setup.sender.serviceCalls)
}

func TestPTRQuestionMultipleServices(t *testing.T) {
	setup := newQuestionHandlerTestSetup([]string{"myhost.local."}, net.ParseIP("192.168.1.100"))
	setup.sender.services = []ServiceInstance{
		{Instance: "Web 1", Service: "_http._tcp", Domain: "local", Host: "myhost.local.", Port: 80},
		{Instance: "Web 2", Service: "_http._tcp", Domain: "local", Host: "myhost.local.", Port: 8080},
		{Instance: "Printer", Service: "_ipp._tcp", Domain: "local", Host: "myhost.local.", Port: 631},
	}
	msgCtx := newTestMessageContext(5353)
	msg := newTestQuestion("_http._tcp.local.", dnsmessage.TypePTR, dnsmessage.ClassINET)

	setup.handler.handle(msgCtx, msg)

	// Should match Web 1 and Web 2, but not Printer.
	assert.Len(t, setup.sender.serviceCalls, 2)
}

// ---------------------------------------------------------------------------
// DNS-SD: SRV question handling
// ---------------------------------------------------------------------------

func TestSRVQuestionMatchesServiceInstance(t *testing.T) {
	setup := newQuestionHandlerTestSetup([]string{"myhost.local."}, net.ParseIP("192.168.1.100"))
	setup.sender.services = []ServiceInstance{
		{Instance: "My Web", Service: "_http._tcp", Domain: "local", Host: "myhost.local.", Port: 8080},
	}
	msgCtx := newTestMessageContext(5353)
	msg := newTestQuestion("My Web._http._tcp.local.", dnsmessage.TypeSRV, dnsmessage.ClassINET)

	setup.handler.handle(msgCtx, msg)

	assert.Len(t, setup.sender.serviceCalls, 1)
	assert.Equal(t, dnsmessage.TypeSRV, setup.sender.serviceCalls[0].question.Type)
}

func TestSRVQuestionNoMatch(t *testing.T) {
	setup := newQuestionHandlerTestSetup([]string{"myhost.local."}, net.ParseIP("192.168.1.100"))
	setup.sender.services = []ServiceInstance{
		{Instance: "My Web", Service: "_http._tcp", Domain: "local", Host: "myhost.local.", Port: 8080},
	}
	msgCtx := newTestMessageContext(5353)
	msg := newTestQuestion("Other._http._tcp.local.", dnsmessage.TypeSRV, dnsmessage.ClassINET)

	setup.handler.handle(msgCtx, msg)

	assert.Empty(t, setup.sender.serviceCalls)
}

// ---------------------------------------------------------------------------
// DNS-SD: TXT question handling
// ---------------------------------------------------------------------------

func TestTXTQuestionMatchesServiceInstance(t *testing.T) {
	setup := newQuestionHandlerTestSetup([]string{"myhost.local."}, net.ParseIP("192.168.1.100"))
	setup.sender.services = []ServiceInstance{
		{Instance: "My Web", Service: "_http._tcp", Domain: "local", Host: "myhost.local.", Port: 8080},
	}
	msgCtx := newTestMessageContext(5353)
	msg := newTestQuestion("My Web._http._tcp.local.", dnsmessage.TypeTXT, dnsmessage.ClassINET)

	setup.handler.handle(msgCtx, msg)

	assert.Len(t, setup.sender.serviceCalls, 1)
	assert.Equal(t, dnsmessage.TypeTXT, setup.sender.serviceCalls[0].question.Type)
}

// ---------------------------------------------------------------------------
// DNS-SD: allowedRecordTypes filter
// ---------------------------------------------------------------------------

func TestAllowedRecordTypesFilterBlocksPTR(t *testing.T) {
	// Legacy behavior: only A/AAAA allowed
	setup := newQuestionHandlerTestSetupWithTypes(
		[]string{"myhost.local."}, net.ParseIP("192.168.1.100"),
		[]dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA},
	)
	setup.sender.services = []ServiceInstance{
		{Instance: "Web", Service: "_http._tcp", Domain: "local", Host: "myhost.local.", Port: 80},
	}
	msgCtx := newTestMessageContext(5353)
	msg := newTestQuestion("_http._tcp.local.", dnsmessage.TypePTR, dnsmessage.ClassINET)

	setup.handler.handle(msgCtx, msg)

	assert.Empty(t, setup.sender.serviceCalls, "PTR should be blocked by record type filter")
}

func TestAllowedRecordTypesFilterAllowsPTR(t *testing.T) {
	// Explicit allowlist including PTR
	setup := newQuestionHandlerTestSetupWithTypes(
		[]string{"myhost.local."}, net.ParseIP("192.168.1.100"),
		[]dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA, dnsmessage.TypePTR},
	)
	setup.sender.services = []ServiceInstance{
		{Instance: "Web", Service: "_http._tcp", Domain: "local", Host: "myhost.local.", Port: 80},
	}
	msgCtx := newTestMessageContext(5353)
	msg := newTestQuestion("_http._tcp.local.", dnsmessage.TypePTR, dnsmessage.ClassINET)

	setup.handler.handle(msgCtx, msg)

	assert.Len(t, setup.sender.serviceCalls, 1)
}

func TestAllowedRecordTypesNilAllowsAll(t *testing.T) {
	// nil allowedRecordTypes means no filter (all types allowed)
	setup := newQuestionHandlerTestSetupWithTypes(
		[]string{"myhost.local."}, net.ParseIP("192.168.1.100"),
		nil,
	)
	setup.sender.services = []ServiceInstance{
		{Instance: "Web", Service: "_http._tcp", Domain: "local", Host: "myhost.local.", Port: 80},
	}
	msgCtx := newTestMessageContext(5353)
	msg := newTestQuestion("_http._tcp.local.", dnsmessage.TypePTR, dnsmessage.ClassINET)

	setup.handler.handle(msgCtx, msg)

	assert.Len(t, setup.sender.serviceCalls, 1)
}

// ---------------------------------------------------------------------------
// DNS-SD: server registerService / unregisterService
// ---------------------------------------------------------------------------

func TestServerRegisterUnregister(t *testing.T) {
	srv := &server{}
	svc := ServiceInstance{
		Instance: "Test",
		Service:  "_http._tcp",
		Domain:   "local",
		Host:     "test.local.",
		Port:     80,
	}

	srv.registerService(svc)
	assert.Len(t, srv.getServices(), 1)
	assert.Equal(t, "Test", srv.getServices()[0].Instance)

	srv.unregisterService("Test", "_http._tcp")
	assert.Empty(t, srv.getServices())
}

func TestServerUnregisterNonExistent(t *testing.T) {
	srv := &server{}
	svc := ServiceInstance{
		Instance: "Test",
		Service:  "_http._tcp",
		Domain:   "local",
		Host:     "test.local.",
		Port:     80,
	}
	srv.registerService(svc)

	// Unregister something that doesn't exist.
	srv.unregisterService("Other", "_http._tcp")
	assert.Len(t, srv.getServices(), 1, "should not remove non-matching service")
}

// ---------------------------------------------------------------------------
// DNS-SD: createServiceAnswer
// ---------------------------------------------------------------------------

func TestCreateServiceAnswerPTR(t *testing.T) {
	srv := &server{ttl: 120}
	svc := &ServiceInstance{
		Instance: "My Web",
		Service:  "_http._tcp",
		Domain:   "local",
		Host:     "myhost.local.",
		Port:     8080,
	}
	question := dnsmessage.Question{
		Name:  dnsmessage.MustNewName("_http._tcp.local."),
		Type:  dnsmessage.TypePTR,
		Class: dnsmessage.ClassINET,
	}
	addr := netip.MustParseAddr("192.168.1.100")

	msg, err := srv.createServiceAnswer(1234, question, svc, addr, false)
	assert.NoError(t, err)
	assert.True(t, msg.Header.Response)
	assert.True(t, msg.Header.Authoritative)
	assert.Len(t, msg.Answers, 1)
	assert.Equal(t, dnsmessage.TypePTR, msg.Answers[0].Header.Type)
	// Additional should have SRV + TXT + A
	assert.Len(t, msg.Additionals, 3)
	assert.Equal(t, dnsmessage.TypeSRV, msg.Additionals[0].Header.Type)
	assert.Equal(t, dnsmessage.TypeTXT, msg.Additionals[1].Header.Type)
	assert.Equal(t, dnsmessage.TypeA, msg.Additionals[2].Header.Type)
}

func TestCreateServiceAnswerSRV(t *testing.T) {
	srv := &server{ttl: 120}
	svc := &ServiceInstance{
		Instance: "My Web",
		Service:  "_http._tcp",
		Domain:   "local",
		Host:     "myhost.local.",
		Port:     8080,
	}
	question := dnsmessage.Question{
		Name:  dnsmessage.MustNewName("My Web._http._tcp.local."),
		Type:  dnsmessage.TypeSRV,
		Class: dnsmessage.ClassINET,
	}
	addr := netip.MustParseAddr("192.168.1.100")

	msg, err := srv.createServiceAnswer(1234, question, svc, addr, false)
	assert.NoError(t, err)
	assert.Len(t, msg.Answers, 1)
	assert.Equal(t, dnsmessage.TypeSRV, msg.Answers[0].Header.Type)
	// Additional: A record for host
	assert.Len(t, msg.Additionals, 1)
	assert.Equal(t, dnsmessage.TypeA, msg.Additionals[0].Header.Type)
}

func TestCreateServiceAnswerTXT(t *testing.T) {
	srv := &server{ttl: 120}
	svc := &ServiceInstance{
		Instance: "My Web",
		Service:  "_http._tcp",
		Domain:   "local",
		Host:     "myhost.local.",
		Port:     8080,
	}
	question := dnsmessage.Question{
		Name:  dnsmessage.MustNewName("My Web._http._tcp.local."),
		Type:  dnsmessage.TypeTXT,
		Class: dnsmessage.ClassINET,
	}
	addr := netip.MustParseAddr("192.168.1.100")

	msg, err := srv.createServiceAnswer(1234, question, svc, addr, false)
	assert.NoError(t, err)
	assert.Len(t, msg.Answers, 1)
	assert.Equal(t, dnsmessage.TypeTXT, msg.Answers[0].Header.Type)
	assert.Empty(t, msg.Additionals, "TXT answers should have no additional records")
}

func TestCreateServiceAnswerUnicast(t *testing.T) {
	srv := &server{ttl: 120}
	svc := &ServiceInstance{
		Instance: "My Web",
		Service:  "_http._tcp",
		Domain:   "local",
		Host:     "myhost.local.",
		Port:     8080,
	}
	question := dnsmessage.Question{
		Name:  dnsmessage.MustNewName("_http._tcp.local."),
		Type:  dnsmessage.TypePTR,
		Class: dnsmessage.ClassINET,
	}
	addr := netip.MustParseAddr("192.168.1.100")

	msg, err := srv.createServiceAnswer(1234, question, svc, addr, true)
	assert.NoError(t, err)
	assert.Len(t, msg.Questions, 1, "unicast response should echo the question")
}

func TestCreateServiceAnswerIPv6(t *testing.T) {
	srv := &server{ttl: 120}
	svc := &ServiceInstance{
		Instance: "My Web",
		Service:  "_http._tcp",
		Domain:   "local",
		Host:     "myhost.local.",
		Port:     8080,
	}
	question := dnsmessage.Question{
		Name:  dnsmessage.MustNewName("_http._tcp.local."),
		Type:  dnsmessage.TypePTR,
		Class: dnsmessage.ClassINET,
	}
	addr := netip.MustParseAddr("2001:db8::1")

	msg, err := srv.createServiceAnswer(1234, question, svc, addr, false)
	assert.NoError(t, err)
	// Additional should have SRV + TXT + AAAA
	assert.Len(t, msg.Additionals, 3)
	assert.Equal(t, dnsmessage.TypeAAAA, msg.Additionals[2].Header.Type)
}
