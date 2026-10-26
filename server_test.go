// SPDX-FileCopyrightText: The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package mdns

import (
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestWithRefreshInterval(t *testing.T) {
	cfg := &serverConfig{}

	err := WithRefreshInterval(5 * time.Second).applyServer(cfg)
	assert.NoError(t, err)
	assert.Equal(t, 5*time.Second, cfg.refreshCheckInterval)
}

func TestWithRefreshIntervalNonPositive(t *testing.T) {
	cfg := &serverConfig{}

	err := WithRefreshInterval(0).applyServer(cfg)
	assert.ErrorIs(t, err, errIntervalNonPositive)

	err = WithRefreshInterval(-time.Second).applyServer(cfg)
	assert.ErrorIs(t, err, errIntervalNonPositive)
	assert.Zero(t, cfg.refreshCheckInterval)
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
	calls    []mockAnswerCall
	services []ServiceInstance
}

type mockAnswerCall struct {
	queryID   uint16
	question  dnsmessage.Question
	ifIndex   int
	match     nameMatch
	dst       *net.UDPAddr
	isUnicast bool
}

func (m *mockAnswerSender) sendAnswer(
	queryID uint16, question dnsmessage.Question, ifIndex int,
	match nameMatch, dst *net.UDPAddr, isUnicast bool,
) {
	m.calls = append(m.calls, mockAnswerCall{
		queryID:   queryID,
		question:  question,
		ifIndex:   ifIndex,
		match:     match,
		dst:       dst,
		isUnicast: isUnicast,
	})
}

func (m *mockAnswerSender) getServices() []ServiceInstance {
	return m.services
}

// mockAnswerWriter records raw answer bytes and delivery flags for testing.
type mockAnswerWriter struct {
	writtenAnswers [][]byte
	writes         []mockAnswerWrite
}

type mockAnswerWrite struct {
	ifIndex         int
	hasLoopbackData bool
	hasIPv6Zone     bool
	dst             *net.UDPAddr
}

func (m *mockAnswerWriter) writeAnswer(ifIndex int, b []byte, hasLoopbackData, hasIPv6Zone bool, dst *net.UDPAddr) {
	m.writtenAnswers = append(m.writtenAnswers, b)
	m.writes = append(m.writes, mockAnswerWrite{
		ifIndex:         ifIndex,
		hasLoopbackData: hasLoopbackData,
		hasIPv6Zone:     hasIPv6Zone,
		dst:             dst,
	})
}

// messages unpacks the written answers.
func (m *mockAnswerWriter) messages(t *testing.T) []dnsmessage.Message {
	t.Helper()

	msgs := make([]dnsmessage.Message, len(m.writtenAnswers))
	for i, raw := range m.writtenAnswers {
		require.NoError(t, msgs[i].Unpack(raw))
	}

	return msgs
}

// questionHandlerTestSetup holds common test fixtures for questionHandler tests.
type questionHandlerTestSetup struct {
	handler *questionHandler
	sender  *mockAnswerSender
}

// newTestQuestionHandler creates a questionHandler with the standard test
// logger, name and multicast destinations.
func newTestQuestionHandler(
	localNames []string, localAddr net.IP, ifaces map[int]netInterface, hasIPv4 bool,
	sender answerSender, allowedTypes []dnsmessage.Type,
) *questionHandler {
	return newQuestionHandler(
		localNames,
		localAddr,
		ifaces,
		hasIPv4,
		sender,
		logging.NewDefaultLoggerFactory().NewLogger("test"),
		"test",
		&net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353},
		&net.UDPAddr{IP: net.ParseIP("FF02::FB"), Port: 5353},
		allowedTypes,
	)
}

// testIfaces returns one interface with the given addresses, supporting the
// address families they belong to; without addresses it supports IPv4.
func testIfaces(ipAddrs ...netip.Addr) map[int]netInterface {
	ifc := netInterface{
		Interface:  net.Interface{Index: 1, Flags: net.FlagMulticast | net.FlagUp},
		ipAddrs:    ipAddrs,
		supportsV4: len(ipAddrs) == 0,
	}
	for _, addr := range ipAddrs {
		if addr.Is4() {
			ifc.supportsV4 = true
		} else {
			ifc.supportsV6 = true
		}
	}

	return map[int]netInterface{1: ifc}
}

// newQuestionHandlerTestSetup creates a standard test setup with IPv4 support.
func newQuestionHandlerTestSetup(localNames []string, localAddr net.IP) *questionHandlerTestSetup {
	return newQuestionHandlerTestSetupWithTypes(localNames, localAddr, nil)
}

// newQuestionHandlerTestSetupWithTypes creates a test setup with specific allowed record types.
func newQuestionHandlerTestSetupWithTypes(
	localNames []string, localAddr net.IP, allowedTypes []dnsmessage.Type,
) *questionHandlerTestSetup {
	sender := &mockAnswerSender{}
	handler := newTestQuestionHandler(localNames, localAddr, testIfaces(), true, sender, allowedTypes)

	return &questionHandlerTestSetup{handler: handler, sender: sender}
}

// newQuestionHandlerTestSetupIPv6 creates a test setup for IPv6-only handlers.
func newQuestionHandlerTestSetupIPv6(localNames []string, localAddr net.IP) *questionHandlerTestSetup {
	sender := &mockAnswerSender{}
	ifaces := map[int]netInterface{
		1: {Interface: net.Interface{Index: 1, Flags: net.FlagMulticast | net.FlagUp}, supportsV4: false},
	}
	handler := newTestQuestionHandler(localNames, localAddr, ifaces, false, sender, nil)

	return &questionHandlerTestSetup{handler: handler, sender: sender}
}

// newQuestionHandlerTestSetupIfaces creates a dual-stack test setup whose
// addresses are derived from the interface rather than a configured address.
func newQuestionHandlerTestSetupIfaces(localNames []string, ipAddrs []netip.Addr) *questionHandlerTestSetup {
	sender := &mockAnswerSender{}
	handler := newTestQuestionHandler(localNames, nil, testIfaces(ipAddrs...), true, sender, nil)

	return &questionHandlerTestSetup{handler: handler, sender: sender}
}

// responderTestSetup wires a questionHandler to a real server with a mock
// writer, so a test observes the messages actually written.
type responderTestSetup struct {
	handler *questionHandler
	writer  *mockAnswerWriter
}

func newResponderTestSetup(
	localNames []string, localAddr net.IP, services []ServiceInstance, allowedTypes []dnsmessage.Type,
) *responderTestSetup {
	writer := &mockAnswerWriter{}
	srv := newServer(
		logging.NewDefaultLoggerFactory().NewLogger("test"),
		"test",
		writer,
		localNames,
		localAddr,
		testIfaces(),
		true,
		&net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353},
		&net.UDPAddr{IP: net.ParseIP("FF02::FB"), Port: 5353},
		120,
		services,
		allowedTypes,
	)

	return &responderTestSetup{handler: srv.handler, writer: writer}
}

// newTestMessageContext creates a standard messageContext for testing.
func newTestMessageContext(sourcePort int) *messageContext {
	return &messageContext{
		source:  &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: sourcePort},
		ifIndex: 1,
	}
}

// testQuestion creates a DNS question for testing.
func testQuestion(name string, qtype dnsmessage.Type, class dnsmessage.Class) dnsmessage.Question {
	return dnsmessage.Question{
		Name:  dnsmessage.MustNewName(name),
		Type:  qtype,
		Class: class,
	}
}

// newTestQuestion creates a DNS question message for testing.
func newTestQuestion(name string, qtype dnsmessage.Type, class dnsmessage.Class) *dnsmessage.Message {
	return &dnsmessage.Message{
		Header:    dnsmessage.Header{ID: 1234},
		Questions: []dnsmessage.Question{testQuestion(name, qtype, class)},
	}
}

// hostMatch returns the match of a local host name answering with addrs.
func hostMatch(addrs ...netip.Addr) *nameMatch {
	match := &nameMatch{host: true, addrs: addrs}
	for _, addr := range addrs {
		match.types = append(match.types, addressRecordType(addr))
	}

	return match
}

// browseInstances returns the instance names matched as a browse name.
func browseInstances(match nameMatch) []string {
	var names []string
	for _, browse := range match.browse {
		names = append(names, browse.svc.Instance)
	}

	return names
}

// instanceNames returns the instance names matched as a Service Instance Name.
func instanceNames(match nameMatch) []string {
	var names []string
	for _, svc := range match.instances {
		names = append(names, svc.Instance)
	}

	return names
}

// resourceSummary renders records as "owner type" strings for compact assertions.
func resourceSummary(records []dnsmessage.Resource) []string {
	var out []string
	for _, res := range records {
		out = append(out, res.Header.Name.String()+" "+res.Header.Type.String())
	}

	return out
}

func TestQuestionHandlerMatchingName(t *testing.T) {
	setup := newQuestionHandlerTestSetup([]string{"test.local."}, net.ParseIP("192.168.1.100"))
	msgCtx := newTestMessageContext(5353)
	msg := newTestQuestion("test.local.", dnsmessage.TypeA, dnsmessage.ClassINET)

	setup.handler.handle(msgCtx, msg)

	require.Len(t, setup.sender.calls, 1)
	call := setup.sender.calls[0]
	assert.Equal(t, uint16(1234), call.queryID)
	assert.True(t, call.match.host)
	assert.Equal(t, []dnsmessage.Type{dnsmessage.TypeA}, call.match.types)
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("192.168.1.100")}, call.match.addrs)
	assert.False(t, call.isUnicast) // Multicast response (port 5353, no QU bit)
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
	setup := newResponderTestSetup([]string{"test.local."}, net.ParseIP("::1"), nil, nil)
	msgCtx := newTestMessageContext(5353)
	msg := newTestQuestion("test.local.", dnsmessage.TypeA, dnsmessage.ClassINET)

	setup.handler.handle(msgCtx, msg)

	// Should not send answer - IPv6 address can't answer A query
	assert.Empty(t, setup.writer.writtenAnswers, "should not answer A query with IPv6 address")
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

	require.Len(t, setup.sender.calls, 1)
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("2001:db8::1")}, setup.sender.calls[0].match.addrs)
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

func TestWithServiceValidTXT(t *testing.T) {
	cfg := &serverConfig{}
	opt := WithService(ServiceInstance{
		Instance: "My Web",
		Service:  "_http._tcp",
		Port:     8080,
		Text: []TXTEntry{
			NewTXTString("version", "1.2.3"),
			NewTXTFlag("secure"),
		},
	})
	err := opt.applyServer(cfg)

	assert.NoError(t, err)
	require.Len(t, cfg.services, 1)
	assert.Len(t, cfg.services[0].Text, 2)
}

func TestWithServiceInvalidTXT(t *testing.T) {
	tests := []struct {
		name    string
		text    []TXTEntry
		wantErr error
	}{
		{"key with equals", []TXTEntry{{Key: "a=b", Value: []byte("v")}}, errTXTKeyHasEquals},
		{"empty key", []TXTEntry{NewTXTString("", "v")}, errTXTKeyEmpty},
		{"non-ascii key", []TXTEntry{NewTXTString("naïve", "v")}, errTXTKeyNotASCII},
		{"duplicate key", []TXTEntry{NewTXTString("k", "1"), NewTXTString("K", "2")}, errTXTDuplicateKey},
		{"too long", []TXTEntry{NewTXTString("k", strings.Repeat("x", 254))}, errTXTStringTooLong},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &serverConfig{}
			opt := WithService(ServiceInstance{
				Instance: "My Web",
				Service:  "_http._tcp",
				Port:     8080,
				Text:     tt.text,
			})
			err := opt.applyServer(cfg)

			assert.ErrorIs(t, err, tt.wantErr)
			assert.Empty(t, cfg.services, "invalid service should not be registered")
		})
	}
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

	require.Len(t, setup.sender.calls, 1)
	call := setup.sender.calls[0]
	assert.Equal(t, dnsmessage.TypePTR, call.question.Type)
	assert.Equal(t, []dnsmessage.Type{dnsmessage.TypePTR}, call.match.types)
	assert.Equal(t, []string{"My Web"}, browseInstances(call.match))
	assert.Equal(t, "_http._tcp.local.", call.match.browse[0].ptrName)
	assert.False(t, call.match.host)
	assert.Empty(t, call.match.instances)
}

func TestPTRQuestionCaseInsensitive(t *testing.T) {
	setup := newQuestionHandlerTestSetup([]string{"myhost.local."}, net.ParseIP("192.168.1.100"))
	setup.sender.services = []ServiceInstance{
		{Instance: "My Web", Service: "_http._tcp", Domain: "local", Host: "myhost.local.", Port: 8080},
	}
	msgCtx := newTestMessageContext(5353)
	msg := newTestQuestion("_HTTP._TCP.local.", dnsmessage.TypePTR, dnsmessage.ClassINET)

	setup.handler.handle(msgCtx, msg)

	require.Len(t, setup.sender.calls, 1)
	assert.Equal(t, []string{"My Web"}, browseInstances(setup.sender.calls[0].match))
}

func TestPTRQuestionNoMatch(t *testing.T) {
	setup := newQuestionHandlerTestSetup([]string{"myhost.local."}, net.ParseIP("192.168.1.100"))
	setup.sender.services = []ServiceInstance{
		{Instance: "My Web", Service: "_http._tcp", Domain: "local", Host: "myhost.local.", Port: 8080},
	}
	msgCtx := newTestMessageContext(5353)
	msg := newTestQuestion("_ipp._tcp.local.", dnsmessage.TypePTR, dnsmessage.ClassINET)

	setup.handler.handle(msgCtx, msg)

	assert.Empty(t, setup.sender.calls)
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

	// Web 1 and Web 2 match, but not Printer; both go in one response
	// (RFC 6762 §6.4).
	require.Len(t, setup.sender.calls, 1, "one response per question")
	assert.Equal(t, []string{"Web 1", "Web 2"}, browseInstances(setup.sender.calls[0].match))
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

	require.Len(t, setup.sender.calls, 1)
	call := setup.sender.calls[0]
	assert.Equal(t, dnsmessage.TypeSRV, call.question.Type)
	assert.Equal(t, []dnsmessage.Type{dnsmessage.TypeSRV}, call.match.types)
	assert.Equal(t, []string{"My Web"}, instanceNames(call.match))
	assert.Empty(t, call.match.browse)
}

func TestSRVQuestionNoMatch(t *testing.T) {
	setup := newQuestionHandlerTestSetup([]string{"myhost.local."}, net.ParseIP("192.168.1.100"))
	setup.sender.services = []ServiceInstance{
		{Instance: "My Web", Service: "_http._tcp", Domain: "local", Host: "myhost.local.", Port: 8080},
	}
	msgCtx := newTestMessageContext(5353)
	msg := newTestQuestion("Other._http._tcp.local.", dnsmessage.TypeSRV, dnsmessage.ClassINET)

	setup.handler.handle(msgCtx, msg)

	assert.Empty(t, setup.sender.calls)
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

	require.Len(t, setup.sender.calls, 1)
	call := setup.sender.calls[0]
	assert.Equal(t, dnsmessage.TypeTXT, call.question.Type)
	assert.Equal(t, []dnsmessage.Type{dnsmessage.TypeTXT}, call.match.types)
	assert.Equal(t, []string{"My Web"}, instanceNames(call.match))
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

	assert.Empty(t, setup.sender.calls, "PTR should be blocked by record type filter")
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

	assert.Len(t, setup.sender.calls, 1)
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

	assert.Len(t, setup.sender.calls, 1)
}

func TestAnswerTypes(t *testing.T) {
	legacy := []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA}

	tests := []struct {
		name    string
		allowed []dnsmessage.Type
		qtype   dnsmessage.Type
		want    []dnsmessage.Type
	}{
		{name: "typed question answers its own type", qtype: dnsmessage.TypePTR, want: []dnsmessage.Type{dnsmessage.TypePTR}},
		{name: "unserved type", qtype: dnsmessage.TypeNS},
		{name: "ANY expands to every served type", qtype: dnsmessage.TypeALL, want: anyAllTypes()},
		{name: "filter blocks a typed question", allowed: legacy, qtype: dnsmessage.TypePTR},
		{name: "filter passes a typed question", allowed: legacy, qtype: dnsmessage.TypeAAAA, want: []dnsmessage.Type{dnsmessage.TypeAAAA}},
		{name: "filter narrows ANY", allowed: legacy, qtype: dnsmessage.TypeALL, want: legacy},
		{name: "listing ANY itself allows nothing", allowed: []dnsmessage.Type{dnsmessage.TypeALL}, qtype: dnsmessage.TypeALL},
		{
			name: "ANY keeps the served order", allowed: []dnsmessage.Type{dnsmessage.TypeTXT, dnsmessage.TypeA},
			qtype: dnsmessage.TypeALL, want: []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeTXT},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setup := newQuestionHandlerTestSetupWithTypes(nil, nil, tc.allowed)

			assert.Equal(t, tc.want, setup.handler.answerTypes(tc.qtype))
		})
	}
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

func TestServerUpdateTXT(t *testing.T) {
	writer := &mockAnswerWriter{}
	srv := &server{ttl: 120, writer: writer}
	srv.registerService(ServiceInstance{
		Instance: "Test",
		Service:  "_http._tcp",
		Domain:   "local",
		Host:     "test.local.",
		Port:     80,
		Text:     []TXTEntry{NewTXTString("version", "1")},
	})

	generation, err := srv.updateTXT("Test", "_http._tcp", []TXTEntry{NewTXTString("version", "2")})
	require.NoError(t, err)
	assert.NotZero(t, generation)
	require.Len(t, srv.getServices(), 1)
	assert.Equal(t, []TXTEntry{NewTXTString("version", "2")}, srv.getServices()[0].Text)

	require.Len(t, writer.writtenAnswers, 1)
	var msg dnsmessage.Message
	require.NoError(t, msg.Unpack(writer.writtenAnswers[0]))
	require.Len(t, msg.Answers, 1)
	assert.True(t, msg.Header.Response)
	assert.True(t, msg.Header.Authoritative)
	assert.Equal(t, dnsmessage.TypeTXT, msg.Answers[0].Header.Type)
	assert.NotZero(t, msg.Answers[0].Header.Class&rrClassCacheFlush)

	txts, err := parseTXTData(msg.Answers[0].Body)
	require.NoError(t, err)
	assert.Equal(t, []string{"version=2"}, txts)

	unchangedGeneration, err := srv.updateTXT("Test", "_http._tcp", []TXTEntry{NewTXTString("version", "2")})
	require.NoError(t, err)
	assert.Zero(t, unchangedGeneration)
	assert.Len(t, writer.writtenAnswers, 1)

	require.NoError(t, srv.repeatTXTAnnouncement("Test", "_http._tcp", generation))
	assert.Len(t, writer.writtenAnswers, 2)
}

func TestServerUpdateTXTServiceNotFound(t *testing.T) {
	srv := &server{writer: &mockAnswerWriter{}}

	_, err := srv.updateTXT("Missing", "_http._tcp", nil)
	assert.ErrorIs(t, err, errServiceNotFound)
}

func TestServerUpdateTXTSupersedesRepeatedAnnouncement(t *testing.T) {
	writer := &mockAnswerWriter{}
	srv := &server{ttl: 120, writer: writer}
	srv.registerService(ServiceInstance{
		Instance: "Test",
		Service:  "_http._tcp",
		Domain:   "local",
	})

	first, err := srv.updateTXT("Test", "_http._tcp", []TXTEntry{NewTXTString("version", "1")})
	require.NoError(t, err)
	second, err := srv.updateTXT("Test", "_http._tcp", []TXTEntry{NewTXTString("version", "2")})
	require.NoError(t, err)
	require.NoError(t, srv.repeatTXTAnnouncement("Test", "_http._tcp", first))
	require.NoError(t, srv.repeatTXTAnnouncement("Test", "_http._tcp", second))

	assert.Len(t, writer.writtenAnswers, 3)
}

func TestServerUnregisterCancelsTXTRepeat(t *testing.T) {
	writer := &mockAnswerWriter{}
	srv := &server{ttl: 120, writer: writer}
	srv.registerService(ServiceInstance{
		Instance: "Test",
		Service:  "_http._tcp",
		Domain:   "local",
	})

	generation, err := srv.updateTXT("Test", "_http._tcp", []TXTEntry{NewTXTString("version", "1")})
	require.NoError(t, err)
	srv.unregisterService("Test", "_http._tcp")
	srv.registerService(ServiceInstance{
		Instance: "Test",
		Service:  "_http._tcp",
		Domain:   "local",
		Text:     []TXTEntry{NewTXTString("version", "2")},
	})

	require.NoError(t, srv.repeatTXTAnnouncement("Test", "_http._tcp", generation))
	assert.Len(t, writer.writtenAnswers, 1)
}

// ---------------------------------------------------------------------------
// DNS-SD: createAnswer for service records
// ---------------------------------------------------------------------------

func TestCreateAnswerService(t *testing.T) {
	svc := &ServiceInstance{
		Instance: "My Web",
		Service:  "_http._tcp",
		Domain:   "local",
		Host:     "myhost.local.",
		Port:     8080,
	}
	const instanceName = "My Web._http._tcp.local."
	addr4 := netip.MustParseAddr("192.168.1.100")
	addr6 := netip.MustParseAddr("2001:db8::1")
	browse := []browseMatch{{svc: svc, ptrName: "_http._tcp.local."}}
	instances := []*ServiceInstance{svc}

	tests := []struct {
		name            string
		qname           string
		match           nameMatch
		wantAnswers     []string
		wantAdditionals []string
	}{
		{
			// Additional should have SRV + TXT + A (RFC 6763 §12.1).
			name:            "PTR",
			qname:           "_http._tcp.local.",
			match:           nameMatch{types: []dnsmessage.Type{dnsmessage.TypePTR}, browse: browse, addrs: []netip.Addr{addr4}},
			wantAnswers:     []string{"_http._tcp.local. TypePTR"},
			wantAdditionals: []string{instanceName + " TypeSRV", instanceName + " TypeTXT", "myhost.local. TypeA"},
		},
		{
			name:            "PTR with IPv6",
			qname:           "_http._tcp.local.",
			match:           nameMatch{types: []dnsmessage.Type{dnsmessage.TypePTR}, browse: browse, addrs: []netip.Addr{addr6}},
			wantAnswers:     []string{"_http._tcp.local. TypePTR"},
			wantAdditionals: []string{instanceName + " TypeSRV", instanceName + " TypeTXT", "myhost.local. TypeAAAA"},
		},
		{
			name:        "PTR with both address families",
			qname:       "_http._tcp.local.",
			match:       nameMatch{types: []dnsmessage.Type{dnsmessage.TypePTR}, browse: browse, addrs: []netip.Addr{addr4, addr6}},
			wantAnswers: []string{"_http._tcp.local. TypePTR"},
			wantAdditionals: []string{
				instanceName + " TypeSRV", instanceName + " TypeTXT", "myhost.local. TypeA", "myhost.local. TypeAAAA",
			},
		},
		{
			// Additional: A record for host (RFC 6763 §12.2).
			name:            "SRV",
			qname:           instanceName,
			match:           nameMatch{types: []dnsmessage.Type{dnsmessage.TypeSRV}, instances: instances, addrs: []netip.Addr{addr4}},
			wantAnswers:     []string{instanceName + " TypeSRV"},
			wantAdditionals: []string{"myhost.local. TypeA"},
		},
		{
			// TXT answers should have no additional records (RFC 6763 §12.3).
			name:        "TXT",
			qname:       instanceName,
			match:       nameMatch{types: []dnsmessage.Type{dnsmessage.TypeTXT}, instances: instances, addrs: []netip.Addr{addr4}},
			wantAnswers: []string{instanceName + " TypeTXT"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := &server{ttl: 120}
			question := testQuestion(tc.qname, tc.match.types[0], dnsmessage.ClassINET)

			msg, _, err := srv.createAnswer(1234, question, &tc.match, false)
			require.NoError(t, err)

			assert.True(t, msg.Header.Response)
			assert.True(t, msg.Header.Authoritative)
			assert.Empty(t, msg.Questions, "multicast response does not echo the question")
			assert.Equal(t, tc.wantAnswers, resourceSummary(msg.Answers))
			assert.Equal(t, tc.wantAdditionals, resourceSummary(msg.Additionals))
		})
	}
}

func TestCreateAnswerTXTWithEntries(t *testing.T) {
	srv := &server{ttl: 120}
	svc := &ServiceInstance{
		Instance: "My Web",
		Service:  "_http._tcp",
		Domain:   "local",
		Host:     "myhost.local.",
		Port:     8080,
		Text: []TXTEntry{
			NewTXTString("version", "1.2.3"),
			NewTXTString("setup", ""),
			NewTXTFlag("secure"),
		},
	}
	question := testQuestion("My Web._http._tcp.local.", dnsmessage.TypeTXT, dnsmessage.ClassINET)
	match := &nameMatch{types: []dnsmessage.Type{dnsmessage.TypeTXT}, instances: []*ServiceInstance{svc}}

	msg, _, err := srv.createAnswer(1234, question, match, false)
	require.NoError(t, err)
	require.Len(t, msg.Answers, 1)
	assert.Equal(t, dnsmessage.TypeTXT, msg.Answers[0].Header.Type)

	txts, err := parseTXTData(msg.Answers[0].Body)
	require.NoError(t, err)
	assert.Equal(t, []string{"version=1.2.3", "setup=", "secure"}, txts)
}

// ---------------------------------------------------------------------------
// DNS-SD: subtype PTR question handling (RFC 6763 §7.1)
// ---------------------------------------------------------------------------

// rfc6763SubtypeServices returns the two instances from the RFC 6763 §7.1
// example: "A web page" is advertised only via "_http._tcp", while
// "A printer's web page" is additionally advertised via the "_printer"
// subtype.
func rfc6763SubtypeServices() []ServiceInstance {
	return []ServiceInstance{
		{Instance: "A web page", Service: "_http._tcp", Domain: "local", Host: "myhost.local.", Port: 100},
		{
			Instance: "A printer's web page", Service: "_http._tcp", Domain: "local",
			Host: "myhost.local.", Port: 101, Subtypes: []string{"_printer"},
		},
	}
}

func TestPTRQuestionSubtype(t *testing.T) {
	tests := []struct {
		name          string
		qname         string
		wantInstances []string
	}{
		{"plain browse returns both", "_http._tcp.local.", []string{"A web page", "A printer's web page"}},
		{"subtype browse returns only printer", "_printer._sub._http._tcp.local.", []string{"A printer's web page"}},
		{"subtype match is case-insensitive", "_PRINTER._SUB._HTTP._TCP.local.", []string{"A printer's web page"}},
		{"unknown subtype", "_scanner._sub._http._tcp.local.", nil},
		{"subtype of other service type", "_printer._sub._ipp._tcp.local.", nil},
		{"subtype without _sub label", "_printer._http._tcp.local.", nil},
		{"bare _sub label", "_sub._http._tcp.local.", nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setup := newQuestionHandlerTestSetup([]string{"myhost.local."}, net.ParseIP("192.168.1.100"))
			setup.sender.services = rfc6763SubtypeServices()
			msgCtx := newTestMessageContext(5353)
			msg := newTestQuestion(tc.qname, dnsmessage.TypePTR, dnsmessage.ClassINET)

			setup.handler.handle(msgCtx, msg)

			var got []string
			for _, call := range setup.sender.calls {
				assert.Equal(t, dnsmessage.TypePTR, call.question.Type)
				got = append(got, browseInstances(call.match)...)
			}
			assert.Equal(t, tc.wantInstances, got)
		})
	}
}

func TestPTRQuestionMultipleSubtypes(t *testing.T) {
	// Matter commissionable node: several subtypes on one instance.
	setup := newQuestionHandlerTestSetup([]string{"myhost.local."}, net.ParseIP("192.168.1.100"))
	setup.sender.services = []ServiceInstance{{
		Instance: "0123456789ABCDEF", Service: "_matterc._udp", Domain: "local",
		Host: "myhost.local.", Port: 5540,
		Subtypes: []string{"_L840", "_S3", "_CM", "_V65521", "_T22"},
	}}

	for _, qname := range []string{
		"_matterc._udp.local.",
		"_L840._sub._matterc._udp.local.",
		"_S3._sub._matterc._udp.local.",
		"_CM._sub._matterc._udp.local.",
		"_V65521._sub._matterc._udp.local.",
		"_T22._sub._matterc._udp.local.",
	} {
		setup.sender.calls = nil
		setup.handler.handle(newTestMessageContext(5353), newTestQuestion(qname, dnsmessage.TypePTR, dnsmessage.ClassINET))
		assert.Len(t, setup.sender.calls, 1, "qname %q", qname)
	}

	setup.sender.calls = nil
	setup.handler.handle(
		newTestMessageContext(5353),
		newTestQuestion("_L841._sub._matterc._udp.local.", dnsmessage.TypePTR, dnsmessage.ClassINET),
	)
	assert.Empty(t, setup.sender.calls)
}

func TestServiceTypeEnumerationExcludesSubtypes(t *testing.T) {
	setup := newResponderTestSetup([]string{"myhost.local."}, net.ParseIP("192.168.1.100"), rfc6763SubtypeServices(), nil)

	setup.handler.handle(
		newTestMessageContext(5353),
		newTestQuestion("_services._dns-sd._udp.local.", dnsmessage.TypePTR, dnsmessage.ClassINET),
	)

	msgs := setup.writer.messages(t)
	require.Len(t, msgs, 1)
	require.Len(t, msgs[0].Answers, 1, "only the base service type is enumerated (RFC 6763 §9)")
	assert.Empty(t, msgs[0].Additionals)

	target, err := parsePTRTarget(msgs[0].Answers[0].Body)
	require.NoError(t, err)
	assert.Equal(t, "_http._tcp.local.", target)
}

func TestSubtypePTRResponse(t *testing.T) {
	setup := newResponderTestSetup([]string{"myhost.local."}, net.ParseIP("192.168.1.100"), rfc6763SubtypeServices(), nil)

	setup.handler.handle(
		newTestMessageContext(5353),
		newTestQuestion("_PRINTER._sub._http._tcp.local.", dnsmessage.TypePTR, dnsmessage.ClassINET),
	)

	msgs := setup.writer.messages(t)
	require.Len(t, msgs, 1)
	msg := msgs[0]

	// The PTR is owned by the subtype browsing name (in the instance's own
	// casing) and points at the unchanged Service Instance Name.
	require.Len(t, msg.Answers, 1)
	assert.Equal(t, "_printer._sub._http._tcp.local.", msg.Answers[0].Header.Name.String())
	assert.Equal(t, dnsmessage.TypePTR, msg.Answers[0].Header.Type)
	target, err := parsePTRTarget(msg.Answers[0].Body)
	require.NoError(t, err)
	assert.Equal(t, "A printer's web page._http._tcp.local.", target)

	// Same SRV + TXT + A additionals as a plain PTR answer (RFC 6763 §12.1).
	assert.Equal(t, []string{
		"A printer's web page._http._tcp.local. TypeSRV",
		"A printer's web page._http._tcp.local. TypeTXT",
		"myhost.local. TypeA",
	}, resourceSummary(msg.Additionals))

	// A plain PTR question keeps the plain owner and answers both instances.
	setup.handler.handle(
		newTestMessageContext(5353),
		newTestQuestion("_http._tcp.local.", dnsmessage.TypePTR, dnsmessage.ClassINET),
	)
	msgs = setup.writer.messages(t)
	require.Len(t, msgs, 2)
	assert.Equal(t, []string{"_http._tcp.local. TypePTR", "_http._tcp.local. TypePTR"}, resourceSummary(msgs[1].Answers))
}

// ---------------------------------------------------------------------------
// DNS-SD: subtype registration via WithService and Register
// ---------------------------------------------------------------------------

func TestWithServiceSubtypes(t *testing.T) {
	cfg := &serverConfig{}
	subtypes := []string{"_printer"}
	err := WithService(ServiceInstance{
		Instance: "A printer's web page",
		Service:  "_http._tcp",
		Port:     101,
		Subtypes: subtypes,
	}).applyServer(cfg)

	require.NoError(t, err)
	require.Len(t, cfg.services, 1)
	assert.Equal(t, []string{"_printer"}, cfg.services[0].Subtypes)

	// The registered copy must be detached from the caller's slice.
	subtypes[0] = "_mutated"
	assert.Equal(t, []string{"_printer"}, cfg.services[0].Subtypes)
}

func TestWithServiceInvalidSubtypes(t *testing.T) {
	tests := []struct {
		name     string
		subtypes []string
		wantErr  error
	}{
		{"empty", []string{""}, errSubtypeEmpty},
		{"too long", []string{strings.Repeat("x", 64)}, errSubtypeTooLong},
		{"contains dot", []string{"_a.b"}, errSubtypeNotLabel},
		{"contains backslash", []string{`_a\b`}, errSubtypeNotLabel},
		{"duplicate", []string{"_printer", "_Printer"}, errSubtypeDuplicate},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &serverConfig{}
			err := WithService(ServiceInstance{
				Instance: "My Web",
				Service:  "_http._tcp",
				Port:     8080,
				Subtypes: tc.subtypes,
			}).applyServer(cfg)

			assert.ErrorIs(t, err, tc.wantErr)
			assert.Empty(t, cfg.services, "invalid service should not be registered")
		})
	}
}

func TestRegisterSubtypes(t *testing.T) {
	conn := &Conn{
		server:     &server{ttl: 120, writer: &mockAnswerWriter{}},
		closed:     make(chan any),
		localNames: []string{"myhost.local."},
	}

	subtypes := []string{"_printer"}
	err := conn.Register(ServiceInstance{
		Instance: "A printer's web page",
		Service:  "_http._tcp",
		Port:     101,
		Subtypes: subtypes,
	})
	require.NoError(t, err)

	services := conn.server.getServices()
	require.Len(t, services, 1)
	assert.Equal(t, []string{"_printer"}, services[0].Subtypes)
	assert.Equal(t, "myhost.local.", services[0].Host)

	subtypes[0] = "_mutated"
	assert.Equal(t, []string{"_printer"}, conn.server.getServices()[0].Subtypes,
		"registered subtypes must be detached from the caller's slice")

	err = conn.Register(ServiceInstance{
		Instance: "Bad",
		Service:  "_http._tcp",
		Port:     1,
		Subtypes: []string{"_a.b"},
	})
	assert.ErrorIs(t, err, errSubtypeNotLabel)
	assert.Len(t, conn.server.getServices(), 1)

	// Subtypes travel with the registration through UpdateTXT and are
	// dropped with Unregister.
	_, err = conn.server.updateTXT("A printer's web page", "_http._tcp", []TXTEntry{NewTXTString("k", "v")})
	require.NoError(t, err)
	assert.Equal(t, []string{"_printer"}, conn.server.getServices()[0].Subtypes)

	conn.Unregister("A printer's web page", "_http._tcp")
	assert.Empty(t, conn.server.getServices())
}

// ---------------------------------------------------------------------------
// qtype ANY question handling (RFC 6762 §6.5)
// ---------------------------------------------------------------------------

// anyTestServices returns the RFC 6763 §7.1 example instances plus a Matter
// commissionable node advertised under several subtypes.
func anyTestServices() []ServiceInstance {
	return append(rfc6763SubtypeServices(), ServiceInstance{
		Instance: "0123456789ABCDEF", Service: "_matterc._udp", Domain: "local",
		Host: "myhost.local.", Port: 5540,
		Text:     []TXTEntry{NewTXTString("D", "840")},
		Subtypes: []string{"_L840", "_S3", "_CM"},
	})
}

func anyAllTypes() []dnsmessage.Type {
	return []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA, dnsmessage.TypePTR, dnsmessage.TypeSRV, dnsmessage.TypeTXT}
}

func TestAnyQuestionMatching(t *testing.T) {
	tests := []struct {
		name          string
		qname         string
		wantHost      bool
		wantPTRNames  []string
		wantInstances []string
	}{
		{name: "host name", qname: "myhost.local.", wantHost: true},
		{name: "host name is case-insensitive", qname: "MYHOST.LOCAL.", wantHost: true},
		{
			name: "plain browse name", qname: "_http._tcp.local.",
			wantPTRNames: []string{"_http._tcp.local.", "_http._tcp.local."},
		},
		{
			name: "plain browse name is case-insensitive", qname: "_HTTP._TCP.local.",
			wantPTRNames: []string{"_http._tcp.local.", "_http._tcp.local."},
		},
		{
			name: "subtype browse name", qname: "_printer._sub._http._tcp.local.",
			wantPTRNames: []string{"_printer._sub._http._tcp.local."},
		},
		{
			name: "subtype browse name keeps instance casing", qname: "_S3._SUB._MATTERC._UDP.LOCAL.",
			wantPTRNames: []string{"_S3._sub._matterc._udp.local."},
		},
		{name: "instance name", qname: "A printer's web page._http._tcp.local.", wantInstances: []string{"A printer's web page"}},
		{name: "instance name is case-insensitive", qname: "0123456789abcdef._matterc._udp.local.", wantInstances: []string{"0123456789ABCDEF"}},
		{name: "unknown host", qname: "other.local."},
		{name: "unknown service type", qname: "_ipp._tcp.local."},
		{name: "unknown subtype", qname: "_scanner._sub._http._tcp.local."},
		{name: "unknown instance", qname: "Nobody._http._tcp.local."},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setup := newQuestionHandlerTestSetup([]string{"myhost.local."}, net.ParseIP("192.168.1.100"))
			setup.sender.services = anyTestServices()

			setup.handler.handle(newTestMessageContext(5353), newTestQuestion(tc.qname, dnsmessage.TypeALL, dnsmessage.ClassINET))

			if !tc.wantHost && tc.wantPTRNames == nil && tc.wantInstances == nil {
				assert.Empty(t, setup.sender.calls, "unknown names get no answer")

				return
			}

			require.Len(t, setup.sender.calls, 1, "one response per question")
			call := setup.sender.calls[0]
			assert.Equal(t, uint16(1234), call.queryID)
			assert.Equal(t, dnsmessage.TypeALL, call.question.Type)
			assert.Equal(t, 1, call.ifIndex)
			assert.False(t, call.isUnicast)
			assert.Equal(t, anyAllTypes(), call.match.types)
			assert.Equal(t, []netip.Addr{netip.MustParseAddr("192.168.1.100")}, call.match.addrs)
			assert.Equal(t, tc.wantHost, call.match.host)
			assert.Empty(t, call.match.serviceTypes)

			var ptrNames []string
			for _, browse := range call.match.browse {
				ptrNames = append(ptrNames, browse.ptrName)
			}
			assert.Equal(t, tc.wantPTRNames, ptrNames)
			assert.Equal(t, tc.wantInstances, instanceNames(call.match))
		})
	}
}

func TestServiceTypeEnumerationQuestion(t *testing.T) {
	for _, qtype := range []dnsmessage.Type{dnsmessage.TypePTR, dnsmessage.TypeALL} {
		t.Run(qtype.String(), func(t *testing.T) {
			setup := newResponderTestSetup([]string{"myhost.local."}, net.ParseIP("192.168.1.100"), anyTestServices(), nil)

			setup.handler.handle(
				newTestMessageContext(5353),
				newTestQuestion("_SERVICES._dns-sd._udp.local.", qtype, dnsmessage.ClassINET),
			)

			msgs := setup.writer.messages(t)
			require.Len(t, msgs, 1)
			assert.Empty(t, msgs[0].Questions, "multicast response does not echo the question")
			assert.Empty(t, msgs[0].Additionals)

			var types []string
			for _, answer := range msgs[0].Answers {
				assert.Equal(t, "_services._dns-sd._udp.local.", answer.Header.Name.String())
				assert.Equal(t, dnsmessage.TypePTR, answer.Header.Type)
				assert.Equal(t, browseTTL, answer.Header.TTL)
				target, err := parsePTRTarget(answer.Body)
				require.NoError(t, err)
				types = append(types, target)
			}
			assert.Equal(t, []string{"_http._tcp.local.", "_matterc._udp.local."}, types, "subtypes are never enumerated")
		})
	}
}

func TestAnyQuestionRecordTypeFilter(t *testing.T) {
	legacy := []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA}

	tests := []struct {
		name        string
		allowed     []dnsmessage.Type
		qname       string
		wantAnswers []string // nil: no response at all
	}{
		{name: "no filter answers host name", qname: "myhost.local.", wantAnswers: []string{"myhost.local. TypeA"}},
		{name: "legacy filter answers host name", allowed: legacy, qname: "myhost.local.", wantAnswers: []string{"myhost.local. TypeA"}},
		{name: "legacy filter ignores browse name", allowed: legacy, qname: "_http._tcp.local."},
		{name: "legacy filter ignores subtype browse name", allowed: legacy, qname: "_printer._sub._http._tcp.local."},
		{name: "legacy filter ignores instance name", allowed: legacy, qname: "A web page._http._tcp.local."},
		{name: "legacy filter ignores enumeration name", allowed: legacy, qname: "_services._dns-sd._udp.local."},
		{
			name: "PTR-only filter answers browse name", allowed: []dnsmessage.Type{dnsmessage.TypePTR},
			qname: "_http._tcp.local.", wantAnswers: []string{"_http._tcp.local. TypePTR", "_http._tcp.local. TypePTR"},
		},
		{name: "PTR-only filter ignores host name", allowed: []dnsmessage.Type{dnsmessage.TypePTR}, qname: "myhost.local."},
		{
			name: "TXT-only filter answers instance name", allowed: []dnsmessage.Type{dnsmessage.TypeTXT},
			qname: "A web page._http._tcp.local.", wantAnswers: []string{"A web page._http._tcp.local. TypeTXT"},
		},
		{name: "listing ANY itself allows nothing", allowed: []dnsmessage.Type{dnsmessage.TypeALL}, qname: "myhost.local."},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setup := newResponderTestSetup([]string{"myhost.local."}, net.ParseIP("192.168.1.100"), anyTestServices(), tc.allowed)

			setup.handler.handle(newTestMessageContext(5353), newTestQuestion(tc.qname, dnsmessage.TypeALL, dnsmessage.ClassINET))

			msgs := setup.writer.messages(t)
			if tc.wantAnswers == nil {
				assert.Empty(t, msgs)

				return
			}
			require.Len(t, msgs, 1)
			assert.Equal(t, tc.wantAnswers, resourceSummary(msgs[0].Answers))
		})
	}
}

func TestAnyQuestionUnicast(t *testing.T) {
	tests := []struct {
		name        string
		sourcePort  int
		class       dnsmessage.Class
		wantUnicast bool
	}{
		{name: "multicast", sourcePort: 5353, class: dnsmessage.ClassINET, wantUnicast: false},
		{name: "QU bit", sourcePort: 5353, class: dnsmessage.ClassINET | qClassUnicastResponse, wantUnicast: true},
		{name: "legacy source port", sourcePort: 41234, class: dnsmessage.ClassINET, wantUnicast: true},
		{name: "legacy source port with QU bit", sourcePort: 41234, class: dnsmessage.ClassINET | qClassUnicastResponse, wantUnicast: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setup := newQuestionHandlerTestSetup([]string{"myhost.local."}, net.ParseIP("192.168.1.100"))
			setup.sender.services = anyTestServices()
			msgCtx := newTestMessageContext(tc.sourcePort)

			setup.handler.handle(msgCtx, newTestQuestion("_S3._sub._matterc._udp.local.", dnsmessage.TypeALL, tc.class))

			require.Len(t, setup.sender.calls, 1)
			call := setup.sender.calls[0]
			assert.Equal(t, tc.wantUnicast, call.isUnicast)
			if tc.wantUnicast {
				assert.Equal(t, msgCtx.source, call.dst, "unicast reply goes to the source")
			} else {
				assert.Nil(t, call.dst)
			}
			assert.Equal(t, tc.class, call.question.Class, "the question is passed on unchanged")
		})
	}
}

func TestResolveAddresses(t *testing.T) {
	localNames := []string{"myhost.local."}
	addr4 := netip.MustParseAddr("192.168.1.100")
	global6 := netip.MustParseAddr("2001:db8::1")
	linkLocal6 := netip.MustParseAddr("fe80::1%eth0")
	ifaceSetup := func(addrs ...netip.Addr) func() *questionHandlerTestSetup {
		return func() *questionHandlerTestSetup {
			return newQuestionHandlerTestSetupIfaces(localNames, addrs)
		}
	}

	tests := []struct {
		name      string
		setup     func() *questionHandlerTestSetup
		source    net.IP // querier address; defaults to IPv4
		qtype     dnsmessage.Type
		wantAddrs []netip.Addr
	}{
		{
			name:      "ANY carries IPv4 and global IPv6 from interface",
			setup:     ifaceSetup(addr4, global6),
			qtype:     dnsmessage.TypeALL,
			wantAddrs: []netip.Addr{addr4, global6},
		},
		{
			name:      "ANY carries IPv4 only from interface",
			setup:     ifaceSetup(addr4),
			qtype:     dnsmessage.TypeALL,
			wantAddrs: []netip.Addr{addr4},
		},
		{
			// A zoned link-local address would confine the whole response to
			// IPv6 delivery, so it yields to the IPv4 address.
			name:      "ANY drops link-local IPv6 next to IPv4",
			setup:     ifaceSetup(addr4, linkLocal6),
			qtype:     dnsmessage.TypeALL,
			wantAddrs: []netip.Addr{addr4},
		},
		{
			name: "ANY carries configured IPv4 address",
			setup: func() *questionHandlerTestSetup {
				return newQuestionHandlerTestSetup(localNames, net.ParseIP("192.168.1.100"))
			},
			qtype:     dnsmessage.TypeALL,
			wantAddrs: []netip.Addr{addr4},
		},
		{
			name: "ANY carries configured IPv6 address on IPv6-only responder",
			setup: func() *questionHandlerTestSetup {
				return newQuestionHandlerTestSetupIPv6(localNames, net.ParseIP("2001:db8::1"))
			},
			qtype:     dnsmessage.TypeALL,
			wantAddrs: []netip.Addr{global6},
		},
		{
			name:      "A carries IPv4 only",
			setup:     ifaceSetup(addr4, global6),
			qtype:     dnsmessage.TypeA,
			wantAddrs: []netip.Addr{addr4},
		},
		{
			name:      "AAAA carries global IPv6 only",
			setup:     ifaceSetup(addr4, global6),
			qtype:     dnsmessage.TypeAAAA,
			wantAddrs: []netip.Addr{global6},
		},
		{
			// No A record can be in the message, so the zone is no obstacle.
			name:      "AAAA carries link-local IPv6 next to IPv4",
			setup:     ifaceSetup(addr4, linkLocal6),
			qtype:     dnsmessage.TypeAAAA,
			wantAddrs: []netip.Addr{linkLocal6},
		},
		{
			name:      "PTR carries both families for its additionals",
			setup:     ifaceSetup(addr4, global6),
			qtype:     dnsmessage.TypePTR,
			wantAddrs: []netip.Addr{addr4, global6},
		},
		{
			name:      "PTR drops link-local IPv6 next to IPv4",
			setup:     ifaceSetup(addr4, linkLocal6),
			qtype:     dnsmessage.TypePTR,
			wantAddrs: []netip.Addr{addr4},
		},
		{
			// Without an IPv4 address on the interface the IPv4 lookup falls
			// back to the route towards the querier, which here is IPv6.
			name:      "SRV carries link-local IPv6 when it is the only address",
			setup:     ifaceSetup(linkLocal6),
			source:    net.ParseIP("2001:db8::2"),
			qtype:     dnsmessage.TypeSRV,
			wantAddrs: []netip.Addr{linkLocal6},
		},
		{
			name:  "TXT carries no addresses",
			setup: ifaceSetup(addr4, global6),
			qtype: dnsmessage.TypeTXT,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			setup := tc.setup()
			msgCtx := newTestMessageContext(5353)
			if tc.source != nil {
				msgCtx.source.IP = tc.source
			}

			// The host name matches whatever the type, so the handler always
			// resolves addresses for it.
			setup.handler.handle(msgCtx, newTestQuestion("myhost.local.", tc.qtype, dnsmessage.ClassINET))

			require.Len(t, setup.sender.calls, 1)
			assert.Equal(t, tc.wantAddrs, setup.sender.calls[0].match.addrs)
		})
	}
}

func TestAnyQuestionAmongOtherQuestions(t *testing.T) {
	// A multi-question query mixes ANY with regular questions; each gets
	// its own response.
	setup := newQuestionHandlerTestSetup([]string{"myhost.local."}, net.ParseIP("192.168.1.100"))
	setup.sender.services = anyTestServices()
	msg := &dnsmessage.Message{
		Header: dnsmessage.Header{ID: 7},
		Questions: []dnsmessage.Question{
			{Name: dnsmessage.MustNewName("myhost.local."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
			{Name: dnsmessage.MustNewName("_matterc._udp.local."), Type: dnsmessage.TypeALL, Class: dnsmessage.ClassINET},
			{Name: dnsmessage.MustNewName("_matterc._udp.local."), Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET},
		},
	}

	setup.handler.handle(newTestMessageContext(5353), msg)

	require.Len(t, setup.sender.calls, 3)
	assert.Equal(t, []dnsmessage.Type{dnsmessage.TypeA}, setup.sender.calls[0].match.types)
	assert.Equal(t, anyAllTypes(), setup.sender.calls[1].match.types)
	assert.Equal(t, []dnsmessage.Type{dnsmessage.TypePTR}, setup.sender.calls[2].match.types)
}

func anyQuestion(name string) dnsmessage.Question {
	return testQuestion(name, dnsmessage.TypeALL, dnsmessage.ClassINET)
}

func TestCreateAnswerHost(t *testing.T) {
	srv := &server{ttl: 120}
	addrs := []netip.Addr{netip.MustParseAddr("192.168.1.100"), netip.MustParseAddr("2001:db8::1")}
	match := &nameMatch{types: anyAllTypes(), host: true, addrs: addrs}

	msg, usedAddrs, err := srv.createAnswer(42, anyQuestion("MyHost.local."), match, false)
	require.NoError(t, err)

	assert.Equal(t, uint16(42), msg.Header.ID)
	assert.True(t, msg.Header.Response)
	assert.True(t, msg.Header.Authoritative)
	assert.Empty(t, msg.Questions, "multicast response does not echo the question")
	// Owned by the name as asked, like an A/AAAA answer.
	assert.Equal(t, []string{"MyHost.local. TypeA", "MyHost.local. TypeAAAA"}, resourceSummary(msg.Answers))
	assert.Empty(t, msg.Additionals, "address answers recommend no additionals (RFC 6763 §12.4)")
	assert.Equal(t, addrs, usedAddrs)

	for _, answer := range msg.Answers {
		assert.Equal(t, uint32(120), answer.Header.TTL)
		assert.Equal(t, dnsmessage.ClassINET, answer.Header.Class, "no cache-flush bit on responses")
	}
	addr4, err := addrFromAnswer(msg.Answers[0])
	require.NoError(t, err)
	assert.Equal(t, addrs[0], *addr4)
	addr6, err := addrFromAnswer(msg.Answers[1])
	require.NoError(t, err)
	assert.Equal(t, addrs[1], *addr6)
}

func TestCreateAnswerBrowse(t *testing.T) {
	srv := &server{ttl: 120}
	services := rfc6763SubtypeServices()
	match := &nameMatch{
		types: []dnsmessage.Type{dnsmessage.TypePTR},
		browse: []browseMatch{
			{svc: &services[0], ptrName: "_http._tcp.local."},
			{svc: &services[1], ptrName: "_http._tcp.local."},
		},
		addrs: []netip.Addr{netip.MustParseAddr("192.168.1.100")},
	}

	msg, usedAddrs, err := srv.createAnswer(1, testQuestion("_http._tcp.local.", dnsmessage.TypePTR, dnsmessage.ClassINET), match, false)
	require.NoError(t, err)

	// One PTR per instance; SRV/TXT additionals per instance (RFC 6763
	// §12.1) and the shared host address only once.
	assert.Equal(t, []string{"_http._tcp.local. TypePTR", "_http._tcp.local. TypePTR"}, resourceSummary(msg.Answers))
	assert.Equal(t, []string{
		"A web page._http._tcp.local. TypeSRV",
		"A web page._http._tcp.local. TypeTXT",
		"myhost.local. TypeA",
		"A printer's web page._http._tcp.local. TypeSRV",
		"A printer's web page._http._tcp.local. TypeTXT",
	}, resourceSummary(msg.Additionals))
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("192.168.1.100")}, usedAddrs)

	targets := make([]string, 0, len(msg.Answers))
	for _, answer := range msg.Answers {
		assert.Equal(t, browseTTL, answer.Header.TTL)
		target, err := parsePTRTarget(answer.Body)
		require.NoError(t, err)
		targets = append(targets, target)
	}
	assert.Equal(t, []string{"A web page._http._tcp.local.", "A printer's web page._http._tcp.local."}, targets)
}

func TestCreateAnswerSubtypeBrowse(t *testing.T) {
	srv := &server{ttl: 120}
	services := anyTestServices()
	match := &nameMatch{
		types:  anyAllTypes(),
		browse: []browseMatch{{svc: &services[2], ptrName: "_S3._sub._matterc._udp.local."}},
		addrs:  []netip.Addr{netip.MustParseAddr("2001:db8::1")},
	}

	msg, _, err := srv.createAnswer(1, anyQuestion("_s3._sub._matterc._udp.local."), match, false)
	require.NoError(t, err)

	// The PTR is owned by the subtype browse name and points at the
	// unchanged Service Instance Name (RFC 6763 §7.1).
	assert.Equal(t, []string{"_S3._sub._matterc._udp.local. TypePTR"}, resourceSummary(msg.Answers))
	target, err := parsePTRTarget(msg.Answers[0].Body)
	require.NoError(t, err)
	assert.Equal(t, "0123456789ABCDEF._matterc._udp.local.", target)

	assert.Equal(t, []string{
		"0123456789ABCDEF._matterc._udp.local. TypeSRV",
		"0123456789ABCDEF._matterc._udp.local. TypeTXT",
		"myhost.local. TypeAAAA",
	}, resourceSummary(msg.Additionals))
	srvTarget, port, _, _, err := parseSRVData(msg.Additionals[0].Body)
	require.NoError(t, err)
	assert.Equal(t, "myhost.local.", srvTarget)
	assert.Equal(t, uint16(5540), port)
	txts, err := parseTXTData(msg.Additionals[1].Body)
	require.NoError(t, err)
	assert.Equal(t, []string{"D=840"}, txts)
}

func TestCreateAnswerInstance(t *testing.T) {
	srv := &server{ttl: 120}
	services := anyTestServices()
	match := &nameMatch{
		types:     anyAllTypes(),
		instances: []*ServiceInstance{&services[2]},
		addrs:     []netip.Addr{netip.MustParseAddr("192.168.1.100"), netip.MustParseAddr("2001:db8::1")},
	}

	msg, usedAddrs, err := srv.createAnswer(1, anyQuestion("0123456789ABCDEF._matterc._udp.local."), match, false)
	require.NoError(t, err)

	// SRV and TXT answers; the SRV brings the host addresses (RFC 6763 §12.2).
	assert.Equal(t, []string{
		"0123456789ABCDEF._matterc._udp.local. TypeSRV",
		"0123456789ABCDEF._matterc._udp.local. TypeTXT",
	}, resourceSummary(msg.Answers))
	assert.Equal(t, []string{"myhost.local. TypeA", "myhost.local. TypeAAAA"}, resourceSummary(msg.Additionals))
	assert.Equal(t, match.addrs, usedAddrs)
}

func TestCreateAnswerServiceTypes(t *testing.T) {
	srv := &server{ttl: 120}
	match := &nameMatch{
		types:        anyAllTypes(),
		serviceTypes: []string{"_http._tcp.local.", "_matterc._udp.local."},
		addrs:        []netip.Addr{netip.MustParseAddr("192.168.1.100")},
	}

	msg, usedAddrs, err := srv.createAnswer(1, anyQuestion("_services._dns-sd._udp.local."), match, false)
	require.NoError(t, err)

	// One PTR per service type and no additionals (RFC 6763 §9).
	assert.Equal(t, []string{
		"_services._dns-sd._udp.local. TypePTR",
		"_services._dns-sd._udp.local. TypePTR",
	}, resourceSummary(msg.Answers))
	assert.Empty(t, msg.Additionals)
	assert.Empty(t, usedAddrs)
}

func TestCreateAnswerUnicastEchoesQuestion(t *testing.T) {
	srv := &server{ttl: 120}
	services := anyTestServices()
	question := anyQuestion("_S3._sub._matterc._udp.local.")
	question.Class |= qClassUnicastResponse
	match := &nameMatch{
		types:  anyAllTypes(),
		browse: []browseMatch{{svc: &services[2], ptrName: "_S3._sub._matterc._udp.local."}},
		addrs:  []netip.Addr{netip.MustParseAddr("192.168.1.100")},
	}

	msg, _, err := srv.createAnswer(0x1234, question, match, true)
	require.NoError(t, err)

	assert.Equal(t, uint16(0x1234), msg.Header.ID, "legacy response repeats the query ID (RFC 6762 §6.7)")
	assert.Equal(t, []dnsmessage.Question{question}, msg.Questions, "legacy response repeats the question as asked")
	assert.Len(t, msg.Answers, 1)
}

func TestCreateAnswerRecordTypeFilter(t *testing.T) {
	services := anyTestServices()
	addrs := []netip.Addr{netip.MustParseAddr("192.168.1.100"), netip.MustParseAddr("2001:db8::1")}

	tests := []struct {
		name            string
		types           []dnsmessage.Type
		match           nameMatch
		wantAnswers     []string
		wantAdditionals []string
		wantAddrs       []netip.Addr
	}{
		{
			name:        "host name with A only",
			types:       []dnsmessage.Type{dnsmessage.TypeA},
			match:       nameMatch{host: true},
			wantAnswers: []string{"myhost.local. TypeA"},
			wantAddrs:   addrs[:1],
		},
		{
			name:  "host name with AAAA only",
			types: []dnsmessage.Type{dnsmessage.TypeAAAA},
			match: nameMatch{host: true}, wantAnswers: []string{"myhost.local. TypeAAAA"},
			wantAddrs: addrs[1:],
		},
		{
			name:  "browse name without PTR",
			types: []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA},
			match: nameMatch{browse: []browseMatch{{svc: &services[0], ptrName: "_http._tcp.local."}}},
		},
		{
			name:  "enumeration name without PTR",
			types: []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA},
			match: nameMatch{serviceTypes: []string{"_http._tcp.local."}},
		},
		{
			// Additionals follow the answer, not the filter, as for a PTR question.
			name:        "browse name with PTR only",
			types:       []dnsmessage.Type{dnsmessage.TypePTR},
			match:       nameMatch{browse: []browseMatch{{svc: &services[0], ptrName: "_http._tcp.local."}}},
			wantAnswers: []string{"_http._tcp.local. TypePTR"},
			wantAdditionals: []string{
				"A web page._http._tcp.local. TypeSRV", "A web page._http._tcp.local. TypeTXT",
				"myhost.local. TypeA", "myhost.local. TypeAAAA",
			},
			wantAddrs: addrs,
		},
		{
			name:            "instance name with SRV only",
			types:           []dnsmessage.Type{dnsmessage.TypeSRV},
			match:           nameMatch{instances: []*ServiceInstance{&services[0]}},
			wantAnswers:     []string{"A web page._http._tcp.local. TypeSRV"},
			wantAdditionals: []string{"myhost.local. TypeA", "myhost.local. TypeAAAA"},
			wantAddrs:       addrs,
		},
		{
			name:        "instance name with TXT only",
			types:       []dnsmessage.Type{dnsmessage.TypeTXT},
			match:       nameMatch{instances: []*ServiceInstance{&services[0]}},
			wantAnswers: []string{"A web page._http._tcp.local. TypeTXT"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := &server{ttl: 120}
			match := tc.match
			match.types = tc.types
			match.addrs = addrs

			msg, usedAddrs, err := srv.createAnswer(1, anyQuestion("myhost.local."), &match, false)
			require.NoError(t, err)

			assert.Equal(t, tc.wantAnswers, resourceSummary(msg.Answers))
			assert.Equal(t, tc.wantAdditionals, resourceSummary(msg.Additionals))
			assert.Equal(t, tc.wantAddrs, usedAddrs)
		})
	}
}

func TestSendAnswer(t *testing.T) {
	services := anyTestServices()
	loopback := netip.MustParseAddr("127.0.0.1")
	linkLocal := netip.MustParseAddr("fe80::1%eth0")

	tests := []struct {
		name            string
		match           nameMatch
		wantWrite       bool
		wantLoopback    bool
		wantIPv6Zone    bool
		wantAnswerCount int
	}{
		{
			name:  "nothing to answer sends nothing",
			match: nameMatch{types: []dnsmessage.Type{dnsmessage.TypeA}, browse: []browseMatch{{svc: &services[0], ptrName: "_http._tcp.local."}}},
		},
		{
			name:  "host name without addresses sends nothing",
			match: nameMatch{types: anyAllTypes(), host: true},
		},
		{
			name:            "plain addresses",
			match:           nameMatch{types: anyAllTypes(), host: true, addrs: []netip.Addr{netip.MustParseAddr("192.168.1.100")}},
			wantWrite:       true,
			wantAnswerCount: 1,
		},
		{
			name:            "loopback and zoned addresses set the delivery flags",
			match:           nameMatch{types: anyAllTypes(), host: true, addrs: []netip.Addr{loopback, linkLocal}},
			wantWrite:       true,
			wantLoopback:    true,
			wantIPv6Zone:    true,
			wantAnswerCount: 2,
		},
		{
			name: "zoned address in an additional sets the delivery flag",
			match: nameMatch{
				types: []dnsmessage.Type{dnsmessage.TypeSRV}, instances: []*ServiceInstance{&services[0]},
				addrs: []netip.Addr{linkLocal},
			},
			wantWrite:       true,
			wantIPv6Zone:    true,
			wantAnswerCount: 1,
		},
		{
			// Addresses not carried in the message do not restrict delivery.
			name: "TXT-only answer ignores unused addresses",
			match: nameMatch{
				types: []dnsmessage.Type{dnsmessage.TypeTXT}, instances: []*ServiceInstance{&services[0]},
				addrs: []netip.Addr{loopback, linkLocal},
			},
			wantWrite:       true,
			wantAnswerCount: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			writer := &mockAnswerWriter{}
			srv := &server{ttl: 120, writer: writer, log: logging.NewDefaultLoggerFactory().NewLogger("test")}
			dst := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 5353}

			srv.sendAnswer(1, anyQuestion("myhost.local."), 3, tc.match, dst, true)

			if !tc.wantWrite {
				assert.Empty(t, writer.writes)

				return
			}
			require.Len(t, writer.writes, 1, "one packet per question")
			write := writer.writes[0]
			assert.Equal(t, 3, write.ifIndex)
			assert.Equal(t, dst, write.dst)
			assert.Equal(t, tc.wantLoopback, write.hasLoopbackData)
			assert.Equal(t, tc.wantIPv6Zone, write.hasIPv6Zone)

			msgs := writer.messages(t)
			assert.Len(t, msgs[0].Answers, tc.wantAnswerCount)
			assert.Len(t, msgs[0].Questions, 1, "unicast response echoes the question")
		})
	}
}
