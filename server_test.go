// SPDX-FileCopyrightText: The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package mdns

import (
	"net"
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

func TestConfigurePacketConn4Nil(t *testing.T) {
	log := logging.NewDefaultLoggerFactory().NewLogger("mdns")
	result := configurePacketConn4(nil, "test", "multicast", log)
	assert.Nil(t, result)
}

func TestConfigurePacketConn6Nil(t *testing.T) {
	log := logging.NewDefaultLoggerFactory().NewLogger("mdns")
	result := configurePacketConn6(nil, "test", "multicast", log)
	assert.Nil(t, result)
}

func TestEnableLoopback4Nil(t *testing.T) {
	log := logging.NewDefaultLoggerFactory().NewLogger("mdns")
	// Should not panic when called with nil
	enableLoopback4(nil, "test", "multicast", log)
}

func TestEnableLoopback6Nil(t *testing.T) {
	log := logging.NewDefaultLoggerFactory().NewLogger("mdns")
	// Should not panic when called with nil
	enableLoopback6(nil, "test", "multicast", log)
}

func TestConfigurePacketConn4WithConn(t *testing.T) {
	sock := createListener4(t)
	defer func() { _ = sock.Close() }()

	log := logging.NewDefaultLoggerFactory().NewLogger("mdns")
	pc := ipv4.NewPacketConn(sock)
	result := configurePacketConn4(pc, "test", "multicast", log)
	assert.NotNil(t, result)
}

func TestConfigurePacketConn6WithConn(t *testing.T) {
	sock := createListener6(t)
	defer func() { _ = sock.Close() }()

	log := logging.NewDefaultLoggerFactory().NewLogger("mdns")
	pc := ipv6.NewPacketConn(sock)
	result := configurePacketConn6(pc, "test", "multicast", log)
	assert.NotNil(t, result)
}

func TestEnableLoopback4WithConn(t *testing.T) {
	sock := createListener4(t)
	defer func() { _ = sock.Close() }()

	log := logging.NewDefaultLoggerFactory().NewLogger("mdns")
	pc := ipv4.NewPacketConn(sock)
	// Should not panic
	enableLoopback4(pc, "test", "multicast", log)
}

func TestEnableLoopback6WithConn(t *testing.T) {
	sock := createListener6(t)
	defer func() { _ = sock.Close() }()

	log := logging.NewDefaultLoggerFactory().NewLogger("mdns")
	pc := ipv6.NewPacketConn(sock)
	// Should not panic
	enableLoopback6(pc, "test", "multicast", log)
}
