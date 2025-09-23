// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js
// +build !js

package mdns

import (
	"context"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/pion/transport/v3/test"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	localAddress = "1.2.3.4"
	isWindows    = runtime.GOOS == "windows"
)

func checkIPv4(t *testing.T, addr netip.Addr) {
	t.Helper()
	assert.Truef(t, addr.Is4(), "expected IPv4 for answer but got %s", addr)
}

func checkIPv6(t *testing.T, addr netip.Addr) {
	t.Helper()
	assert.Truef(t, addr.Is6(), "expected IPv6 for answer but got %s", addr)
}

func createListener4(t *testing.T) *net.UDPConn {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", DefaultAddressIPv4)
	assert.NoError(t, err)

	sock, err := net.ListenUDP("udp4", addr)
	assert.NoError(t, err)

	// ensure multicast loopback is enabled so tests can observe their own packets.
	_ = ipv4.NewPacketConn(sock).SetMulticastLoopback(true)

	return sock
}

func createListener6(t *testing.T) *net.UDPConn {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", DefaultAddressIPv6)
	assert.NoError(t, err)

	sock, err := net.ListenUDP("udp6", addr)
	assert.NoError(t, err)

	// Ensure multicast loopback is enabled so tests can observe their own packets.
	_ = ipv6.NewPacketConn(sock).SetMulticastLoopback(true)

	return sock
}

// firstUsableIPv4Addr returns the first interface that is up, supports multicast,
// is not loopback, and one of its IPv4 addresses. Used to provide a concrete IPv4.
// this is needed for windows because cross-stack ipv4/ipv6 is unreliable.
func firstUsableIPv4Addr(t *testing.T) net.IP {
	t.Helper()
	ifaces, err := net.Interfaces()

	assert.NoError(t, err)
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 {
			continue
		}
		if ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		if ifc.Flags&net.FlagMulticast == 0 {
			continue
		}
		addrs, err := ifc.Addrs()

		assert.NoError(t, err)

		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil {
				continue
			}
			if v4 := ip.To4(); v4 != nil {
				return v4
			}
		}
	}

	assert.Fail(t, "no usable IPv4 interface found for test")

	return nil
}

func TestValidCommunication(t *testing.T) {
	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	aSock := createListener4(t)
	bSock := createListener4(t)

	aServer, err := Server(ipv4.NewPacketConn(aSock), nil, &Config{
		LocalNames: []string{"pion-mdns-1.local", "pion-mdns-2.local"},
	})
	assert.NoError(t, err)

	bServer, err := Server(ipv4.NewPacketConn(bSock), nil, &Config{})
	assert.NoError(t, err)

	_, addr, err := bServer.QueryAddr(context.TODO(), "pion-mdns-1.local")
	assert.NoError(t, err)
	assert.NotEqualf(t, localAddress, addr.String(), "unexpected local address: %v", addr)
	checkIPv4(t, addr)

	_, addr, err = bServer.QueryAddr(context.TODO(), "pion-mdns-2.local")
	assert.NoError(t, err)
	assert.NotEqualf(t, localAddress, addr.String(), "unexpected local address: %v", addr)
	checkIPv4(t, addr)

	// test against regression from https://github.com/pion/mdns/commit/608f20b
	// where by properly sending mDNS responses to all interfaces, we significantly
	// increased the chance that we send a loopback response to a Query that is
	// unwillingly to use loopback addresses (the default in pion/ice).
	for i := 0; i < 100; i++ {
		_, addr, err = bServer.QueryAddr(context.TODO(), "pion-mdns-2.local")
		assert.NoError(t, err)
		assert.NotEqualf(t, localAddress, addr.String(), "unexpected local address: %v", addr)
		assert.NotEqual(t, "127.0.0.1", addr.String(), "unexpected loopback")
		checkIPv4(t, addr)
	}

	assert.NoError(t, aServer.Close())
	assert.NoError(t, bServer.Close())

	assert.Empty(t, aServer.queries, "Queries not cleaned up after aServer close")
	assert.Empty(t, bServer.queries, "Queries not cleaned up after bServer close")
}

func TestValidCommunicationWithAddressConfig(t *testing.T) {
	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	aSock := createListener4(t)

	aServer, err := Server(ipv4.NewPacketConn(aSock), nil, &Config{
		LocalNames:   []string{"pion-mdns-1.local", "pion-mdns-2.local"},
		LocalAddress: net.ParseIP(localAddress),
	})
	assert.NoError(t, err)

	_, addr, err := aServer.QueryAddr(context.TODO(), "pion-mdns-1.local")
	assert.NoError(t, err)
	assert.Equalf(t, localAddress, addr.String(), "address mismatch: expected %s, but got %v\n", localAddress, addr)

	assert.NoError(t, aServer.Close())
	assert.Empty(t, aServer.queries, "Queries not cleaned up after aServer close")
}

func TestValidCommunicationWithLoopbackAddressConfig(t *testing.T) {
	// loopbacks cannot join multicast groups on windows.
	if isWindows {
		t.Skip("not supported on windows")
	}

	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	aSock := createListener4(t)

	loopbackIP := net.ParseIP("127.0.0.1")

	aServer, err := Server(ipv4.NewPacketConn(aSock), nil, &Config{
		LocalNames:      []string{"pion-mdns-1.local", "pion-mdns-2.local"},
		LocalAddress:    loopbackIP,
		IncludeLoopback: true, // the test would fail if this was false
	})
	assert.NoError(t, err)

	_, addr, err := aServer.QueryAddr(context.TODO(), "pion-mdns-1.local")
	assert.NoError(t, err)
	assert.Equalf(t, loopbackIP.String(), addr.String(), "address mismatch: expected %s, but got %v\n", loopbackIP, addr)

	assert.NoError(t, aServer.Close())
}

func TestValidCommunicationWithLoopbackInterface(t *testing.T) {
	// loopbacks cannot join multicast groups on windows.
	if runtime.GOOS == "windows" {
		t.Skip("not supported on windows")
	}

	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	aSock := createListener4(t)

	ifaces, err := net.Interfaces()
	assert.NoError(t, err)
	ifacesToUse := make([]net.Interface, 0, len(ifaces))
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != net.FlagLoopback {
			continue
		}
		ifcCopy := ifc
		ifacesToUse = append(ifacesToUse, ifcCopy)
	}

	// the following checks are unlikely to fail since most places where this code runs
	// will have a loopback
	if len(ifacesToUse) == 0 {
		t.Skip("expected at least one loopback interface, but got none")
	}

	aServer, err := Server(ipv4.NewPacketConn(aSock), nil, &Config{
		LocalNames:      []string{"pion-mdns-1.local", "pion-mdns-2.local"},
		IncludeLoopback: true, // the test would fail if this was false
		Interfaces:      ifacesToUse,
	})
	assert.NoError(t, err)

	_, addr, err := aServer.QueryAddr(context.TODO(), "pion-mdns-1.local")
	assert.NoError(t, err)
	var found bool
	for _, iface := range ifacesToUse {
		addrs, err := iface.Addrs()
		assert.NoError(t, err)
		for _, ifaceAddr := range addrs {
			ipAddr, ok := ifaceAddr.(*net.IPNet)
			assert.Truef(t, ok, "expected *net.IPNet address for loopback but got %T", addr)
			if addr.String() == ipAddr.IP.String() {
				found = true

				break
			}
		}
		if found {
			break
		}
	}
	assert.Truef(t, found, "address mismatch: expected loopback address, but got %v\n", addr)

	assert.NoError(t, aServer.Close())
}

func TestValidCommunicationIPv6(t *testing.T) { //nolint:cyclop
	if runtime.GOARCH == "386" {
		t.Skip("IPv6 not supported on 386 for some reason")
	}
	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	_, err := Server(nil, nil, &Config{
		LocalNames: []string{"pion-mdns-1.local", "pion-mdns-2.local"},
	})
	assert.ErrorIs(t, err, errNoPacketConn, "expected error if no PacketConn supplied to Server")

	aSock := createListener6(t)
	bSock := createListener6(t)

	aServer, err := Server(nil, ipv6.NewPacketConn(aSock), &Config{
		LocalNames: []string{"pion-mdns-1.local", "pion-mdns-2.local"},
	})
	assert.NoError(t, err)

	bServer, err := Server(nil, ipv6.NewPacketConn(bSock), &Config{})
	assert.NoError(t, err)

	header, addr, err := bServer.QueryAddr(context.TODO(), "pion-mdns-1.local")
	assert.NoError(t, err)
	assert.Equalf(t, dnsmessage.TypeAAAA, header.Type, "expected AAAA but got %s", header.Type)

	assert.NotEqualf(t, localAddress, addr.String(), "unexpected local address: %v", addr)
	checkIPv6(t, addr)
	if addr.Is4In6() {
		// probably within docker
		t.Logf("address %s is an IPv4-to-IPv6 mapped address even though the stack is IPv6", addr)
	} else if addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
		assert.NotEqualf(t, "", addr.Zone(), "expected link-local IPv6 to have zone but got %s", addr)
	}

	header, addr, err = bServer.QueryAddr(context.TODO(), "pion-mdns-2.local")
	assert.NoError(t, err)
	assert.Equalf(t, dnsmessage.TypeAAAA, header.Type, "expected AAAA but got %s", header.Type)

	assert.NotEqualf(t, localAddress, addr.String(), "unexpected local address: %v", addr)
	checkIPv6(t, addr)
	if !addr.Is4In6() {
		assert.NotEqualf(t, "", addr.Zone(), "expected IPv6 to have zone but got %s", addr)
	}

	assert.NoError(t, aServer.Close())
	assert.NoError(t, bServer.Close())

	assert.Empty(t, aServer.queries, "Queries not cleaned up after aServer close")
	assert.Empty(t, bServer.queries, "Queries not cleaned up after bServer close")
}

func TestValidCommunicationIPv46(t *testing.T) {
	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	aSock4 := createListener4(t)
	bSock4 := createListener4(t)
	aSock6 := createListener6(t)
	bSock6 := createListener6(t)

	aServer, err := Server(ipv4.NewPacketConn(aSock4), ipv6.NewPacketConn(aSock6), &Config{
		LocalNames: []string{"pion-mdns-1.local", "pion-mdns-2.local"},
	})
	assert.NoError(t, err)

	bServer, err := Server(ipv4.NewPacketConn(bSock4), ipv6.NewPacketConn(bSock6), &Config{})
	assert.NoError(t, err)

	_, addr, err := bServer.QueryAddr(context.TODO(), "pion-mdns-1.local")
	assert.NoError(t, err)

	assert.NotEqualf(t, localAddress, addr.String(), "unexpected local address: %v", addr)

	_, addr, err = bServer.QueryAddr(context.TODO(), "pion-mdns-2.local")
	assert.NoError(t, err)
	assert.NotEqualf(t, localAddress, addr.String(), "unexpected local address: %v", addr)

	assert.NoError(t, aServer.Close())
	assert.NoError(t, bServer.Close())

	assert.Empty(t, aServer.queries, "Queries not cleaned up after aServer close")
	assert.Empty(t, bServer.queries, "Queries not cleaned up after bServer close")
}

func TestValidCommunicationIPv46Mixed(t *testing.T) {
	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	aSock4 := createListener4(t)
	bSock6 := createListener6(t)

	// we can always send from a 6-only server to a 4-only server but not always
	// the other way around because the IPv4-only server will only listen
	// on multicast for IPv4 questions, so it will never see an IPv6 originated
	// question that contains required information to respond (the zone, if link-local).
	// Therefore, the IPv4 server will refuse answering AAAA responses over
	// unicast/multicast IPv4 if the answer is an IPv6 link-local address. This is basically
	// the majority of cases unless a LocalAddress is set on the Config.
	// aServer is IPv4-only and will perform the query
	aServer, err := Server(ipv4.NewPacketConn(aSock4), nil, &Config{
		Name: "aServer",
	})
	assert.NoError(t, err)

	bCfg := &Config{
		Name:       "bServer",
		LocalNames: []string{"pion-mdns-1.local"},
	}
	// for windows: provide a concrete IPv4 LocalAddress to allow answering an A record .
	// because windows cross-stack ipv4/ipv6 is unreliable.
	if isWindows {
		v4 := firstUsableIPv4Addr(t)
		bCfg.LocalAddress = v4
	}
	bServer, err := Server(nil, ipv6.NewPacketConn(bSock6), bCfg)
	assert.NoError(t, err)

	header, addr, err := aServer.QueryAddr(context.TODO(), "pion-mdns-1.local")

	assert.NoError(t, err)
	assert.Equalf(t, dnsmessage.TypeA, header.Type, "expected A but got %s", header.Type)

	checkIPv4(t, addr)

	assert.NoError(t, aServer.Close())
	assert.NoError(t, bServer.Close())

	assert.Empty(t, aServer.queries, "Queries not cleaned up after aServer close")
	assert.Empty(t, bServer.queries, "Queries not cleaned up after bServer close")
}

func TestValidCommunicationIPv46MixedLocalAddress(t *testing.T) {
	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	aSock4 := createListener4(t)
	bSock6 := createListener6(t)

	aServer, err := Server(ipv4.NewPacketConn(aSock4), nil, &Config{
		LocalAddress: net.IPv4(1, 2, 3, 4),
		LocalNames:   []string{"pion-mdns-1.local"},
	})
	assert.NoError(t, err)

	bServer, err := Server(nil, ipv6.NewPacketConn(bSock6), &Config{})
	assert.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// we want ipv6 but all we can offer is an ipv4 mapped address, so it should fail until we support
	// allowing this explicitly via configuration on the aServer side
	_, _, err = bServer.QueryAddr(ctx, "pion-mdns-1.local")
	assert.ErrorIsf(t, err, errContextElapsed, "Query expired but returned unexpected error %v", err)

	assert.NoError(t, aServer.Close())
	assert.NoError(t, bServer.Close())

	assert.Empty(t, aServer.queries, "Queries not cleaned up after aServer close")
	assert.Empty(t, bServer.queries, "Queries not cleaned up after bServer close")
}

func TestValidCommunicationIPv66Mixed(t *testing.T) {
	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	aSock6 := createListener6(t)
	bSock6 := createListener6(t)

	aServer, err := Server(nil, ipv6.NewPacketConn(aSock6), &Config{
		LocalNames: []string{"pion-mdns-1.local"},
	})
	assert.NoError(t, err)

	bServer, err := Server(nil, ipv6.NewPacketConn(bSock6), &Config{})
	assert.NoError(t, err)

	header, addr, err := bServer.QueryAddr(context.TODO(), "pion-mdns-1.local")
	assert.NoError(t, err)
	assert.Equalf(t, dnsmessage.TypeAAAA, header.Type, "expected AAAA but got %s", header.Type)
	assert.NotEqualf(t, localAddress, addr.String(), "unexpected local address: %v", addr)
	assert.Falsef(t, addr.Is4In6(), "expected address to not be ipv4-to-ipv6 mapped: %v", addr)
	checkIPv6(t, addr)

	assert.NoError(t, aServer.Close())
	assert.NoError(t, bServer.Close())

	assert.Empty(t, aServer.queries, "Queries not cleaned up after aServer close")
	assert.Empty(t, bServer.queries, "Queries not cleaned up after bServer close")
}

func TestValidCommunicationIPv66MixedLocalAddress(t *testing.T) {
	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	aSock6 := createListener6(t)
	bSock6 := createListener6(t)

	aServer, err := Server(nil, ipv6.NewPacketConn(aSock6), &Config{
		LocalAddress: net.IPv4(1, 2, 3, 4),
		LocalNames:   []string{"pion-mdns-1.local"},
	})
	assert.NoError(t, err)

	bServer, err := Server(nil, ipv6.NewPacketConn(bSock6), &Config{})
	assert.NoError(t, err)

	header, addr, err := bServer.QueryAddr(context.TODO(), "pion-mdns-1.local")
	assert.NoError(t, err)
	assert.Equalf(t, dnsmessage.TypeAAAA, header.Type, "expected AAAA but got %s", header.Type)
	assert.Truef(t, addr.Is4In6(), "expected address to be ipv4-to-ipv6 mapped: %v", addr)
	// now unmap just for this check
	assert.Equalf(t, localAddress, addr.Unmap().String(), "unexpected local address: %v", addr)
	checkIPv6(t, addr)

	assert.NoError(t, aServer.Close())
	assert.NoError(t, bServer.Close())

	assert.Empty(t, aServer.queries, "Queries not cleaned up after aServer close")
	assert.Empty(t, bServer.queries, "Queries not cleaned up after bServer close")
}

func TestValidCommunicationIPv64Mixed(t *testing.T) {
	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	aSock6 := createListener6(t)
	bSock4 := createListener4(t)

	aCfg := &Config{
		LocalNames: []string{"pion-mdns-1.local", "pion-mdns-2.local"},
	}
	// for windows: provide a concrete IPv4 LocalAddress to allow answering an A record .
	// because windows cross-stack ipv4/ipv6 is unreliable.
	if isWindows {
		v4 := firstUsableIPv4Addr(t)
		aCfg.LocalAddress = v4
	}
	aServer, err := Server(nil, ipv6.NewPacketConn(aSock6), aCfg)
	assert.NoError(t, err)

	bServer, err := Server(ipv4.NewPacketConn(bSock4), nil, &Config{})
	assert.NoError(t, err)

	_, addr, err := bServer.QueryAddr(context.TODO(), "pion-mdns-1.local")
	assert.NoError(t, err)

	assert.NotEqualf(t, localAddress, addr.String(), "unexpected local address: %v", addr)

	header, addr, err := bServer.QueryAddr(context.TODO(), "pion-mdns-2.local")
	assert.NoError(t, err)
	assert.Equalf(t, dnsmessage.TypeA, header.Type, "expected A but got %s", header.Type)
	assert.NotEqualf(t, localAddress, addr.String(), "unexpected local address: %v", addr)

	assert.NoError(t, aServer.Close())
	assert.NoError(t, bServer.Close())

	assert.Empty(t, aServer.queries, "Queries not cleaned up after aServer close")
	assert.Empty(t, bServer.queries, "Queries not cleaned up after bServer close")
}

func TestMultipleClose(t *testing.T) {
	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	aSock := createListener4(t)

	server, err := Server(ipv4.NewPacketConn(aSock), nil, &Config{})
	assert.NoError(t, err)

	assert.NoError(t, server.Close())
	assert.NoError(t, server.Close())

	assert.Empty(t, server.queries, "Queries not cleaned up after server close")
}

func TestQueryRespectTimeout(t *testing.T) {
	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	aSock := createListener4(t)

	server, err := Server(ipv4.NewPacketConn(aSock), nil, &Config{})
	assert.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	_, _, err = server.QueryAddr(ctx, "invalid-host")
	assert.ErrorIsf(t, err, errContextElapsed, "Query expired but returned unexpected error %v", err)

	assert.NoError(t, server.Close())

	assert.Empty(t, server.queries, "Queries not cleaned up after server close")
}

func TestQueryRespectClose(t *testing.T) {
	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	aSock := createListener4(t)

	server, err := Server(ipv4.NewPacketConn(aSock), nil, &Config{})
	assert.NoError(t, err)

	go func() {
		time.Sleep(3 * time.Second)
		assert.NoError(t, server.Close())
	}()

	_, _, err = server.QueryAddr(context.TODO(), "invalid-host")
	assert.ErrorIsf(t, err, errConnectionClosed, "Query on closed server but returned unexpected error %v", err)

	_, _, err = server.QueryAddr(context.TODO(), "invalid-host")
	assert.ErrorIsf(t, err, errConnectionClosed, "Query on closed server but returned unexpected error %v", err)

	assert.Empty(t, server.queries, "Queries not cleaned up after server close")
}

func TestResourceParsing(t *testing.T) {
	lookForIP := func(t *testing.T, msg dnsmessage.Message, expectedIP []byte) {
		t.Helper()

		buf, err := msg.Pack()
		assert.NoError(t, err)

		var parser dnsmessage.Parser
		_, err = parser.Start(buf)
		assert.NoError(t, err)

		assert.NoError(t, parser.SkipAllQuestions())

		h, err := parser.AnswerHeader()
		assert.NoError(t, err)

		actualAddr, err := addrFromAnswerHeader(h, parser)
		assert.NoError(t, err)

		assert.Equalf(
			t,
			expectedIP,
			actualAddr.AsSlice(),
			"Expected(%v) and Actual(%v) IP don't match",
			expectedIP,
			actualAddr.AsSlice(),
		)
	}

	name := "test-server."

	t.Run("A Record", func(t *testing.T) {
		answer, err := createAnswer(1, name, mustAddr(t, net.IP{127, 0, 0, 1}))
		assert.NoError(t, err)
		lookForIP(t, answer, []byte{127, 0, 0, 1})
	})

	t.Run("AAAA Record", func(t *testing.T) {
		answer, err := createAnswer(1, name, netip.MustParseAddr("::1"))
		assert.NoError(t, err)
		lookForIP(t, answer, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	})
}

func mustAddr(t *testing.T, ip net.IP) netip.Addr {
	t.Helper()
	addr, ok := netip.AddrFromSlice(ip)
	assert.True(t, ok)

	return addr
}

func TestIPToBytes(t *testing.T) { //nolint:cyclop
	expectedIP := []byte{127, 0, 0, 1}
	actualAddr4, err := ipv4ToBytes(netip.MustParseAddr("127.0.0.1"))
	assert.NoError(t, err)
	assert.Equalf(t, expectedIP, actualAddr4[:], "Expected(%v) and Actual(%v) IP don't match", expectedIP, actualAddr4)

	expectedIP = []byte{0, 0, 0, 1}
	actualAddr4, err = ipv4ToBytes(netip.MustParseAddr("0.0.0.1"))
	assert.NoError(t, err)
	assert.Equalf(t, expectedIP, actualAddr4[:], "Expected(%v) and Actual(%v) IP don't match", expectedIP, actualAddr4)

	expectedIP = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	actualAddr6, err := ipv6ToBytes(netip.MustParseAddr("::1"))
	assert.NoError(t, err)
	assert.Equalf(t, expectedIP, actualAddr6[:], "Expected(%v) and Actual(%v) IP don't match", expectedIP, actualAddr6)

	_, err = ipv4ToBytes(netip.MustParseAddr("::1"))
	assert.Error(t, err, "::1 should not be output to IPv4 bytes")

	expectedIP = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 127, 0, 0, 1}
	addr, ok := netip.AddrFromSlice(net.ParseIP("127.0.0.1"))
	assert.True(t, ok, "expected to be able to convert IP to netip.Addr")
	actualAddr6, err = ipv6ToBytes(addr)
	assert.NoError(t, err)
	assert.Equalf(t, expectedIP, actualAddr6[:], "Expected(%v) and Actual(%v) IP don't match", expectedIP, actualAddr6)
}
