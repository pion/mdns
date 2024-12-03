// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js
// +build !js

package mdns

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/pion/transport/v3/test"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const localAddress = "1.2.3.4"

func check(err error, t *testing.T) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func checkIPv4(addr netip.Addr, t *testing.T) {
	t.Helper()
	if !addr.Is4() {
		t.Fatalf("expected IPv4 for answer but got %s", addr)
	}
}

func checkIPv6(addr netip.Addr, t *testing.T) {
	t.Helper()
	if !addr.Is6() {
		t.Fatalf("expected IPv6 for answer but got %s", addr)
	}
}

func createListener4(t *testing.T) *net.UDPConn {
	addr, err := net.ResolveUDPAddr("udp", DefaultAddressIPv4)
	check(err, t)

	sock, err := net.ListenUDP("udp4", addr)
	check(err, t)

	return sock
}

func createListener6(t *testing.T) *net.UDPConn {
	addr, err := net.ResolveUDPAddr("udp", DefaultAddressIPv6)
	check(err, t)

	sock, err := net.ListenUDP("udp6", addr)
	check(err, t)

	return sock
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
	check(err, t)

	bServer, err := Server(ipv4.NewPacketConn(bSock), nil, &Config{})
	check(err, t)

	_, addr, err := bServer.QueryAddr(context.TODO(), "pion-mdns-1.local")
	check(err, t)
	if addr.String() == localAddress {
		t.Fatalf("unexpected local address: %v", addr)
	}
	checkIPv4(addr, t)

	_, addr, err = bServer.QueryAddr(context.TODO(), "pion-mdns-2.local")
	check(err, t)
	if addr.String() == localAddress {
		t.Fatalf("unexpected local address: %v", addr)
	}
	checkIPv4(addr, t)

	// test against regression from https://github.com/pion/mdns/commit/608f20b
	// where by properly sending mDNS responses to all interfaces, we significantly
	// increased the chance that we send a loopback response to a Query that is
	// unwillingly to use loopback addresses (the default in pion/ice).
	for i := 0; i < 100; i++ {
		_, addr, err = bServer.QueryAddr(context.TODO(), "pion-mdns-2.local")
		check(err, t)
		if addr.String() == localAddress {
			t.Fatalf("unexpected local address: %v", addr)
		}
		if addr.String() == "127.0.0.1" {
			t.Fatal("unexpected loopback")
		}
		checkIPv4(addr, t)
	}

	check(aServer.Close(), t)
	check(bServer.Close(), t)

	if len(aServer.queries) > 0 {
		t.Fatalf("Queries not cleaned up after aServer close")
	}
	if len(bServer.queries) > 0 {
		t.Fatalf("Queries not cleaned up after bServer close")
	}
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
	check(err, t)

	_, addr, err := aServer.QueryAddr(context.TODO(), "pion-mdns-1.local")
	check(err, t)
	if addr.String() != localAddress {
		t.Fatalf("address mismatch: expected %s, but got %v\n", localAddress, addr)
	}

	check(aServer.Close(), t)
	if len(aServer.queries) > 0 {
		t.Fatalf("Queries not cleaned up after aServer close")
	}
}

func TestValidCommunicationWithLoopbackAddressConfig(t *testing.T) {
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
	check(err, t)

	_, addr, err := aServer.QueryAddr(context.TODO(), "pion-mdns-1.local")
	check(err, t)
	if addr.String() != loopbackIP.String() {
		t.Fatalf("address mismatch: expected %s, but got %v\n", localAddress, addr)
	}

	check(aServer.Close(), t)
}

func TestValidCommunicationWithLoopbackInterface(t *testing.T) {
	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	aSock := createListener4(t)

	ifaces, err := net.Interfaces()
	check(err, t)
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
	check(err, t)

	_, addr, err := aServer.QueryAddr(context.TODO(), "pion-mdns-1.local")
	check(err, t)
	var found bool
	for _, iface := range ifacesToUse {
		addrs, err := iface.Addrs()
		check(err, t)
		for _, ifaceAddr := range addrs {
			ipAddr, ok := ifaceAddr.(*net.IPNet)
			if !ok {
				t.Fatalf("expected *net.IPNet address for loopback but got %T", addr)
			}
			if addr.String() == ipAddr.IP.String() {
				found = true
				break
			}
		}
		if found {
			break
		}
	}
	if !found {
		t.Fatalf("address mismatch: expected loopback address, but got %v\n", addr)
	}

	check(aServer.Close(), t)
}

func TestValidCommunicationIPv6(t *testing.T) {
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
	if !errors.Is(err, errNoPacketConn) {
		t.Fatalf("expected error if no PacketConn supplied to Server; got %v", err)
	}

	aSock := createListener6(t)
	bSock := createListener6(t)

	aServer, err := Server(nil, ipv6.NewPacketConn(aSock), &Config{
		LocalNames: []string{"pion-mdns-1.local", "pion-mdns-2.local"},
	})
	check(err, t)

	bServer, err := Server(nil, ipv6.NewPacketConn(bSock), &Config{})
	check(err, t)

	header, addr, err := bServer.QueryAddr(context.TODO(), "pion-mdns-1.local")
	check(err, t)
	if header.Type != dnsmessage.TypeAAAA {
		t.Fatalf("expected AAAA but got %s", header.Type)
	}

	if addr.String() == localAddress {
		t.Fatalf("unexpected local address: %v", addr)
	}
	checkIPv6(addr, t)
	if addr.Is4In6() {
		// probably within docker
		t.Logf("address %s is an IPv4-to-IPv6 mapped address even though the stack is IPv6", addr)
	}
	if !addr.Is4In6() && addr.Zone() == "" {
		t.Fatalf("expected IPv6 to have zone but got %s", addr)
	}

	header, addr, err = bServer.QueryAddr(context.TODO(), "pion-mdns-2.local")
	check(err, t)
	if header.Type != dnsmessage.TypeAAAA {
		t.Fatalf("expected AAAA but got %s", header.Type)
	}

	if addr.String() == localAddress {
		t.Fatalf("unexpected local address: %v", addr)
	}
	checkIPv6(addr, t)
	if !addr.Is4In6() && addr.Zone() == "" {
		t.Fatalf("expected IPv6 to have zone but got %s", addr)
	}

	check(aServer.Close(), t)
	check(bServer.Close(), t)

	if len(aServer.queries) > 0 {
		t.Fatalf("Queries not cleaned up after aServer close")
	}
	if len(bServer.queries) > 0 {
		t.Fatalf("Queries not cleaned up after bServer close")
	}
}

func TestValidCommunicationIPv46(t *testing.T) {
	if runtime.GOARCH == "386" {
		t.Skip("IPv6 not supported on 386 for some reason")
	}

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
	check(err, t)

	bServer, err := Server(ipv4.NewPacketConn(bSock4), ipv6.NewPacketConn(bSock6), &Config{})
	check(err, t)

	_, addr, err := bServer.QueryAddr(context.TODO(), "pion-mdns-1.local")
	check(err, t)

	if addr.String() == localAddress {
		t.Fatalf("unexpected local address: %v", addr)
	}

	_, addr, err = bServer.QueryAddr(context.TODO(), "pion-mdns-2.local")
	check(err, t)
	if addr.String() == localAddress {
		t.Fatalf("unexpected local address: %v", addr)
	}

	check(aServer.Close(), t)
	check(bServer.Close(), t)

	if len(aServer.queries) > 0 {
		t.Fatalf("Queries not cleaned up after aServer close")
	}
	if len(bServer.queries) > 0 {
		t.Fatalf("Queries not cleaned up after bServer close")
	}
}

func TestValidCommunicationIPv46Mixed(t *testing.T) {
	if runtime.GOARCH == "386" {
		t.Skip("IPv6 not supported on 386 for some reason")
	}

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
	aServer, err := Server(ipv4.NewPacketConn(aSock4), nil, &Config{
		Name: "aServer",
	})
	check(err, t)

	bServer, err := Server(nil, ipv6.NewPacketConn(bSock6), &Config{
		Name:       "bServer",
		LocalNames: []string{"pion-mdns-1.local"},
	})
	check(err, t)

	header, addr, err := aServer.QueryAddr(context.TODO(), "pion-mdns-1.local")

	check(err, t)
	if header.Type != dnsmessage.TypeA {
		t.Fatalf("expected A but got %s", header.Type)
	}
	checkIPv4(addr, t)

	check(aServer.Close(), t)
	check(bServer.Close(), t)

	if len(aServer.queries) > 0 {
		t.Fatalf("Queries not cleaned up after aServer close")
	}
	if len(bServer.queries) > 0 {
		t.Fatalf("Queries not cleaned up after bServer close")
	}
}

func TestValidCommunicationIPv46MixedLocalAddress(t *testing.T) {
	if runtime.GOARCH == "386" {
		t.Skip("IPv6 not supported on 386 for some reason")
	}

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
	check(err, t)

	bServer, err := Server(nil, ipv6.NewPacketConn(bSock6), &Config{})
	check(err, t)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// we want ipv6 but all we can offer is an ipv4 mapped address, so it should fail until we support
	// allowing this explicitly via configuration on the aServer side
	if _, _, err := bServer.QueryAddr(ctx, "pion-mdns-1.local"); !errors.Is(err, errContextElapsed) {
		t.Fatalf("Query expired but returned unexpected error %v", err)
	}

	check(aServer.Close(), t)
	check(bServer.Close(), t)

	if len(aServer.queries) > 0 {
		t.Fatalf("Queries not cleaned up after aServer close")
	}
	if len(bServer.queries) > 0 {
		t.Fatalf("Queries not cleaned up after bServer close")
	}
}

func TestValidCommunicationIPv66Mixed(t *testing.T) {
	if runtime.GOARCH == "386" {
		t.Skip("IPv6 not supported on 386 for some reason")
	}

	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	aSock6 := createListener6(t)
	bSock6 := createListener6(t)

	aServer, err := Server(nil, ipv6.NewPacketConn(aSock6), &Config{
		LocalNames: []string{"pion-mdns-1.local"},
	})
	check(err, t)

	bServer, err := Server(nil, ipv6.NewPacketConn(bSock6), &Config{})
	check(err, t)

	header, addr, err := bServer.QueryAddr(context.TODO(), "pion-mdns-1.local")
	check(err, t)
	if header.Type != dnsmessage.TypeAAAA {
		t.Fatalf("expected AAAA but got %s", header.Type)
	}
	if addr.String() == localAddress {
		t.Fatalf("unexpected local address: %v", addr)
	}
	if addr.Is4In6() {
		t.Fatalf("expected address to not be ipv4-to-ipv6 mapped: %v", addr)
	}
	checkIPv6(addr, t)

	check(aServer.Close(), t)
	check(bServer.Close(), t)

	if len(aServer.queries) > 0 {
		t.Fatalf("Queries not cleaned up after aServer close")
	}
	if len(bServer.queries) > 0 {
		t.Fatalf("Queries not cleaned up after bServer close")
	}
}

func TestValidCommunicationIPv66MixedLocalAddress(t *testing.T) {
	if runtime.GOARCH == "386" {
		t.Skip("IPv6 not supported on 386 for some reason")
	}

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
	check(err, t)

	bServer, err := Server(nil, ipv6.NewPacketConn(bSock6), &Config{})
	check(err, t)

	header, addr, err := bServer.QueryAddr(context.TODO(), "pion-mdns-1.local")
	check(err, t)
	if header.Type != dnsmessage.TypeAAAA {
		t.Fatalf("expected AAAA but got %s", header.Type)
	}
	if !addr.Is4In6() {
		t.Fatalf("expected address to be ipv4-to-ipv6 mapped: %v", addr)
	}
	// now unmap just for this check
	if addr.Unmap().String() != localAddress {
		t.Fatalf("unexpected local address: %v", addr)
	}
	checkIPv6(addr, t)

	check(aServer.Close(), t)
	check(bServer.Close(), t)

	if len(aServer.queries) > 0 {
		t.Fatalf("Queries not cleaned up after aServer close")
	}
	if len(bServer.queries) > 0 {
		t.Fatalf("Queries not cleaned up after bServer close")
	}
}

func TestValidCommunicationIPv64Mixed(t *testing.T) {
	if runtime.GOARCH == "386" {
		t.Skip("IPv6 not supported on 386 for some reason")
	}

	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	aSock6 := createListener6(t)
	bSock4 := createListener4(t)

	aServer, err := Server(nil, ipv6.NewPacketConn(aSock6), &Config{
		LocalNames: []string{"pion-mdns-1.local", "pion-mdns-2.local"},
	})
	check(err, t)

	bServer, err := Server(ipv4.NewPacketConn(bSock4), nil, &Config{})
	check(err, t)

	_, addr, err := bServer.QueryAddr(context.TODO(), "pion-mdns-1.local")
	check(err, t)

	if addr.String() == localAddress {
		t.Fatalf("unexpected local address: %v", addr)
	}

	header, addr, err := bServer.QueryAddr(context.TODO(), "pion-mdns-2.local")
	check(err, t)
	if header.Type != dnsmessage.TypeA {
		t.Fatalf("expected A but got %s", header.Type)
	}
	if addr.String() == localAddress {
		t.Fatalf("unexpected local address: %v", addr)
	}

	check(aServer.Close(), t)
	check(bServer.Close(), t)

	if len(aServer.queries) > 0 {
		t.Fatalf("Queries not cleaned up after aServer close")
	}
	if len(bServer.queries) > 0 {
		t.Fatalf("Queries not cleaned up after bServer close")
	}
}

func TestMultipleClose(t *testing.T) {
	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	aSock := createListener4(t)

	server, err := Server(ipv4.NewPacketConn(aSock), nil, &Config{})
	check(err, t)

	check(server.Close(), t)
	check(server.Close(), t)

	if len(server.queries) > 0 {
		t.Fatalf("Queries not cleaned up after server close")
	}
}

func TestQueryRespectTimeout(t *testing.T) {
	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	aSock := createListener4(t)

	server, err := Server(ipv4.NewPacketConn(aSock), nil, &Config{})
	check(err, t)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	if _, _, err = server.QueryAddr(ctx, "invalid-host"); !errors.Is(err, errContextElapsed) {
		t.Fatalf("Query expired but returned unexpected error %v", err)
	}

	if closeErr := server.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}

	if len(server.queries) > 0 {
		t.Fatalf("Queries not cleaned up after context expiration")
	}
}

func TestQueryRespectClose(t *testing.T) {
	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	aSock := createListener4(t)

	server, err := Server(ipv4.NewPacketConn(aSock), nil, &Config{})
	check(err, t)

	go func() {
		time.Sleep(3 * time.Second)
		check(server.Close(), t)
	}()

	if _, _, err = server.QueryAddr(context.TODO(), "invalid-host"); !errors.Is(err, errConnectionClosed) {
		t.Fatalf("Query on closed server but returned unexpected error %v", err)
	}

	if _, _, err = server.QueryAddr(context.TODO(), "invalid-host"); !errors.Is(err, errConnectionClosed) {
		t.Fatalf("Query on closed server but returned unexpected error %v", err)
	}

	if len(server.queries) > 0 {
		t.Fatalf("Queries not cleaned up after query")
	}
}

func TestResourceParsing(t *testing.T) {
	lookForIP := func(msg dnsmessage.Message, expectedIP []byte, t *testing.T) {
		buf, err := msg.Pack()
		if err != nil {
			t.Fatal(err)
		}

		var p dnsmessage.Parser
		if _, err = p.Start(buf); err != nil {
			t.Fatal(err)
		}

		if err = p.SkipAllQuestions(); err != nil {
			t.Fatal(err)
		}

		h, err := p.AnswerHeader()
		if err != nil {
			t.Fatal(err)
		}

		actualAddr, err := addrFromAnswerHeader(h, p)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(actualAddr.AsSlice(), expectedIP) {
			t.Fatalf("Expected(%v) and Actual(%v) IP don't match", expectedIP, actualAddr)
		}
	}

	name := "test-server."
	q := dnsmessage.Question{Name: dnsmessage.MustNewName(name)}

	t.Run("A Record", func(t *testing.T) {
		answer, err := createAnswer(1, q, mustAddr(net.IP{127, 0, 0, 1}))
		if err != nil {
			t.Fatal(err)
		}
		lookForIP(answer, []byte{127, 0, 0, 1}, t)
	})

	t.Run("AAAA Record", func(t *testing.T) {
		answer, err := createAnswer(1, q, netip.MustParseAddr("::1"))
		if err != nil {
			t.Fatal(err)
		}
		lookForIP(answer, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, t)
	})
}

func mustAddr(ip net.IP) netip.Addr {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		panic(ipToAddrError{ip})
	}
	return addr
}

func TestIPToBytes(t *testing.T) {
	expectedIP := []byte{127, 0, 0, 1}
	actualAddr4, err := ipv4ToBytes(netip.MustParseAddr("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actualAddr4[:], expectedIP) {
		t.Fatalf("Expected(%v) and Actual(%v) IP don't match", expectedIP, actualAddr4)
	}

	expectedIP = []byte{0, 0, 0, 1}
	actualAddr4, err = ipv4ToBytes(netip.MustParseAddr("0.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actualAddr4[:], expectedIP) {
		t.Fatalf("Expected(%v) and Actual(%v) IP don't match", expectedIP, actualAddr4)
	}

	expectedIP = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	actualAddr6, err := ipv6ToBytes(netip.MustParseAddr("::1"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actualAddr6[:], expectedIP) {
		t.Fatalf("Expected(%v) and Actual(%v) IP don't match", expectedIP, actualAddr6)
	}

	_, err = ipv4ToBytes(netip.MustParseAddr("::1"))
	if err == nil {
		t.Fatal("expected ::1 to not be output to IPv4 bytes")
	}

	expectedIP = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 127, 0, 0, 1}
	addr, ok := netip.AddrFromSlice(net.ParseIP("127.0.0.1"))
	if !ok {
		t.Fatal("expected to be able to convert IP to netip.Addr")
	}
	actualAddr6, err = ipv6ToBytes(addr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actualAddr6[:], expectedIP) {
		t.Fatalf("Expected(%v) and Actual(%v) IP don't match", expectedIP, actualAddr6)
	}
}
