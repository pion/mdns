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
	"testing"
	"time"

	"github.com/pion/transport/v3/test"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"
)

const localAddress = "1.2.3.4"

func check(err error, t *testing.T) {
	if err != nil {
		t.Fatal(err)
	}
}

func checkIPv4(addr net.Addr, t *testing.T) {
	var ip net.IP
	switch addr := addr.(type) {
	case *net.IPNet:
		ip = addr.IP
	case *net.IPAddr:
		ip = addr.IP
	default:
		t.Fatalf("Failed to determine address type %T", addr)
	}

	if ip.To4() == nil {
		t.Fatalf("expected IPv4 for answer but got %s", ip)
	}
}

func createListener(t *testing.T) *net.UDPConn {
	addr, err := net.ResolveUDPAddr("udp", DefaultAddress)
	check(err, t)

	sock, err := net.ListenUDP("udp4", addr)
	check(err, t)

	return sock
}

func TestValidCommunication(t *testing.T) {
	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	aSock := createListener(t)
	bSock := createListener(t)

	aServer, err := Server(ipv4.NewPacketConn(aSock), &Config{
		LocalNames: []string{"pion-mdns-1.local", "pion-mdns-2.local"},
	})
	check(err, t)

	bServer, err := Server(ipv4.NewPacketConn(bSock), &Config{})
	check(err, t)

	_, addr, err := bServer.Query(context.TODO(), "pion-mdns-1.local")
	check(err, t)
	if addr.String() == localAddress {
		t.Fatalf("unexpected local address: %v", addr)
	}
	checkIPv4(addr, t)

	_, addr, err = bServer.Query(context.TODO(), "pion-mdns-2.local")
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
		_, addr, err = bServer.Query(context.TODO(), "pion-mdns-2.local")
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
}

func TestValidCommunicationWithAddressConfig(t *testing.T) {
	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	aSock := createListener(t)

	aServer, err := Server(ipv4.NewPacketConn(aSock), &Config{
		LocalNames:   []string{"pion-mdns-1.local", "pion-mdns-2.local"},
		LocalAddress: net.ParseIP(localAddress),
	})
	check(err, t)

	_, addr, err := aServer.Query(context.TODO(), "pion-mdns-1.local")
	check(err, t)
	if addr.String() != localAddress {
		t.Fatalf("address mismatch: expected %s, but got %v\n", localAddress, addr)
	}

	check(aServer.Close(), t)
}

func TestValidCommunicationWithLoopbackAddressConfig(t *testing.T) {
	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	aSock := createListener(t)

	loopbackIP := net.ParseIP("127.0.0.1")

	aServer, err := Server(ipv4.NewPacketConn(aSock), &Config{
		LocalNames:      []string{"pion-mdns-1.local", "pion-mdns-2.local"},
		LocalAddress:    loopbackIP,
		IncludeLoopback: true, // the test would fail if this was false
	})
	check(err, t)

	_, addr, err := aServer.Query(context.TODO(), "pion-mdns-1.local")
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

	aSock := createListener(t)

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

	aServer, err := Server(ipv4.NewPacketConn(aSock), &Config{
		LocalNames:      []string{"pion-mdns-1.local", "pion-mdns-2.local"},
		IncludeLoopback: true, // the test would fail if this was false
		Interfaces:      ifacesToUse,
	})
	check(err, t)

	_, addr, err := aServer.Query(context.TODO(), "pion-mdns-1.local")
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

func TestMultipleClose(t *testing.T) {
	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	aSock := createListener(t)

	server, err := Server(ipv4.NewPacketConn(aSock), &Config{})
	check(err, t)

	check(server.Close(), t)
	check(server.Close(), t)
}

func TestQueryRespectTimeout(t *testing.T) {
	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	aSock := createListener(t)

	server, err := Server(ipv4.NewPacketConn(aSock), &Config{})
	check(err, t)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	if _, _, err = server.Query(ctx, "invalid-host"); !errors.Is(err, errContextElapsed) {
		t.Fatalf("Query expired but returned unexpected error %v", err)
	}

	if closeErr := server.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
}

func TestQueryRespectClose(t *testing.T) {
	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	aSock := createListener(t)

	server, err := Server(ipv4.NewPacketConn(aSock), &Config{})
	check(err, t)

	go func() {
		time.Sleep(3 * time.Second)
		check(server.Close(), t)
	}()

	if _, _, err = server.Query(context.TODO(), "invalid-host"); !errors.Is(err, errConnectionClosed) {
		t.Fatalf("Query on closed server but returned unexpected error %v", err)
	}

	if _, _, err = server.Query(context.TODO(), "invalid-host"); !errors.Is(err, errConnectionClosed) {
		t.Fatalf("Query on closed server but returned unexpected error %v", err)
	}
}

func TestResourceParsing(t *testing.T) {
	lookForIP := func(msg dnsmessage.Message, expectedIP []byte) {
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

		actualIP, err := ipFromAnswerHeader(h, p)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(actualIP, expectedIP) {
			t.Fatalf("Expected(%v) and Actual(%v) IP don't match", expectedIP, actualIP)
		}
	}

	name := "test-server."

	t.Run("A Record", func(t *testing.T) {
		answer, err := createAnswer(name, net.ParseIP("127.0.0.1"))
		if err != nil {
			t.Fatal(err)
		}
		lookForIP(answer, []byte{127, 0, 0, 1})
	})

	t.Run("AAAA Record", func(t *testing.T) {
		answer, err := createAnswer(name, net.ParseIP("::1"))
		if err != nil {
			t.Fatal(err)
		}
		lookForIP(answer, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	})
}

func TestIPToBytes(t *testing.T) {
	expectedIP := []byte{127, 0, 0, 1}
	actualIP4, err := ipv4ToBytes(net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actualIP4[:], expectedIP) {
		t.Fatalf("Expected(%v) and Actual(%v) IP don't match", expectedIP, actualIP4)
	}

	expectedIP = []byte{0, 0, 0, 1}
	actualIP4, err = ipv4ToBytes(net.ParseIP("0.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actualIP4[:], expectedIP) {
		t.Fatalf("Expected(%v) and Actual(%v) IP don't match", expectedIP, actualIP4)
	}

	expectedIP = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	actualIP6, err := ipv6ToBytes(net.ParseIP("::1"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actualIP6[:], expectedIP) {
		t.Fatalf("Expected(%v) and Actual(%v) IP don't match", expectedIP, actualIP6)
	}

	_, err = ipv4ToBytes(net.ParseIP("::1"))
	if err == nil {
		t.Fatal("expected ::1 to not be output to IPv4 bytes")
	}

	expectedIP = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 127, 0, 0, 1}
	actualIP6, err = ipv6ToBytes(net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actualIP6[:], expectedIP) {
		t.Fatalf("Expected(%v) and Actual(%v) IP don't match", expectedIP, actualIP6)
	}
}
