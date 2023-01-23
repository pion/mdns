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

	"github.com/pion/transport/v2/test"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"
)

func check(err error, t *testing.T) {
	if err != nil {
		t.Fatal(err)
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

	_, _, err = bServer.Query(context.TODO(), "pion-mdns-1.local")
	check(err, t)

	_, _, err = bServer.Query(context.TODO(), "pion-mdns-2.local")
	check(err, t)

	check(aServer.Close(), t)
	check(bServer.Close(), t)
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

	name, err := dnsmessage.NewName("test-server.")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("A Record", func(t *testing.T) {
		lookForIP(dnsmessage.Message{
			Header: dnsmessage.Header{Response: true, Authoritative: true},
			Answers: []dnsmessage.Resource{
				{
					Header: dnsmessage.ResourceHeader{
						Name:  name,
						Type:  dnsmessage.TypeA,
						Class: dnsmessage.ClassINET,
					},
					Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}},
				},
			},
		}, []byte{127, 0, 0, 1})
	})

	t.Run("AAAA Record", func(t *testing.T) {
		lookForIP(dnsmessage.Message{
			Header: dnsmessage.Header{Response: true, Authoritative: true},
			Answers: []dnsmessage.Resource{
				{
					Header: dnsmessage.ResourceHeader{
						Name:  name,
						Type:  dnsmessage.TypeAAAA,
						Class: dnsmessage.ClassINET,
					},
					Body: &dnsmessage.AAAAResource{AAAA: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
				},
			},
		}, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	})
}
