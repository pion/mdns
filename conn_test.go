package mdns

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/pion/transport/test"
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
		LocalNames: []string{"pion-mdns-1.local.", "pion-mdns-2.local."},
	})
	check(err, t)

	bServer, err := Server(ipv4.NewPacketConn(bSock), &Config{})
	check(err, t)

	_, _, err = bServer.Query(context.TODO(), "pion-mdns-1.local.")
	check(err, t)

	_, _, err = bServer.Query(context.TODO(), "pion-mdns-2.local.")
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

	if _, _, err = server.Query(ctx, "invalid-host."); err != errContextElapsed {
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

	if _, _, err = server.Query(context.TODO(), "invalid-host."); err != errConnectionClosed {
		t.Fatalf("Query on closed server but returned unexpected error %v", err)
	}

	if _, _, err = server.Query(context.TODO(), "invalid-host."); err != errConnectionClosed {
		t.Fatalf("Query on closed server but returned unexpected error %v", err)
	}
}
