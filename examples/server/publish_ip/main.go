// This example program allows to set an IP that deviates from the automatically determined interface address.
// Use the "-ip" parameter to set an IP. If not set, the example server defaults to "1.2.3.4".
package main

import (
	"flag"
	"net"

	"github.com/pion/mdns"
	"golang.org/x/net/ipv4"
)

func main() {
	ip := flag.String("ip", "1.2.3.4", "IP address to be published")
	flag.Parse()

	addr, err := net.ResolveUDPAddr("udp", mdns.DefaultAddress)
	if err != nil {
		panic(err)
	}

	l, err := net.ListenUDP("udp4", addr)
	if err != nil {
		panic(err)
	}

	_, err = mdns.Server(ipv4.NewPacketConn(l), &mdns.Config{
		LocalNames:   []string{"pion-test.local"},
		LocalAddress: net.ParseIP(*ip),
	})
	if err != nil {
		panic(err)
	}
	select {}
}
