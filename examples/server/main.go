package main

import (
	"net"

	"github.com/pion/mdns"
)

func main() {
	addr, err := net.ResolveUDPAddr("udp", mdns.DefaultAddress)
	if err != nil {
		panic(err)
	}

	l, err := net.ListenMulticastUDP("udp", nil, addr)
	if err != nil {
		panic(err)
	}

	_, err = mdns.Server(l, &mdns.Config{
		LocalNames: []string{"pion-test.local"},
	})
	if err != nil {
		panic(err)
	}
	select {}
}
