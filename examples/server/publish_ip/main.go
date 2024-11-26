// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// This example program allows to set an IP that deviates from the automatically determined interface address.
// Use the "-ip" parameter to set an IP. If not set, the example server defaults to "1.2.3.4".
package main

import (
	"flag"
	"net"

	"github.com/pion/mdns/v2"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func main() {
	ip := flag.String("ip", "1.2.3.4", "IP address to be published")
	flag.Parse()

	addr4, err := net.ResolveUDPAddr("udp4", mdns.DefaultAddressIPv4)
	if err != nil {
		panic(err)
	}

	addr6, err := net.ResolveUDPAddr("udp6", mdns.DefaultAddressIPv6)
	if err != nil {
		panic(err)
	}

	l4, err := net.ListenUDP("udp4", addr4)
	if err != nil {
		panic(err)
	}

	l6, err := net.ListenUDP("udp6", addr6)
	if err != nil {
		panic(err)
	}

	_, err = mdns.Server(ipv4.NewPacketConn(l4), ipv6.NewPacketConn(l6), &mdns.Config{
		LocalNames:   []string{"pion-test.local"},
		LocalAddress: net.ParseIP(*ip),
	})
	if err != nil {
		panic(err)
	}
	select {}
}
