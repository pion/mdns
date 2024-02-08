// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// This example program showcases the use of the mDNS server by publishing "pion-test.local"
package main

import (
	"net"

	"github.com/pion/mdns/v2"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func main() {
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
		LocalNames: []string{"pion-test.local"},
	})
	if err != nil {
		panic(err)
	}
	select {}
}
