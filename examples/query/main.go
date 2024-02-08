// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// This example program showcases the use of the mDNS client by querying a previously published address
package main

import (
	"context"
	"fmt"
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

	server, err := mdns.Server(ipv4.NewPacketConn(l4), ipv6.NewPacketConn(l6), &mdns.Config{})
	if err != nil {
		panic(err)
	}
	answer, src, err := server.Query(context.TODO(), "pion-test.local")
	fmt.Println(answer)
	fmt.Println(src)
	fmt.Println(err)
}
