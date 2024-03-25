// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// This example program showcases the use of the mDNS client by querying a previously published address
package main

import (
	"context"
	"fmt"
	"net"
	"os"

	"github.com/pion/mdns/v2"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func main() {
	var useV4, useV6 bool
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-v4only":
			useV4 = true
			useV6 = false
		case "-v6only":
			useV4 = false
			useV6 = true
		default:
			useV4 = true
			useV6 = true
		}
	} else {
		useV4 = true
		useV6 = true
	}

	var packetConnV4 *ipv4.PacketConn
	if useV4 {
		addr4, err := net.ResolveUDPAddr("udp4", mdns.DefaultAddressIPv4)
		if err != nil {
			panic(err)
		}

		l4, err := net.ListenUDP("udp4", addr4)
		if err != nil {
			panic(err)
		}

		packetConnV4 = ipv4.NewPacketConn(l4)
	}

	var packetConnV6 *ipv6.PacketConn
	if useV6 {
		addr6, err := net.ResolveUDPAddr("udp6", mdns.DefaultAddressIPv6)
		if err != nil {
			panic(err)
		}

		l6, err := net.ListenUDP("udp6", addr6)
		if err != nil {
			panic(err)
		}

		packetConnV6 = ipv6.NewPacketConn(l6)
	}

	server, err := mdns.Server(packetConnV4, packetConnV6, &mdns.Config{})
	if err != nil {
		panic(err)
	}
	answer, src, err := server.QueryAddr(context.TODO(), "pion-test.local")
	fmt.Println(answer)
	fmt.Println(src)
	fmt.Println(err)
}
