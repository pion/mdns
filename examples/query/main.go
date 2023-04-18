// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// This example program showcases the use of the mDNS client by querying a previously published address
package main

import (
	"context"
	"fmt"
	"net"

	"github.com/pion/mdns"
	"golang.org/x/net/ipv4"
)

func main() {
	addr, err := net.ResolveUDPAddr("udp", mdns.DefaultAddress)
	if err != nil {
		panic(err)
	}

	l, err := net.ListenUDP("udp4", addr)
	if err != nil {
		panic(err)
	}

	server, err := mdns.Server(ipv4.NewPacketConn(l), &mdns.Config{})
	if err != nil {
		panic(err)
	}
	answer, src, err := server.Query(context.TODO(), "pion-test.local")
	fmt.Println(answer)
	fmt.Println(src)
	fmt.Println(err)
}
