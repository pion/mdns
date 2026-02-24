// SPDX-FileCopyrightText: The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build e2e

// Package main implements end-to-end integration tests for pion/mdns against
// avahi-daemon running in a Docker container. It is a standalone binary
// (not go test) that exits 0 on success and 1 on failure.
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pion/mdns/v2"
	"golang.org/x/net/ipv4"
)

const testTimeout = 30 * time.Second

func main() {
	tests := []struct {
		name string
		fn   func() error
	}{
		{"QueryAddr", testQueryAddr},
		{"Browse", testBrowse},
		{"EnumerateServiceTypes", testEnumerateServiceTypes},
		{"Reverse", testReverse},
	}

	failed := false
	for _, tt := range tests {
		fmt.Printf("=== RUN   %s\n", tt.name)
		if err := tt.fn(); err != nil {
			fmt.Printf("--- FAIL: %s (%v)\n", tt.name, err)
			failed = true
		} else {
			fmt.Printf("--- PASS: %s\n", tt.name)
		}
	}

	if failed {
		fmt.Println("FAIL")
		os.Exit(1)
	}
	fmt.Println("PASS")
}

// newConn creates a new mDNS Conn with IPv4 multicast only.
func newConn(opts ...mdns.ServerOption) (*mdns.Conn, error) {
	addr, err := net.ResolveUDPAddr("udp4", mdns.DefaultAddressIPv4)
	if err != nil {
		return nil, fmt.Errorf("resolve udp4: %w", err)
	}

	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return nil, fmt.Errorf("listen udp4: %w", err)
	}

	return mdns.NewServer(ipv4.NewPacketConn(conn), nil, opts...)
}

// testQueryAddr resolves avahi-test.local and verifies we get an IP back.
func testQueryAddr() error {
	conn, err := newConn()
	if err != nil {
		return fmt.Errorf("newConn: %w", err)
	}
	defer conn.Close() //nolint:errcheck

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	_, addr, err := conn.QueryAddr(ctx, "avahi-test.local")
	if err != nil {
		return fmt.Errorf("QueryAddr: %w", err)
	}

	if !addr.IsValid() {
		return fmt.Errorf("QueryAddr returned invalid address")
	}

	fmt.Printf("    resolved avahi-test.local -> %s\n", addr)

	return nil
}

// testBrowse discovers avahi's _http._tcp service and verifies instance details.
func testBrowse() error {
	conn, err := newConn()
	if err != nil {
		return fmt.Errorf("newConn: %w", err)
	}
	defer conn.Close() //nolint:errcheck

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	var (
		found bool
		mu    sync.Mutex
		done  = make(chan struct{})
	)

	conn.OnServiceDiscovered(func(evt mdns.ServiceEvent) {
		mu.Lock()
		defer mu.Unlock()
		if found {
			return
		}

		inst := evt.Instance
		fmt.Printf("    discovered: %q service=%s port=%d host=%s addr=%s\n",
			inst.Instance, inst.Service, inst.Port, inst.Host, evt.Addr)

		if inst.Service != "_http._tcp" {
			return
		}

		if inst.Instance != "Avahi Test Web Server" {
			return
		}

		if inst.Port != 8080 {
			return
		}

		found = true
		close(done)
	})

	if err := conn.Browse(ctx, "_http._tcp"); err != nil {
		return fmt.Errorf("Browse: %w", err)
	}

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("timed out waiting for _http._tcp service discovery")
	}
}

// testEnumerateServiceTypes discovers service types and expects _http._tcp.
func testEnumerateServiceTypes() error {
	conn, err := newConn()
	if err != nil {
		return fmt.Errorf("newConn: %w", err)
	}
	defer conn.Close() //nolint:errcheck

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	var (
		found bool
		mu    sync.Mutex
		done  = make(chan struct{})
	)

	conn.OnServiceTypeDiscovered(func(serviceType string) {
		mu.Lock()
		defer mu.Unlock()
		if found {
			return
		}

		fmt.Printf("    service type: %s\n", serviceType)
		if serviceType == "_http._tcp" {
			found = true
			close(done)
		}
	})

	if err := conn.EnumerateServiceTypes(ctx); err != nil {
		return fmt.Errorf("EnumerateServiceTypes: %w", err)
	}

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("timed out waiting for _http._tcp enumeration")
	}
}

// testReverse advertises a pion service and uses avahi-browse (via HTTP CGI on
// the avahi container) to confirm the service is visible to a third-party.
func testReverse() error {
	conn, err := newConn(
		mdns.WithLocalNames("pion-e2e.local"),
		mdns.WithService(mdns.ServiceInstance{
			Instance: "Pion E2E Test",
			Service:  "_pion-test._tcp",
			Port:     9999,
		}),
	)
	if err != nil {
		return fmt.Errorf("newConn: %w", err)
	}
	defer conn.Close() //nolint:errcheck

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	// Retry until avahi-browse on the avahi container sees our service.
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		out, err := avahiBrowseHTTP(ctx, "_pion-test._tcp")
		if err == nil && strings.Contains(out, "+;") && strings.Contains(out, "_pion-test._tcp") {
			fmt.Printf("    avahi-browse saw: %s\n", strings.TrimSpace(out))

			return nil
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for avahi-browse to see _pion-test._tcp (last output: %q, last err: %v)", out, err)
		case <-ticker.C:
		}
	}
}

// avahiBrowseHTTP calls the CGI endpoint on the avahi container to run
// avahi-browse and returns the output.
func avahiBrowseHTTP(ctx context.Context, serviceType string) (string, error) {
	url := "http://avahi:8080/cgi-bin/browse?" + serviceType
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("new request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("http get: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read body: %w", err)
	}

	return string(body), nil
}
