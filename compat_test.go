// SPDX-FileCopyrightText: The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package mdns

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/pion/transport/v4/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"
)

// These tests pin the backward-compatibility contract of the legacy
// Server constructor (the options bridge introduced in PR #255).
// Code written against the pre-options API must keep working unchanged:
// the legacy constructor opts out of newer behavior that could surprise
// it. NewServer, by contrast, gets full behavior by default.
//
// Legacy defaults pinned here:
//   - only A/AAAA records are processed (WebRTC/ICE focus)
//   - no proactive cache refresh (RFC 6762 §5.2)
//   - only ServiceAdded events are delivered (no ServiceRemoved)

func newLegacyServer(t *testing.T, cfg *Config) *Conn {
	t.Helper()

	sock := createListener4(t)
	conn, err := Server(ipv4.NewPacketConn(sock), nil, cfg)
	require.NoError(t, err)

	return conn
}

func TestLegacyServerDefaults(t *testing.T) {
	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	conn := newLegacyServer(t, &Config{})

	assert.Equal(t,
		[]dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA},
		conn.server.handler.allowedRecordTypes,
		"legacy Server must only process A/AAAA records")
	assert.False(t, conn.cacheRefresh,
		"legacy Server must not enable proactive cache refresh")
	assert.Equal(t, []ServiceEventType{ServiceAdded}, conn.serviceEventTypes,
		"legacy Server must only deliver ServiceAdded events")

	assert.NoError(t, conn.Close())
}

func TestLegacyServerFiltersServiceRemoved(t *testing.T) {
	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	conn := newLegacyServer(t, &Config{})

	var received []ServiceEvent
	conn.OnServiceDiscovered(func(evt ServiceEvent) {
		received = append(received, evt)
	})

	added := ServiceEvent{
		Type: ServiceAdded,
		Instance: ServiceInstance{
			Instance: "My Web", Service: "_http._tcp", Domain: "local",
			Host: "myhost.local.", Port: 8080,
		},
		Addr: netip.MustParseAddr("192.168.1.100"),
	}
	removed := added
	removed.Type = ServiceRemoved

	conn.serviceEventHandler(added)
	conn.serviceEventHandler(removed)

	// Pre-removal-events code only ever saw discoveries; the legacy
	// constructor preserves that: the removal is silently dropped.
	require.Len(t, received, 1)
	assert.Equal(t, ServiceAdded, received[0].Type)

	assert.NoError(t, conn.Close())
}

func TestNewServerDeliversAllServiceEvents(t *testing.T) {
	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	sock := createListener4(t)
	conn, err := NewServer(ipv4.NewPacketConn(sock), nil)
	require.NoError(t, err)

	var received []ServiceEvent
	conn.OnServiceEvent(func(evt ServiceEvent) {
		received = append(received, evt)
	})

	conn.serviceEventHandler(ServiceEvent{Type: ServiceAdded})
	conn.serviceEventHandler(ServiceEvent{Type: ServiceRemoved})

	require.Len(t, received, 2)
	assert.Equal(t, ServiceAdded, received[0].Type)
	assert.Equal(t, ServiceRemoved, received[1].Type)

	assert.NoError(t, conn.Close())
}

func TestNewServerWithServiceEventTypesOptIn(t *testing.T) {
	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	// NewServer users can opt into the legacy adds-only behavior.
	sock := createListener4(t)
	conn, err := NewServer(ipv4.NewPacketConn(sock), nil,
		WithServiceEventTypes(ServiceAdded))
	require.NoError(t, err)

	var received []ServiceEvent
	conn.OnServiceEvent(func(evt ServiceEvent) {
		received = append(received, evt)
	})

	conn.serviceEventHandler(ServiceEvent{Type: ServiceAdded})
	conn.serviceEventHandler(ServiceEvent{Type: ServiceRemoved})

	require.Len(t, received, 1)
	assert.Equal(t, ServiceAdded, received[0].Type)

	assert.NoError(t, conn.Close())
}

func TestLegacyServerConfigMapping(t *testing.T) {
	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	conn := newLegacyServer(t, &Config{
		Name:          "legacy-name",
		QueryInterval: 250 * time.Millisecond,
		LocalNames:    []string{"legacy-host.local"},
		LocalAddress:  net.ParseIP("192.0.2.10"),
	})

	assert.Equal(t, "legacy-name", conn.name)
	assert.Equal(t, 250*time.Millisecond, conn.queryInterval)
	assert.Equal(t, []string{"legacy-host.local."}, conn.localNames,
		"local names should be normalized with a trailing dot")

	assert.NoError(t, conn.Close())
}
