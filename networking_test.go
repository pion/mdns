// SPDX-FileCopyrightText: The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package mdns

import (
	"net"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/transport/v3/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func TestConfigurePacketConn4Nil(t *testing.T) {
	log := logging.NewDefaultLoggerFactory().NewLogger("mdns")
	result := configurePacketConn4(nil, "test", "multicast", log)
	assert.Nil(t, result)
}

func TestConfigurePacketConn6Nil(t *testing.T) {
	log := logging.NewDefaultLoggerFactory().NewLogger("mdns")
	result := configurePacketConn6(nil, "test", "multicast", log)
	assert.Nil(t, result)
}

func TestEnableLoopback4Nil(t *testing.T) {
	log := logging.NewDefaultLoggerFactory().NewLogger("mdns")
	// Should not panic when called with nil
	enableLoopback4(nil, "test", "multicast", log)
}

func TestEnableLoopback6Nil(t *testing.T) {
	log := logging.NewDefaultLoggerFactory().NewLogger("mdns")
	// Should not panic when called with nil
	enableLoopback6(nil, "test", "multicast", log)
}

func TestConfigurePacketConn4WithConn(t *testing.T) {
	sock := createListener4(t)
	defer func() { _ = sock.Close() }()

	log := logging.NewDefaultLoggerFactory().NewLogger("mdns")
	pc := ipv4.NewPacketConn(sock)
	result := configurePacketConn4(pc, "test", "multicast", log)
	assert.NotNil(t, result)
}

func TestConfigurePacketConn6WithConn(t *testing.T) {
	sock := createListener6(t)
	defer func() { _ = sock.Close() }()

	log := logging.NewDefaultLoggerFactory().NewLogger("mdns")
	pc := ipv6.NewPacketConn(sock)
	result := configurePacketConn6(pc, "test", "multicast", log)
	assert.NotNil(t, result)
}

func TestEnableLoopback4WithConn(t *testing.T) {
	sock := createListener4(t)
	defer func() { _ = sock.Close() }()

	log := logging.NewDefaultLoggerFactory().NewLogger("mdns")
	pc := ipv4.NewPacketConn(sock)
	// Should not panic
	enableLoopback4(pc, "test", "multicast", log)
}

func TestEnableLoopback6WithConn(t *testing.T) {
	sock := createListener6(t)
	defer func() { _ = sock.Close() }()

	log := logging.NewDefaultLoggerFactory().NewLogger("mdns")
	pc := ipv6.NewPacketConn(sock)
	// Should not panic
	enableLoopback6(pc, "test", "multicast", log)
}

func TestIPPacketConn4RoundTrip(t *testing.T) {
	lim := test.TimeOut(time.Second * 5)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	// Create sender socket bound to ephemeral port.
	senderAddr, err := net.ResolveUDPAddr("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	senderSock, err := net.ListenUDP("udp4", senderAddr)
	require.NoError(t, err)
	defer func() { _ = senderSock.Close() }()

	// Create receiver socket bound to ephemeral port.
	receiverAddr, err := net.ResolveUDPAddr("udp4", "127.0.0.1:0")
	require.NoError(t, err)
	receiverSock, err := net.ListenUDP("udp4", receiverAddr)
	require.NoError(t, err)
	defer func() { _ = receiverSock.Close() }()

	log := logging.NewDefaultLoggerFactory().NewLogger("mdns")

	// Wrap both in ipPacketConn4.
	sender := configurePacketConn4(ipv4.NewPacketConn(senderSock), "sender", "test", log)
	receiver := configurePacketConn4(ipv4.NewPacketConn(receiverSock), "receiver", "test", log)

	// Get the actual bound address of the receiver.
	receiverBoundAddr := receiverSock.LocalAddr()

	// Send test data with a control message to exercise that code path.
	testData := []byte("hello from ipPacketConn4")
	iface, err := net.InterfaceByName("lo")
	if err != nil {
		// Loopback interface name varies by OS.
		iface = &net.Interface{Index: 1, Name: "lo"}
	}
	cm := &ipControlMessage{IfIndex: iface.Index}
	n, err := sender.WriteTo(testData, iface, cm, receiverBoundAddr)
	require.NoError(t, err)
	assert.Equal(t, len(testData), n)

	// Receive and verify.
	buf := make([]byte, 1500)
	require.NoError(t, receiverSock.SetReadDeadline(time.Now().Add(2*time.Second)))
	n, _, src, err := receiver.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, testData, buf[:n])
	assert.NotNil(t, src)
}

func TestIPPacketConn6RoundTrip(t *testing.T) {
	lim := test.TimeOut(time.Second * 5)
	defer lim.Stop()

	report := test.CheckRoutines(t)
	defer report()

	// Create sender socket bound to ephemeral port.
	senderAddr, err := net.ResolveUDPAddr("udp6", "[::1]:0")
	require.NoError(t, err)
	senderSock, err := net.ListenUDP("udp6", senderAddr)
	if err != nil {
		t.Skipf("IPv6 not available: %v", err)
	}
	defer func() { _ = senderSock.Close() }()

	// Create receiver socket bound to ephemeral port.
	receiverAddr, err := net.ResolveUDPAddr("udp6", "[::1]:0")
	require.NoError(t, err)
	receiverSock, err := net.ListenUDP("udp6", receiverAddr)
	require.NoError(t, err)
	defer func() { _ = receiverSock.Close() }()

	log := logging.NewDefaultLoggerFactory().NewLogger("mdns")

	// Wrap both in ipPacketConn6.
	sender := configurePacketConn6(ipv6.NewPacketConn(senderSock), "sender", "test", log)
	receiver := configurePacketConn6(ipv6.NewPacketConn(receiverSock), "receiver", "test", log)

	// Get the actual bound address of the receiver.
	receiverBoundAddr := receiverSock.LocalAddr()

	// Send test data with a control message to exercise that code path.
	testData := []byte("hello from ipPacketConn6")
	iface, err := net.InterfaceByName("lo")
	if err != nil {
		// Loopback interface name varies by OS.
		iface = &net.Interface{Index: 1, Name: "lo"}
	}
	cm := &ipControlMessage{IfIndex: iface.Index}
	n, err := sender.WriteTo(testData, iface, cm, receiverBoundAddr)
	require.NoError(t, err)
	assert.Equal(t, len(testData), n)

	// Receive and verify.
	buf := make([]byte, 1500)
	require.NoError(t, receiverSock.SetReadDeadline(time.Now().Add(2*time.Second)))
	n, _, src, err := receiver.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, testData, buf[:n])
	assert.NotNil(t, src)
}
