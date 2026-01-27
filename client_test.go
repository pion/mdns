// SPDX-FileCopyrightText: The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package mdns

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
)

func TestAnswerHandlerRegisterUnregister(t *testing.T) {
	log := logging.NewDefaultLoggerFactory().NewLogger("test")
	handler := newAnswerHandler(log, "test")

	// Register a query
	resultChan := make(chan queryResult, 1)
	query1 := handler.registerQuery("test.local.", resultChan)

	assert.Len(t, handler.queries, 1)
	assert.Equal(t, "test.local.", query1.nameWithSuffix)

	// Register another query
	resultChan2 := make(chan queryResult, 1)
	query2 := handler.registerQuery("other.local.", resultChan2)

	assert.Len(t, handler.queries, 2)

	// Unregister first query
	handler.unregisterQuery(query1)
	assert.Len(t, handler.queries, 1)
	assert.Equal(t, query2, handler.queries[0])

	// Unregister second query
	handler.unregisterQuery(query2)
	assert.Empty(t, handler.queries)

	// Unregister non-existent query (should be no-op)
	handler.unregisterQuery(query1)
	assert.Empty(t, handler.queries)
}

func TestAnswerHandlerHandleMatchingAnswer(t *testing.T) {
	log := logging.NewDefaultLoggerFactory().NewLogger("test")
	handler := newAnswerHandler(log, "test")

	resultChan := make(chan queryResult, 1)
	handler.registerQuery("test.local.", resultChan)

	ctx := &messageContext{
		source:    &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 5353},
		ifIndex:   1,
		timestamp: time.Now(),
	}

	msg := &dnsmessage.Message{
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name:  dnsmessage.MustNewName("test.local."),
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					TTL:   120,
				},
				Body: &dnsmessage.AResource{A: [4]byte{192, 168, 1, 100}},
			},
		},
	}

	handler.handle(ctx, msg)

	// Should receive the answer
	select {
	case result := <-resultChan:
		assert.Equal(t, dnsmessage.TypeA, result.answer.Type)
		assert.Equal(t, netip.MustParseAddr("192.168.1.100"), result.addr)
	default:
		assert.Fail(t, "expected result on channel")
	}

	// Query should be removed after being answered
	assert.Empty(t, handler.queries)
}

func TestAnswerHandlerHandleMatchingAnswerIPv6(t *testing.T) {
	log := logging.NewDefaultLoggerFactory().NewLogger("test")
	handler := newAnswerHandler(log, "test")

	resultChan := make(chan queryResult, 1)
	handler.registerQuery("test.local.", resultChan)

	ctx := &messageContext{
		source:    &net.UDPAddr{IP: net.ParseIP("fe80::1"), Port: 5353, Zone: "eth0"},
		ifIndex:   1,
		timestamp: time.Now(),
	}

	msg := &dnsmessage.Message{
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name:  dnsmessage.MustNewName("test.local."),
					Type:  dnsmessage.TypeAAAA,
					Class: dnsmessage.ClassINET,
					TTL:   120,
				},
				Body: &dnsmessage.AAAAResource{AAAA: [16]byte{
					0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
				}},
			},
		},
	}

	handler.handle(ctx, msg)

	// Should receive the answer with zone
	select {
	case result := <-resultChan:
		assert.Equal(t, dnsmessage.TypeAAAA, result.answer.Type)
		assert.Equal(t, "eth0", result.addr.Zone())
	default:
		assert.Fail(t, "expected result on channel")
	}
}

func TestAnswerHandlerHandleNonMatchingName(t *testing.T) {
	log := logging.NewDefaultLoggerFactory().NewLogger("test")
	handler := newAnswerHandler(log, "test")

	resultChan := make(chan queryResult, 1)
	handler.registerQuery("test.local.", resultChan)

	ctx := &messageContext{
		source:    &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 5353},
		ifIndex:   1,
		timestamp: time.Now(),
	}

	msg := &dnsmessage.Message{
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name:  dnsmessage.MustNewName("other.local."),
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					TTL:   120,
				},
				Body: &dnsmessage.AResource{A: [4]byte{192, 168, 1, 100}},
			},
		},
	}

	handler.handle(ctx, msg)

	// Should not receive anything
	select {
	case <-resultChan:
		assert.Fail(t, "should not receive result for non-matching name")
	default:
		// Expected
	}

	// Query should still be registered
	assert.Len(t, handler.queries, 1)
}

func TestAnswerHandlerHandleCaseInsensitive(t *testing.T) {
	log := logging.NewDefaultLoggerFactory().NewLogger("test")
	handler := newAnswerHandler(log, "test")

	resultChan := make(chan queryResult, 1)
	handler.registerQuery("TEST.LOCAL.", resultChan)

	ctx := &messageContext{
		source:    &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 5353},
		ifIndex:   1,
		timestamp: time.Now(),
	}

	msg := &dnsmessage.Message{
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name:  dnsmessage.MustNewName("test.local."),
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					TTL:   120,
				},
				Body: &dnsmessage.AResource{A: [4]byte{192, 168, 1, 100}},
			},
		},
	}

	handler.handle(ctx, msg)

	// Should receive the answer (case-insensitive match)
	select {
	case result := <-resultChan:
		assert.Equal(t, netip.MustParseAddr("192.168.1.100"), result.addr)
	default:
		assert.Fail(t, "expected result on channel for case-insensitive match")
	}
}

func TestAnswerHandlerHandleSkipsNonAddressTypes(t *testing.T) {
	log := logging.NewDefaultLoggerFactory().NewLogger("test")
	handler := newAnswerHandler(log, "test")

	resultChan := make(chan queryResult, 1)
	handler.registerQuery("test.local.", resultChan)

	ctx := &messageContext{
		source:    &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 5353},
		ifIndex:   1,
		timestamp: time.Now(),
	}

	// PTR record should be skipped
	msg := &dnsmessage.Message{
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name:  dnsmessage.MustNewName("test.local."),
					Type:  dnsmessage.TypePTR,
					Class: dnsmessage.ClassINET,
					TTL:   120,
				},
				Body: &dnsmessage.PTRResource{PTR: dnsmessage.MustNewName("ptr.local.")},
			},
		},
	}

	handler.handle(ctx, msg)

	// Should not receive anything (PTR is not A or AAAA)
	select {
	case <-resultChan:
		assert.Fail(t, "should not receive result for PTR record")
	default:
		// Expected
	}

	// Query should still be registered
	assert.Len(t, handler.queries, 1)
}

func TestAnswerHandlerHandleMultipleAnswers(t *testing.T) {
	log := logging.NewDefaultLoggerFactory().NewLogger("test")
	handler := newAnswerHandler(log, "test")

	resultChan1 := make(chan queryResult, 1)
	resultChan2 := make(chan queryResult, 1)
	handler.registerQuery("test1.local.", resultChan1)
	handler.registerQuery("test2.local.", resultChan2)

	ctx := &messageContext{
		source:    &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 5353},
		ifIndex:   1,
		timestamp: time.Now(),
	}

	msg := &dnsmessage.Message{
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name:  dnsmessage.MustNewName("test1.local."),
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					TTL:   120,
				},
				Body: &dnsmessage.AResource{A: [4]byte{192, 168, 1, 1}},
			},
			{
				Header: dnsmessage.ResourceHeader{
					Name:  dnsmessage.MustNewName("test2.local."),
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					TTL:   120,
				},
				Body: &dnsmessage.AResource{A: [4]byte{192, 168, 1, 2}},
			},
		},
	}

	handler.handle(ctx, msg)

	// Should receive both answers
	select {
	case result := <-resultChan1:
		assert.Equal(t, netip.MustParseAddr("192.168.1.1"), result.addr)
	default:
		assert.Fail(t, "expected result on channel 1")
	}

	select {
	case result := <-resultChan2:
		assert.Equal(t, netip.MustParseAddr("192.168.1.2"), result.addr)
	default:
		assert.Fail(t, "expected result on channel 2")
	}

	// Both queries should be removed
	assert.Empty(t, handler.queries)
}

func TestAnswerHandlerHandleSkipsMalformedAnswer(t *testing.T) {
	log := logging.NewDefaultLoggerFactory().NewLogger("test")
	handler := newAnswerHandler(log, "test")

	resultChan := make(chan queryResult, 1)
	handler.registerQuery("test.local.", resultChan)

	ctx := &messageContext{
		source:    &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 5353},
		ifIndex:   1,
		timestamp: time.Now(),
	}

	// First answer is malformed (TypeA but nil body), second is valid
	msg := &dnsmessage.Message{
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name:  dnsmessage.MustNewName("test.local."),
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					TTL:   120,
				},
				Body: nil, // Malformed: TypeA with nil body
			},
			{
				Header: dnsmessage.ResourceHeader{
					Name:  dnsmessage.MustNewName("test.local."),
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					TTL:   120,
				},
				Body: &dnsmessage.AResource{A: [4]byte{192, 168, 1, 100}},
			},
		},
	}

	handler.handle(ctx, msg)

	// Should still receive the valid answer despite the malformed one
	select {
	case result := <-resultChan:
		assert.Equal(t, netip.MustParseAddr("192.168.1.100"), result.addr)
	default:
		assert.Fail(t, "expected result - malformed answer should be skipped, not abort processing")
	}

	// Query should be removed after being answered
	assert.Empty(t, handler.queries)
}

func TestAnswerHandlerHandleChannelFull(t *testing.T) {
	log := logging.NewDefaultLoggerFactory().NewLogger("test")
	handler := newAnswerHandler(log, "test")

	// Create unbuffered channel that's already "full" (no receiver)
	resultChan := make(chan queryResult)
	handler.registerQuery("test.local.", resultChan)

	ctx := &messageContext{
		source:    &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 5353},
		ifIndex:   1,
		timestamp: time.Now(),
	}

	msg := &dnsmessage.Message{
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name:  dnsmessage.MustNewName("test.local."),
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					TTL:   120,
				},
				Body: &dnsmessage.AResource{A: [4]byte{192, 168, 1, 100}},
			},
		},
	}

	// Should not block even though channel is full
	done := make(chan struct{})
	go func() {
		handler.handle(ctx, msg)
		close(done)
	}()

	select {
	case <-done:
		// Expected - handle() should not block
	case <-time.After(100 * time.Millisecond):
		assert.Fail(t, "handle() blocked on full channel")
	}

	// Query should still be registered (wasn't answered successfully)
	assert.Len(t, handler.queries, 1)
}

// buildBrowseResponseMsg builds a DNS response with PTR + SRV + TXT + A in
// Additional section, simulating a typical DNS-SD response.
func buildBrowseResponseMsg(t *testing.T) *dnsmessage.Message {
	t.Helper()

	return &dnsmessage.Message{
		Header: dnsmessage.Header{
			Response:      true,
			Authoritative: true,
		},
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name:  dnsmessage.MustNewName("_http._tcp.local."),
					Type:  dnsmessage.TypePTR,
					Class: dnsmessage.ClassINET,
					TTL:   4500,
				},
				Body: &dnsmessage.PTRResource{PTR: dnsmessage.MustNewName("My Web._http._tcp.local.")},
			},
		},
		Additionals: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name:  dnsmessage.MustNewName("My Web._http._tcp.local."),
					Type:  dnsmessage.TypeSRV,
					Class: dnsmessage.ClassINET,
					TTL:   120,
				},
				Body: &dnsmessage.SRVResource{
					Priority: 0,
					Weight:   0,
					Port:     8080,
					Target:   dnsmessage.MustNewName("myhost.local."),
				},
			},
			{
				Header: dnsmessage.ResourceHeader{
					Name:  dnsmessage.MustNewName("My Web._http._tcp.local."),
					Type:  dnsmessage.TypeTXT,
					Class: dnsmessage.ClassINET,
					TTL:   4500,
				},
				Body: &dnsmessage.TXTResource{TXT: []string{"path=/", "version=1"}},
			},
			{
				Header: dnsmessage.ResourceHeader{
					Name:  dnsmessage.MustNewName("myhost.local."),
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					TTL:   120,
				},
				Body: &dnsmessage.AResource{A: [4]byte{192, 168, 1, 100}},
			},
		},
	}
}

func TestBrowseSessionSinglePacketResolution(t *testing.T) {
	log := logging.NewDefaultLoggerFactory().NewLogger("test")
	handler := newAnswerHandler(log, "test")

	var mu sync.Mutex
	var events []ServiceEvent
	emit := func(evt ServiceEvent) {
		mu.Lock()
		events = append(events, evt)
		mu.Unlock()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	session := newBrowseSession(ctx, "_http._tcp", emit)
	handler.registerBrowseSession(session)
	defer handler.unregisterBrowseSession(session)

	msgCtx := &messageContext{
		source:    &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 5353},
		ifIndex:   1,
		timestamp: time.Now(),
	}

	msg := buildBrowseResponseMsg(t)
	handler.handle(msgCtx, msg)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, events, 1)

	evt := events[0]
	assert.Equal(t, "My Web", evt.Instance.Instance)
	assert.Equal(t, "_http._tcp", evt.Instance.Service)
	assert.Equal(t, "local", evt.Instance.Domain)
	assert.Equal(t, "myhost.local.", evt.Instance.Host)
	assert.Equal(t, uint16(8080), evt.Instance.Port)
	assert.Equal(t, netip.MustParseAddr("192.168.1.100"), evt.Addr)
	require.Len(t, evt.Instance.Text, 2)
	assert.Equal(t, "path", evt.Instance.Text[0].Key)
	assert.Equal(t, []byte("/"), evt.Instance.Text[0].Value)
	assert.Equal(t, "version", evt.Instance.Text[1].Key)
	assert.Equal(t, []byte("1"), evt.Instance.Text[1].Value)
}

func TestBrowseSessionDeduplication(t *testing.T) {
	log := logging.NewDefaultLoggerFactory().NewLogger("test")
	handler := newAnswerHandler(log, "test")

	var mu sync.Mutex
	var callCount int
	emit := func(ServiceEvent) {
		mu.Lock()
		callCount++
		mu.Unlock()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	session := newBrowseSession(ctx, "_http._tcp", emit)
	handler.registerBrowseSession(session)
	defer handler.unregisterBrowseSession(session)

	msgCtx := &messageContext{
		source:    &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 5353},
		ifIndex:   1,
		timestamp: time.Now(),
	}

	msg := buildBrowseResponseMsg(t)

	// Send the same response twice.
	handler.handle(msgCtx, msg)
	handler.handle(msgCtx, msg)

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 1, callCount, "expected exactly one callback (deduplicated)")
}

func TestBrowseSessionMultipleInstances(t *testing.T) {
	log := logging.NewDefaultLoggerFactory().NewLogger("test")
	handler := newAnswerHandler(log, "test")

	var mu sync.Mutex
	seen := make(map[string]bool)
	emit := func(evt ServiceEvent) {
		mu.Lock()
		seen[evt.Instance.Instance] = true
		mu.Unlock()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	session := newBrowseSession(ctx, "_http._tcp", emit)
	handler.registerBrowseSession(session)
	defer handler.unregisterBrowseSession(session)

	msgCtx := &messageContext{
		source:    &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 5353},
		ifIndex:   1,
		timestamp: time.Now(),
	}

	// First service instance.
	msg1 := buildBrowseResponseMsg(t)

	// Second service instance.
	msg2 := &dnsmessage.Message{
		Header: dnsmessage.Header{Response: true, Authoritative: true},
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name: dnsmessage.MustNewName("_http._tcp.local."),
					Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET, TTL: 4500,
				},
				Body: &dnsmessage.PTRResource{PTR: dnsmessage.MustNewName("Other Service._http._tcp.local.")},
			},
		},
		Additionals: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name: dnsmessage.MustNewName("Other Service._http._tcp.local."),
					Type: dnsmessage.TypeSRV, Class: dnsmessage.ClassINET, TTL: 120,
				},
				Body: &dnsmessage.SRVResource{Port: 9090, Target: dnsmessage.MustNewName("otherhost.local.")},
			},
			{
				Header: dnsmessage.ResourceHeader{
					Name: dnsmessage.MustNewName("Other Service._http._tcp.local."),
					Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 4500,
				},
				Body: &dnsmessage.TXTResource{TXT: []string{""}},
			},
			{
				Header: dnsmessage.ResourceHeader{
					Name: dnsmessage.MustNewName("otherhost.local."),
					Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 120,
				},
				Body: &dnsmessage.AResource{A: [4]byte{10, 0, 0, 1}},
			},
		},
	}

	handler.handle(msgCtx, msg1)
	handler.handle(msgCtx, msg2)

	mu.Lock()
	defer mu.Unlock()
	assert.True(t, seen["My Web"])
	assert.True(t, seen["Other Service"])
}

func TestBrowseSessionMultiPacketResolution(t *testing.T) {
	log := logging.NewDefaultLoggerFactory().NewLogger("test")
	handler := newAnswerHandler(log, "test")

	var mu sync.Mutex
	var events []ServiceEvent
	emit := func(evt ServiceEvent) {
		mu.Lock()
		events = append(events, evt)
		mu.Unlock()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	session := newBrowseSession(ctx, "_http._tcp", emit)
	handler.registerBrowseSession(session)
	defer handler.unregisterBrowseSession(session)

	msgCtx := &messageContext{
		source:    &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 5353},
		ifIndex:   1,
		timestamp: time.Now(),
	}

	// Step 1: PTR only (no additionals).
	ptrMsg := &dnsmessage.Message{
		Header: dnsmessage.Header{Response: true, Authoritative: true},
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name: dnsmessage.MustNewName("_http._tcp.local."),
					Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET, TTL: 4500,
				},
				Body: &dnsmessage.PTRResource{PTR: dnsmessage.MustNewName("My Web._http._tcp.local.")},
			},
		},
	}
	handler.handle(msgCtx, ptrMsg)

	mu.Lock()
	assert.Empty(t, events, "should not emit incomplete instance")
	mu.Unlock()

	// Step 2: SRV + TXT answers.
	srvTxtMsg := &dnsmessage.Message{
		Header: dnsmessage.Header{Response: true, Authoritative: true},
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name: dnsmessage.MustNewName("My Web._http._tcp.local."),
					Type: dnsmessage.TypeSRV, Class: dnsmessage.ClassINET, TTL: 120,
				},
				Body: &dnsmessage.SRVResource{Port: 8080, Target: dnsmessage.MustNewName("myhost.local.")},
			},
			{
				Header: dnsmessage.ResourceHeader{
					Name: dnsmessage.MustNewName("My Web._http._tcp.local."),
					Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 4500,
				},
				Body: &dnsmessage.TXTResource{TXT: []string{"path=/"}},
			},
		},
	}
	handler.handle(msgCtx, srvTxtMsg)

	mu.Lock()
	assert.Empty(t, events, "should not emit instance without address")
	mu.Unlock()

	// Step 3: A record for the host.
	addrMsg := &dnsmessage.Message{
		Header: dnsmessage.Header{Response: true, Authoritative: true},
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name: dnsmessage.MustNewName("myhost.local."),
					Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 120,
				},
				Body: &dnsmessage.AResource{A: [4]byte{192, 168, 1, 50}},
			},
		},
	}
	handler.handle(msgCtx, addrMsg)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, events, 1, "expected browse result after address resolution")
	assert.Equal(t, "My Web", events[0].Instance.Instance)
	assert.Equal(t, uint16(8080), events[0].Instance.Port)
	assert.Equal(t, netip.MustParseAddr("192.168.1.50"), events[0].Addr)
}

func TestEnumerateSession(t *testing.T) {
	log := logging.NewDefaultLoggerFactory().NewLogger("test")
	handler := newAnswerHandler(log, "test")

	var mu sync.Mutex
	var discovered []string
	emit := func(svcType string) {
		mu.Lock()
		discovered = append(discovered, svcType)
		mu.Unlock()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	session := newEnumerateSession(ctx, emit)
	handler.registerEnumerateSession(session)
	defer handler.unregisterEnumerateSession(session)

	msgCtx := &messageContext{
		source:    &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 5353},
		ifIndex:   1,
		timestamp: time.Now(),
	}

	msg := &dnsmessage.Message{
		Header: dnsmessage.Header{Response: true, Authoritative: true},
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name: dnsmessage.MustNewName("_services._dns-sd._udp.local."),
					Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET, TTL: 4500,
				},
				Body: &dnsmessage.PTRResource{PTR: dnsmessage.MustNewName("_http._tcp.local.")},
			},
			{
				Header: dnsmessage.ResourceHeader{
					Name: dnsmessage.MustNewName("_services._dns-sd._udp.local."),
					Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET, TTL: 4500,
				},
				Body: &dnsmessage.PTRResource{PTR: dnsmessage.MustNewName("_ipp._tcp.local.")},
			},
		},
	}

	handler.handle(msgCtx, msg)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, discovered, 2)
	seen := make(map[string]bool)
	for _, svc := range discovered {
		seen[svc] = true
	}
	assert.True(t, seen["_http._tcp"])
	assert.True(t, seen["_ipp._tcp"])
}

func TestEnumerateSessionDeduplication(t *testing.T) {
	log := logging.NewDefaultLoggerFactory().NewLogger("test")
	handler := newAnswerHandler(log, "test")

	var mu sync.Mutex
	var callCount int
	emit := func(string) {
		mu.Lock()
		callCount++
		mu.Unlock()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	session := newEnumerateSession(ctx, emit)
	handler.registerEnumerateSession(session)
	defer handler.unregisterEnumerateSession(session)

	msgCtx := &messageContext{
		source:    &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 5353},
		ifIndex:   1,
		timestamp: time.Now(),
	}

	msg := &dnsmessage.Message{
		Header: dnsmessage.Header{Response: true, Authoritative: true},
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name: dnsmessage.MustNewName("_services._dns-sd._udp.local."),
					Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET, TTL: 4500,
				},
				Body: &dnsmessage.PTRResource{PTR: dnsmessage.MustNewName("_http._tcp.local.")},
			},
		},
	}

	// Send twice.
	handler.handle(msgCtx, msg)
	handler.handle(msgCtx, msg)

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 1, callCount, "expected exactly one callback (deduplicated)")
}

func TestBrowseSessionRegisterUnregister(t *testing.T) {
	log := logging.NewDefaultLoggerFactory().NewLogger("test")
	handler := newAnswerHandler(log, "test")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	session := newBrowseSession(ctx, "_http._tcp", func(ServiceEvent) {})
	handler.registerBrowseSession(session)
	assert.Len(t, handler.browseSessions, 1)

	handler.unregisterBrowseSession(session)
	assert.Empty(t, handler.browseSessions)

	// Unregister non-existent session (no-op).
	handler.unregisterBrowseSession(session)
	assert.Empty(t, handler.browseSessions)
}

func TestAnswerHandlerExistingBehaviorUnchanged(t *testing.T) {
	// Verify that existing name query behavior is not broken by browse additions.
	log := logging.NewDefaultLoggerFactory().NewLogger("test")
	handler := newAnswerHandler(log, "test")

	resultChan := make(chan queryResult, 1)
	handler.registerQuery("test.local.", resultChan)

	// Also register a browse session.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	session := newBrowseSession(ctx, "_http._tcp", func(ServiceEvent) {})
	handler.registerBrowseSession(session)
	defer handler.unregisterBrowseSession(session)

	msgCtx := &messageContext{
		source:    &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 5353},
		ifIndex:   1,
		timestamp: time.Now(),
	}

	msg := &dnsmessage.Message{
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name: dnsmessage.MustNewName("test.local."),
					Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 120,
				},
				Body: &dnsmessage.AResource{A: [4]byte{192, 168, 1, 100}},
			},
		},
	}

	handler.handle(msgCtx, msg)

	// Name query should still work.
	select {
	case result := <-resultChan:
		assert.Equal(t, netip.MustParseAddr("192.168.1.100"), result.addr)
	default:
		assert.Fail(t, "expected name query result")
	}

	assert.Empty(t, handler.queries)
}
