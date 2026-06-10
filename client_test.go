// SPDX-FileCopyrightText: The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package mdns

import (
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
	handler := newAnswerHandler(log, "test", newCache(time.Now))

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
	handler := newAnswerHandler(log, "test", newCache(time.Now))

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
	handler := newAnswerHandler(log, "test", newCache(time.Now))

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
	handler := newAnswerHandler(log, "test", newCache(time.Now))

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
	handler := newAnswerHandler(log, "test", newCache(time.Now))

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
	handler := newAnswerHandler(log, "test", newCache(time.Now))

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
	handler := newAnswerHandler(log, "test", newCache(time.Now))

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
	handler := newAnswerHandler(log, "test", newCache(time.Now))

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
	handler := newAnswerHandler(log, "test", newCache(time.Now))

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
	handler := newAnswerHandler(log, "test", newCache(time.Now))

	var mu sync.Mutex
	var events []ServiceEvent
	emit := func(evt ServiceEvent) {
		mu.Lock()
		events = append(events, evt)
		mu.Unlock()
	}

	ctx := t.Context()

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
	handler := newAnswerHandler(log, "test", newCache(time.Now))

	var mu sync.Mutex
	var callCount int
	emit := func(ServiceEvent) {
		mu.Lock()
		callCount++
		mu.Unlock()
	}

	ctx := t.Context()

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
	handler := newAnswerHandler(log, "test", newCache(time.Now))

	var mu sync.Mutex
	seen := make(map[string]bool)
	emit := func(evt ServiceEvent) {
		mu.Lock()
		seen[evt.Instance.Instance] = true
		mu.Unlock()
	}

	ctx := t.Context()

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
	handler := newAnswerHandler(log, "test", newCache(time.Now))

	var mu sync.Mutex
	var events []ServiceEvent
	emit := func(evt ServiceEvent) {
		mu.Lock()
		events = append(events, evt)
		mu.Unlock()
	}

	ctx := t.Context()

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
	handler := newAnswerHandler(log, "test", newCache(time.Now))

	var mu sync.Mutex
	var discovered []string
	emit := func(svcType string) {
		mu.Lock()
		discovered = append(discovered, svcType)
		mu.Unlock()
	}

	ctx := t.Context()

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
	handler := newAnswerHandler(log, "test", newCache(time.Now))

	var mu sync.Mutex
	var callCount int
	emit := func(string) {
		mu.Lock()
		callCount++
		mu.Unlock()
	}

	ctx := t.Context()

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
	handler := newAnswerHandler(log, "test", newCache(time.Now))

	ctx := t.Context()

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
	handler := newAnswerHandler(log, "test", newCache(time.Now))

	resultChan := make(chan queryResult, 1)
	handler.registerQuery("test.local.", resultChan)

	// Also register a browse session.
	ctx := t.Context()
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

// ---------------------------------------------------------------------------
// Cache insertion via answerHandler
// ---------------------------------------------------------------------------

func TestAnswerHandlerCachesRecords(t *testing.T) {
	clock := newTestClock()
	ca := newCache(clock.now)
	log := logging.NewDefaultLoggerFactory().NewLogger("test")
	handler := newAnswerHandler(log, "test", ca)

	msgCtx := &messageContext{
		source:    &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 5353},
		ifIndex:   1,
		timestamp: clock.now(),
	}

	msg := buildBrowseResponseMsg(t)
	handler.handle(msgCtx, msg)

	// PTR from Answers.
	results := ca.lookup("_http._tcp.local.", dnsmessage.TypePTR, dnsmessage.ClassINET)
	assert.Len(t, results, 1)

	// SRV from Additionals.
	results = ca.lookup("My Web._http._tcp.local.", dnsmessage.TypeSRV, dnsmessage.ClassINET)
	assert.Len(t, results, 1)

	// TXT from Additionals.
	results = ca.lookup("My Web._http._tcp.local.", dnsmessage.TypeTXT, dnsmessage.ClassINET)
	assert.Len(t, results, 1)

	// A from Additionals.
	results = ca.lookup("myhost.local.", dnsmessage.TypeA, dnsmessage.ClassINET)
	assert.Len(t, results, 1)
}

func TestAnswerHandlerCacheGoodbye(t *testing.T) {
	clock := newTestClock()
	ca := newCache(clock.now)
	log := logging.NewDefaultLoggerFactory().NewLogger("test")
	handler := newAnswerHandler(log, "test", ca)

	msgCtx := &messageContext{
		source:    &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 5353},
		ifIndex:   1,
		timestamp: clock.now(),
	}

	// Insert a record first.
	msg := &dnsmessage.Message{
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name: dnsmessage.MustNewName("host.local."),
					Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 120,
				},
				Body: &dnsmessage.AResource{A: [4]byte{10, 0, 0, 1}},
			},
		},
	}
	handler.handle(msgCtx, msg)

	// Send goodbye (TTL=0).
	goodbyeMsg := &dnsmessage.Message{
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name: dnsmessage.MustNewName("host.local."),
					Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 0,
				},
				Body: &dnsmessage.AResource{A: [4]byte{10, 0, 0, 1}},
			},
		},
	}
	handler.handle(msgCtx, goodbyeMsg)

	// Still visible (retained for 1s).
	results := ca.lookup("host.local.", dnsmessage.TypeA, dnsmessage.ClassINET)
	assert.Len(t, results, 1)

	// After 2s, gone.
	clock.advance(2 * time.Second)
	results = ca.lookup("host.local.", dnsmessage.TypeA, dnsmessage.ClassINET)
	assert.Empty(t, results)
}

func TestAnswerHandlerCacheFlushBit(t *testing.T) {
	clock := newTestClock()
	ca := newCache(clock.now)
	log := logging.NewDefaultLoggerFactory().NewLogger("test")
	handler := newAnswerHandler(log, "test", ca)

	msgCtx := &messageContext{
		source:    &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 5353},
		ifIndex:   1,
		timestamp: clock.now(),
	}

	// Insert old record.
	msg := &dnsmessage.Message{
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name: dnsmessage.MustNewName("host.local."),
					Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 300,
				},
				Body: &dnsmessage.AResource{A: [4]byte{10, 0, 0, 1}},
			},
		},
	}
	handler.handle(msgCtx, msg)

	// Advance past cache-flush delay.
	clock.advance(2 * time.Second)
	msgCtx.timestamp = clock.now()

	// Insert new record with cache-flush bit.
	flushMsg := &dnsmessage.Message{
		Answers: []dnsmessage.Resource{
			{
				Header: dnsmessage.ResourceHeader{
					Name: dnsmessage.MustNewName("host.local."),
					Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET | rrClassCacheFlush, TTL: 120,
				},
				Body: &dnsmessage.AResource{A: [4]byte{10, 0, 0, 2}},
			},
		},
	}
	handler.handle(msgCtx, flushMsg)

	// Advance past flush delay.
	clock.advance(2 * time.Second)

	results := ca.lookup("host.local.", dnsmessage.TypeA, dnsmessage.ClassINET)
	require.Len(t, results, 1)

	body, ok := results[0].Body.(*dnsmessage.AResource)
	require.True(t, ok)
	assert.Equal(t, [4]byte{10, 0, 0, 2}, body.A)
}

// ---------------------------------------------------------------------------
// Monitored cache keys
// ---------------------------------------------------------------------------

func TestBrowseSessionMonitoredKeys(t *testing.T) {
	session := newBrowseSession(t.Context(), "_http._tcp", func(ServiceEvent) {})

	keys := session.monitoredCacheKeys()
	require.Len(t, keys, 1)
	assert.Equal(t, "_http._tcp.local.", keys[0].name)
	assert.Equal(t, dnsmessage.TypePTR, keys[0].rrType)

	// Add a pending instance.
	session.mu.Lock()
	session.pending["My Web"] = &pendingInstance{
		instance: "My Web",
		service:  "_http._tcp",
		domain:   "local",
		host:     "myhost.local.",
		hasSRV:   true,
	}
	session.mu.Unlock()

	keys = session.monitoredCacheKeys()
	// PTR + SRV + TXT + A + AAAA = 5.
	assert.Len(t, keys, 5)
}

func TestEnumerateSessionMonitoredKeys(t *testing.T) {
	session := newEnumerateSession(t.Context(), func(string) {})
	keys := session.monitoredCacheKeys()

	require.Len(t, keys, 1)
	assert.Equal(t, "_services._dns-sd._udp.local.", keys[0].name)
	assert.Equal(t, dnsmessage.TypePTR, keys[0].rrType)
}

// ---------------------------------------------------------------------------
// Service removed events (RFC 6762 §10.1 goodbye, TTL expiry)
// ---------------------------------------------------------------------------

// collectEvents returns an emit callback that records events, plus an
// accessor returning a snapshot of everything emitted so far.
func collectEvents() (func(ServiceEvent), func() []ServiceEvent) {
	var mu sync.Mutex
	var events []ServiceEvent

	emit := func(evt ServiceEvent) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, evt)
	}
	snapshot := func() []ServiceEvent {
		mu.Lock()
		defer mu.Unlock()

		return append([]ServiceEvent(nil), events...)
	}

	return emit, snapshot
}

// feedInstance drives a browse session through a full PTR → SRV → TXT →
// A resolution for one "_http._tcp" instance, triggering an emit.
func feedInstance(t *testing.T, session *browseSession, instance, host, addr string) {
	t.Helper()

	fqdn := instance + "._http._tcp.local."
	session.processRecord(mustBuildPTR(t, "_http._tcp.local.", fqdn, 4500), "")
	session.processRecord(mustBuildSRV(t, fqdn, host, 8080, 120), "")
	session.processRecord(mustBuildTXT(t, fqdn, []string{"path=/"}, 4500), "")
	session.processRecord(mustBuildA(t, host, addr, 120), "")
}

func TestBrowseMonitorsEmittedInstances(t *testing.T) {
	emit, events := collectEvents()
	session := newBrowseSession(t.Context(), "_http._tcp", emit)

	feedInstance(t, session, "My Web", "myhost.local.", "192.168.1.100")
	require.Len(t, events(), 1)

	// The emitted instance's records must stay monitored so refresh
	// keeps them alive and their expiry is observed: service PTR + SRV +
	// TXT for the instance, A + AAAA for the host.
	keys := session.monitoredCacheKeys()
	require.Len(t, keys, 5)

	typesByName := make(map[string][]dnsmessage.Type)
	for _, key := range keys {
		typesByName[key.name] = append(typesByName[key.name], key.rrType)
	}
	assert.ElementsMatch(t,
		[]dnsmessage.Type{dnsmessage.TypeSRV, dnsmessage.TypeTXT},
		typesByName["my web._http._tcp.local."])
	assert.ElementsMatch(t,
		[]dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA},
		typesByName["myhost.local."])
}

func TestBrowsePTRGoodbyeCreatesNoPending(t *testing.T) {
	emit, events := collectEvents()
	session := newBrowseSession(t.Context(), "_http._tcp", emit)

	// A goodbye PTR (TTL=0) for an unknown instance must not start
	// resolving it.
	session.processRecord(mustBuildPTR(t, "_http._tcp.local.", "Ghost._http._tcp.local.", 0), "")

	session.mu.Lock()
	assert.Empty(t, session.pending)
	session.mu.Unlock()
	assert.Empty(t, events())
}

func TestBrowseExpiredPTREmitsRemoved(t *testing.T) {
	emit, events := collectEvents()
	session := newBrowseSession(t.Context(), "_http._tcp", emit)

	feedInstance(t, session, "My Web", "myhost.local.", "192.168.1.100")

	session.handleExpired(mustBuildPTR(t, "_http._tcp.local.", "My Web._http._tcp.local.", 0))

	evts := events()
	require.Len(t, evts, 2)
	assert.Equal(t, ServiceAdded, evts[0].Type)

	removed := evts[1]
	assert.Equal(t, ServiceRemoved, removed.Type)
	assert.Equal(t, "My Web", removed.Instance.Instance)
	assert.Equal(t, "_http._tcp", removed.Instance.Service)
	assert.Equal(t, "myhost.local.", removed.Instance.Host)
	assert.Equal(t, uint16(8080), removed.Instance.Port)
	assert.Equal(t, netip.MustParseAddr("192.168.1.100"), removed.Addr)
}

func TestBrowseExpiredPTRUnknownInstanceNoEvent(t *testing.T) {
	emit, events := collectEvents()
	session := newBrowseSession(t.Context(), "_http._tcp", emit)

	feedInstance(t, session, "My Web", "myhost.local.", "192.168.1.100")

	session.handleExpired(mustBuildPTR(t, "_http._tcp.local.", "Never Seen._http._tcp.local.", 0))

	evts := events()
	require.Len(t, evts, 1)
	assert.Equal(t, ServiceAdded, evts[0].Type)
}

func TestBrowseExpiredPTRPendingInstanceNoEvent(t *testing.T) {
	emit, events := collectEvents()
	session := newBrowseSession(t.Context(), "_http._tcp", emit)

	// PTR only: the instance stays pending (no SRV/TXT/A yet).
	session.processRecord(mustBuildPTR(t, "_http._tcp.local.", "Half Done._http._tcp.local.", 4500), "")

	session.handleExpired(mustBuildPTR(t, "_http._tcp.local.", "Half Done._http._tcp.local.", 0))

	assert.Empty(t, events())

	session.mu.Lock()
	assert.Empty(t, session.pending)
	session.mu.Unlock()
}

func TestBrowseExpiredSRVAloneNoRemoval(t *testing.T) {
	emit, events := collectEvents()
	session := newBrowseSession(t.Context(), "_http._tcp", emit)

	feedInstance(t, session, "My Web", "myhost.local.", "192.168.1.100")

	// SRV (or A) expiry without PTR expiry does not signal removal; the
	// instance PTR is the canonical presence record.
	session.handleExpired(mustBuildSRV(t, "My Web._http._tcp.local.", "myhost.local.", 8080, 0))
	session.handleExpired(mustBuildA(t, "myhost.local.", "192.168.1.100", 0))

	require.Len(t, events(), 1)
	assert.Len(t, session.monitoredCacheKeys(), 5, "instance should remain monitored")
}

func TestBrowseCacheFlushReplacementNoRemoval(t *testing.T) {
	log := logging.NewDefaultLoggerFactory().NewLogger("test")
	clock := newTestClock()
	recordCache := newCache(clock.now)
	handler := newAnswerHandler(log, "test", recordCache)

	emit, events := collectEvents()
	session := newBrowseSession(t.Context(), "_http._tcp", emit)
	handler.registerBrowseSession(session)
	defer handler.unregisterBrowseSession(session)

	source := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 5353}
	handler.handle(&messageContext{source: source, timestamp: clock.now()}, buildBrowseResponseMsg(t))
	require.Len(t, events(), 1)

	// Two seconds later the service moves ports: a replacement SRV with
	// the cache-flush bit caps the old SRV entry to 1s (§10.2).
	clock.advance(2 * time.Second)
	newSRV := mustBuildSRV(t, "My Web._http._tcp.local.", "myhost.local.", 9090, 120)
	newSRV.Header.Class |= rrClassCacheFlush
	handler.handle(&messageContext{source: source, timestamp: clock.now()}, &dnsmessage.Message{
		Header:  dnsmessage.Header{Response: true},
		Answers: []dnsmessage.Resource{newSRV},
	})

	// Sweeping past the cap reports the old SRV as expired. Forwarding
	// that report must not emit a removal: the instance is alive, only
	// its rdata changed.
	clock.advance(1500 * time.Millisecond)
	expired := recordCache.sweep()
	require.NotEmpty(t, expired)
	handler.handleExpired(expired)

	evts := events()
	require.Len(t, evts, 1)
	assert.Equal(t, ServiceAdded, evts[0].Type)
}

func TestBrowseRediscoveryAfterRemoval(t *testing.T) {
	emit, events := collectEvents()
	session := newBrowseSession(t.Context(), "_http._tcp", emit)

	feedInstance(t, session, "My Web", "myhost.local.", "192.168.1.100")
	session.handleExpired(mustBuildPTR(t, "_http._tcp.local.", "My Web._http._tcp.local.", 0))

	// The instance comes back: it must be reported as a fresh add.
	feedInstance(t, session, "My Web", "myhost.local.", "192.168.1.100")

	evts := events()
	require.Len(t, evts, 3)
	assert.Equal(t, ServiceAdded, evts[0].Type)
	assert.Equal(t, ServiceRemoved, evts[1].Type)
	assert.Equal(t, ServiceAdded, evts[2].Type)
}

func TestBrowseRemovalIdempotent(t *testing.T) {
	emit, events := collectEvents()
	session := newBrowseSession(t.Context(), "_http._tcp", emit)

	feedInstance(t, session, "My Web", "myhost.local.", "192.168.1.100")

	expiredPTR := mustBuildPTR(t, "_http._tcp.local.", "My Web._http._tcp.local.", 0)
	session.handleExpired(expiredPTR)
	session.handleExpired(expiredPTR)

	evts := events()
	require.Len(t, evts, 2, "second expiry of the same instance must not emit again")
	assert.Equal(t, ServiceRemoved, evts[1].Type)
}

func TestBrowseRemovalOneOfTwoInstances(t *testing.T) {
	emit, events := collectEvents()
	session := newBrowseSession(t.Context(), "_http._tcp", emit)

	feedInstance(t, session, "Alpha", "host-a.local.", "10.0.0.1")
	feedInstance(t, session, "Beta", "host-b.local.", "10.0.0.2")
	require.Len(t, events(), 2)

	session.handleExpired(mustBuildPTR(t, "_http._tcp.local.", "Alpha._http._tcp.local.", 0))

	evts := events()
	require.Len(t, evts, 3)
	assert.Equal(t, ServiceRemoved, evts[2].Type)
	assert.Equal(t, "Alpha", evts[2].Instance.Instance)

	// Beta stays active and monitored: PTR + SRV/TXT + A/AAAA.
	assert.Len(t, session.monitoredCacheKeys(), 5)
}

func TestBrowseExpiredPTRCaseInsensitive(t *testing.T) {
	emit, events := collectEvents()
	session := newBrowseSession(t.Context(), "_http._tcp", emit)

	feedInstance(t, session, "My Web", "myhost.local.", "192.168.1.100")

	session.handleExpired(mustBuildPTR(t, "_HTTP._tcp.LOCAL.", "MY WEB._HTTP._tcp.LOCAL.", 0))

	evts := events()
	require.Len(t, evts, 2)
	assert.Equal(t, ServiceRemoved, evts[1].Type)
	assert.Equal(t, "My Web", evts[1].Instance.Instance)
}

func TestBrowseExpiredPTRMalformedIgnored(t *testing.T) {
	emit, events := collectEvents()
	session := newBrowseSession(t.Context(), "_http._tcp", emit)

	feedInstance(t, session, "My Web", "myhost.local.", "192.168.1.100")

	// PTR header with a non-PTR body: rdata parse fails, no event.
	session.handleExpired(dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  dnsmessage.MustNewName("_http._tcp.local."),
			Type:  dnsmessage.TypePTR,
			Class: dnsmessage.ClassINET,
		},
		Body: &dnsmessage.AResource{A: [4]byte{10, 0, 0, 1}},
	})

	// PTR target that is not a service instance name: parse fails, no event.
	session.handleExpired(mustBuildPTR(t, "_http._tcp.local.", "local.", 0))

	require.Len(t, events(), 1)
	assert.Len(t, session.monitoredCacheKeys(), 5, "instance should remain monitored")
}

func TestBrowseExpiredOtherServiceIgnored(t *testing.T) {
	emit, events := collectEvents()
	session := newBrowseSession(t.Context(), "_http._tcp", emit)

	feedInstance(t, session, "My Web", "myhost.local.", "192.168.1.100")

	session.handleExpired(mustBuildPTR(t, "_ipp._tcp.local.", "My Web._ipp._tcp.local.", 0))

	require.Len(t, events(), 1)
	assert.Len(t, session.monitoredCacheKeys(), 5, "instance should remain monitored")
}

func TestAnswerHandlerHandleExpiredFanOut(t *testing.T) {
	log := logging.NewDefaultLoggerFactory().NewLogger("test")
	handler := newAnswerHandler(log, "test", newCache(time.Now))

	emitHTTP, httpEvents := collectEvents()
	httpSession := newBrowseSession(t.Context(), "_http._tcp", emitHTTP)
	handler.registerBrowseSession(httpSession)

	emitIPP, ippEvents := collectEvents()
	ippSession := newBrowseSession(t.Context(), "_ipp._tcp", emitIPP)
	handler.registerBrowseSession(ippSession)

	enumSession := newEnumerateSession(t.Context(), func(string) {})
	handler.registerEnumerateSession(enumSession)

	feedInstance(t, httpSession, "Web", "host-a.local.", "10.0.0.1")

	ippFQDN := "Printer._ipp._tcp.local."
	ippSession.processRecord(mustBuildPTR(t, "_ipp._tcp.local.", ippFQDN, 4500), "")
	ippSession.processRecord(mustBuildSRV(t, ippFQDN, "host-b.local.", 631, 120), "")
	ippSession.processRecord(mustBuildTXT(t, ippFQDN, []string{""}, 4500), "")
	ippSession.processRecord(mustBuildA(t, "host-b.local.", "10.0.0.2", 120), "")

	handler.handleExpired([]dnsmessage.Resource{
		mustBuildPTR(t, "_http._tcp.local.", "Web._http._tcp.local.", 0),
		mustBuildPTR(t, "_ipp._tcp.local.", "Printer._ipp._tcp.local.", 0),
	})

	httpEvts := httpEvents()
	require.Len(t, httpEvts, 2)
	assert.Equal(t, ServiceRemoved, httpEvts[1].Type)
	assert.Equal(t, "Web", httpEvts[1].Instance.Instance)

	ippEvts := ippEvents()
	require.Len(t, ippEvts, 2)
	assert.Equal(t, ServiceRemoved, ippEvts[1].Type)
	assert.Equal(t, "Printer", ippEvts[1].Instance.Instance)
}

func TestAnswerHandlerHandleExpiredNoSessions(t *testing.T) {
	log := logging.NewDefaultLoggerFactory().NewLogger("test")
	handler := newAnswerHandler(log, "test", newCache(time.Now))

	// No sessions registered: must be a no-op, not a panic.
	handler.handleExpired([]dnsmessage.Resource{
		mustBuildPTR(t, "_http._tcp.local.", "My Web._http._tcp.local.", 0),
	})
}
