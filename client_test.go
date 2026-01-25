// SPDX-FileCopyrightText: The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package mdns

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/stretchr/testify/assert"
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
