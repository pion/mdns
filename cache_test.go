// SPDX-FileCopyrightText: The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package mdns

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
)

// ---------------------------------------------------------------------------
// Test clock — deterministic time for cache tests
// ---------------------------------------------------------------------------

type testClock struct {
	current time.Time
}

func (tc *testClock) now() time.Time {
	return tc.current
}

func (tc *testClock) advance(dur time.Duration) {
	tc.current = tc.current.Add(dur)
}

func newTestClock() *testClock {
	return &testClock{current: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)}
}

// ---------------------------------------------------------------------------
// Test helpers — build records without error handling boilerplate
// ---------------------------------------------------------------------------

func mustBuildA(t *testing.T, name, addr string, ttl uint32) dnsmessage.Resource {
	t.Helper()

	res, err := buildAResource(name, netip.MustParseAddr(addr), ttl)
	require.NoError(t, err)

	return res
}

func mustBuildAAAA(t *testing.T, name, addr string, ttl uint32) dnsmessage.Resource {
	t.Helper()

	res, err := buildAAAAResource(name, netip.MustParseAddr(addr), ttl)
	require.NoError(t, err)

	return res
}

func mustBuildPTR(t *testing.T, name, target string, ttl uint32) dnsmessage.Resource {
	t.Helper()

	res, err := buildPTRResource(name, target, ttl)
	require.NoError(t, err)

	return res
}

func mustBuildSRV(t *testing.T, name, target string, port uint16, ttl uint32) dnsmessage.Resource {
	t.Helper()

	res, err := buildSRVResource(name, target, port, 0, 0, ttl)
	require.NoError(t, err)

	return res
}

func mustBuildTXT(t *testing.T, name string, txts []string, ttl uint32) dnsmessage.Resource {
	t.Helper()

	res, err := buildTXTResource(name, txts, ttl)
	require.NoError(t, err)

	return res
}

// ---------------------------------------------------------------------------
// Basic insert/lookup — one test per record type
// ---------------------------------------------------------------------------

func TestCacheInsertLookupA(t *testing.T) {
	clock := newTestClock()
	ca := newCache(clock.now)
	rec := mustBuildA(t, "host.local.", "192.168.1.1", 120)

	ca.insert(rec, clock.now())

	results := ca.lookup("host.local.", dnsmessage.TypeA, dnsmessage.ClassINET)
	require.Len(t, results, 1)
	assert.Equal(t, dnsmessage.TypeA, results[0].Header.Type)

	body, ok := results[0].Body.(*dnsmessage.AResource)
	require.True(t, ok)
	assert.Equal(t, [4]byte{192, 168, 1, 1}, body.A)
}

func TestCacheInsertLookupAAAA(t *testing.T) {
	clock := newTestClock()
	ca := newCache(clock.now)
	rec := mustBuildAAAA(t, "v6host.local.", "fd00::1", 120)

	ca.insert(rec, clock.now())

	results := ca.lookup("v6host.local.", dnsmessage.TypeAAAA, dnsmessage.ClassINET)
	require.Len(t, results, 1)

	body, ok := results[0].Body.(*dnsmessage.AAAAResource)
	require.True(t, ok)
	assert.Equal(t, netip.MustParseAddr("fd00::1").As16(), body.AAAA)
}

func TestCacheInsertLookupPTR(t *testing.T) {
	clock := newTestClock()
	ca := newCache(clock.now)
	rec := mustBuildPTR(t, "_http._tcp.local.", "My Web._http._tcp.local.", 4500)

	ca.insert(rec, clock.now())

	results := ca.lookup("_http._tcp.local.", dnsmessage.TypePTR, dnsmessage.ClassINET)
	require.Len(t, results, 1)

	target, err := parsePTRTarget(results[0].Body)
	require.NoError(t, err)
	assert.Equal(t, "My Web._http._tcp.local.", target)
}

func TestCacheInsertLookupSRV(t *testing.T) {
	clock := newTestClock()
	ca := newCache(clock.now)
	rec := mustBuildSRV(t, "svc._http._tcp.local.", "myhost.local.", 8080, 120)

	ca.insert(rec, clock.now())

	results := ca.lookup("svc._http._tcp.local.", dnsmessage.TypeSRV, dnsmessage.ClassINET)
	require.Len(t, results, 1)

	target, port, _, _, err := parseSRVData(results[0].Body) //nolint:dogsled
	require.NoError(t, err)
	assert.Equal(t, "myhost.local.", target)
	assert.Equal(t, uint16(8080), port)
}

func TestCacheInsertLookupTXT(t *testing.T) {
	clock := newTestClock()
	ca := newCache(clock.now)
	rec := mustBuildTXT(t, "svc._http._tcp.local.", []string{"txtvers=1", "path=/"}, 4500)

	ca.insert(rec, clock.now())

	results := ca.lookup("svc._http._tcp.local.", dnsmessage.TypeTXT, dnsmessage.ClassINET)
	require.Len(t, results, 1)

	txts, err := parseTXTData(results[0].Body)
	require.NoError(t, err)
	assert.Equal(t, []string{"txtvers=1", "path=/"}, txts)
}

// ---------------------------------------------------------------------------
// TTL recalculation
// ---------------------------------------------------------------------------

func TestCacheLookupRemainingTTL(t *testing.T) {
	clock := newTestClock()
	ca := newCache(clock.now)
	rec := mustBuildA(t, "host.local.", "192.168.1.1", 120)

	ca.insert(rec, clock.now())
	clock.advance(30 * time.Second)

	results := ca.lookup("host.local.", dnsmessage.TypeA, dnsmessage.ClassINET)
	require.Len(t, results, 1)
	assert.Equal(t, uint32(90), results[0].Header.TTL)
}

// ---------------------------------------------------------------------------
// Case-insensitive lookup
// ---------------------------------------------------------------------------

func TestCacheLookupCaseInsensitive(t *testing.T) {
	clock := newTestClock()
	ca := newCache(clock.now)
	rec := mustBuildA(t, "Test.Local.", "10.0.0.1", 120)

	ca.insert(rec, clock.now())

	results := ca.lookup("test.local.", dnsmessage.TypeA, dnsmessage.ClassINET)
	require.Len(t, results, 1)

	// Also try uppercase lookup.
	results = ca.lookup("TEST.LOCAL.", dnsmessage.TypeA, dnsmessage.ClassINET)
	require.Len(t, results, 1)
}

// ---------------------------------------------------------------------------
// Multiple records per key
// ---------------------------------------------------------------------------

func TestCacheMultipleRecordsSameName(t *testing.T) {
	clock := newTestClock()
	ca := newCache(clock.now)

	ca.insert(mustBuildA(t, "host.local.", "192.168.1.1", 120), clock.now())
	ca.insert(mustBuildA(t, "host.local.", "192.168.1.2", 120), clock.now())

	results := ca.lookup("host.local.", dnsmessage.TypeA, dnsmessage.ClassINET)
	assert.Len(t, results, 2)
}

func TestCacheMultiplePTRTargets(t *testing.T) {
	clock := newTestClock()
	ca := newCache(clock.now)

	ca.insert(mustBuildPTR(t, "_http._tcp.local.", "Web1._http._tcp.local.", 4500), clock.now())
	ca.insert(mustBuildPTR(t, "_http._tcp.local.", "Web2._http._tcp.local.", 4500), clock.now())

	results := ca.lookup("_http._tcp.local.", dnsmessage.TypePTR, dnsmessage.ClassINET)
	assert.Len(t, results, 2)
}

// ---------------------------------------------------------------------------
// TTL expiration
// ---------------------------------------------------------------------------

func TestCacheTTLExpiration(t *testing.T) {
	clock := newTestClock()
	ca := newCache(clock.now)

	ca.insert(mustBuildA(t, "host.local.", "192.168.1.1", 120), clock.now())
	clock.advance(120 * time.Second)

	results := ca.lookup("host.local.", dnsmessage.TypeA, dnsmessage.ClassINET)
	assert.Empty(t, results)
}

func TestCacheTTLValidBeforeExpiry(t *testing.T) {
	clock := newTestClock()
	ca := newCache(clock.now)

	ca.insert(mustBuildA(t, "host.local.", "192.168.1.1", 120), clock.now())
	clock.advance(119 * time.Second)

	results := ca.lookup("host.local.", dnsmessage.TypeA, dnsmessage.ClassINET)
	require.Len(t, results, 1)
	assert.Equal(t, uint32(1), results[0].Header.TTL)
}

// ---------------------------------------------------------------------------
// Sweep
// ---------------------------------------------------------------------------

func TestCacheSweepRemovesExpired(t *testing.T) {
	clock := newTestClock()
	ca := newCache(clock.now)

	ca.insert(mustBuildA(t, "gone.local.", "10.0.0.1", 60), clock.now())
	ca.insert(mustBuildA(t, "alive.local.", "10.0.0.2", 300), clock.now())
	clock.advance(120 * time.Second)

	ca.sweep()

	assert.Empty(t, ca.lookup("gone.local.", dnsmessage.TypeA, dnsmessage.ClassINET))
	assert.Len(t, ca.lookup("alive.local.", dnsmessage.TypeA, dnsmessage.ClassINET), 1)
}

func TestCacheSweepEmpty(t *testing.T) {
	clock := newTestClock()
	ca := newCache(clock.now)

	// Should not panic or error.
	ca.sweep()
	assert.Equal(t, 0, ca.len())
}

// ---------------------------------------------------------------------------
// TTL update — same rdata, new TTL
// ---------------------------------------------------------------------------

func TestCacheTTLUpdate(t *testing.T) {
	clock := newTestClock()
	ca := newCache(clock.now)

	ca.insert(mustBuildA(t, "host.local.", "192.168.1.1", 60), clock.now())
	clock.advance(10 * time.Second)

	// Re-insert same rdata with new TTL.
	ca.insert(mustBuildA(t, "host.local.", "192.168.1.1", 120), clock.now())

	// Should still be one entry, not two.
	assert.Equal(t, 1, ca.len())

	// Remaining TTL should be based on the new insert: 120s from t=10s.
	results := ca.lookup("host.local.", dnsmessage.TypeA, dnsmessage.ClassINET)
	require.Len(t, results, 1)
	assert.Equal(t, uint32(120), results[0].Header.TTL)
}

// ---------------------------------------------------------------------------
// Goodbye packets — RFC 6762 §10.1
// ---------------------------------------------------------------------------

func TestCacheGoodbyeExistingRecord(t *testing.T) {
	clock := newTestClock()
	ca := newCache(clock.now)

	ca.insert(mustBuildA(t, "host.local.", "192.168.1.1", 120), clock.now())

	// Send goodbye (TTL=0).
	goodbye := mustBuildA(t, "host.local.", "192.168.1.1", 0)
	ca.insert(goodbye, clock.now())

	// Still visible (expires in 1s).
	results := ca.lookup("host.local.", dnsmessage.TypeA, dnsmessage.ClassINET)
	assert.Len(t, results, 1)
}

func TestCacheGoodbyeExpiration(t *testing.T) {
	clock := newTestClock()
	ca := newCache(clock.now)

	ca.insert(mustBuildA(t, "host.local.", "192.168.1.1", 120), clock.now())

	goodbye := mustBuildA(t, "host.local.", "192.168.1.1", 0)
	ca.insert(goodbye, clock.now())
	clock.advance(2 * time.Second)

	// After 2s the goodbye entry should be expired.
	results := ca.lookup("host.local.", dnsmessage.TypeA, dnsmessage.ClassINET)
	assert.Empty(t, results)
}

func TestCacheGoodbyeUnknownRecord(t *testing.T) {
	clock := newTestClock()
	ca := newCache(clock.now)

	// Goodbye for a record not in cache — should create a 1s entry.
	goodbye := mustBuildA(t, "host.local.", "192.168.1.1", 0)
	ca.insert(goodbye, clock.now())

	assert.Equal(t, 1, ca.len())

	clock.advance(2 * time.Second)
	assert.Equal(t, 0, ca.len())
}

// ---------------------------------------------------------------------------
// Cache-flush bit — RFC 6762 §10.2
// ---------------------------------------------------------------------------

func TestCacheFlushBitStripped(t *testing.T) {
	clock := newTestClock()
	ca := newCache(clock.now)

	rec := mustBuildA(t, "host.local.", "192.168.1.1", 120)
	rec.Header.Class |= rrClassCacheFlush

	ca.insert(rec, clock.now())

	// Lookup without the flush bit should find the record.
	results := ca.lookup("host.local.", dnsmessage.TypeA, dnsmessage.ClassINET)
	require.Len(t, results, 1)
}

func TestCacheFlushOldEntries(t *testing.T) {
	clock := newTestClock()
	ca := newCache(clock.now)

	// Insert old record at t=0.
	ca.insert(mustBuildA(t, "host.local.", "192.168.1.1", 300), clock.now())
	clock.advance(2 * time.Second)

	// Insert new record with cache-flush bit at t=2s.
	flusher := mustBuildA(t, "host.local.", "192.168.1.2", 120)
	flusher.Header.Class |= rrClassCacheFlush
	ca.insert(flusher, clock.now())

	// Old entry is marked to expire in 1s (at t=3s). Advance past that.
	clock.advance(2 * time.Second)

	results := ca.lookup("host.local.", dnsmessage.TypeA, dnsmessage.ClassINET)
	require.Len(t, results, 1)

	// Only the new record should survive.
	body, ok := results[0].Body.(*dnsmessage.AResource)
	require.True(t, ok)
	assert.Equal(t, [4]byte{192, 168, 1, 2}, body.A)
}

func TestCacheFlushPreservesRecent(t *testing.T) {
	clock := newTestClock()
	ca := newCache(clock.now)

	// Insert record A at t=0.5s (recent).
	clock.advance(500 * time.Millisecond)
	ca.insert(mustBuildA(t, "host.local.", "192.168.1.1", 300), clock.now())

	// Insert record B with cache-flush bit at t=0.8s.
	clock.advance(300 * time.Millisecond)
	flusher := mustBuildA(t, "host.local.", "192.168.1.2", 120)
	flusher.Header.Class |= rrClassCacheFlush
	ca.insert(flusher, clock.now())

	// Record A was created 300ms ago (< 1s), so it is preserved.
	results := ca.lookup("host.local.", dnsmessage.TypeA, dnsmessage.ClassINET)
	assert.Len(t, results, 2)
}

// ---------------------------------------------------------------------------
// Topology change — RFC 6762 §10.3
// ---------------------------------------------------------------------------

func TestCacheFlushAll(t *testing.T) {
	clock := newTestClock()
	ca := newCache(clock.now)

	ca.insert(mustBuildA(t, "a.local.", "10.0.0.1", 120), clock.now())
	ca.insert(mustBuildA(t, "b.local.", "10.0.0.2", 120), clock.now())
	assert.Equal(t, 2, ca.len())

	ca.flushAll()
	assert.Equal(t, 0, ca.len())
}

func TestCacheReduceTTLs(t *testing.T) {
	clock := newTestClock()
	ca := newCache(clock.now)

	ca.insert(mustBuildA(t, "long.local.", "10.0.0.1", 300), clock.now())
	ca.insert(mustBuildA(t, "short.local.", "10.0.0.2", 3), clock.now())

	ca.reduceTTLs(5 * time.Second)

	// Long TTL should be capped to ~5s.
	results := ca.lookup("long.local.", dnsmessage.TypeA, dnsmessage.ClassINET)
	require.Len(t, results, 1)
	assert.Equal(t, uint32(5), results[0].Header.TTL)

	// Short TTL (3s) is already under 5s, should be unchanged.
	results = ca.lookup("short.local.", dnsmessage.TypeA, dnsmessage.ClassINET)
	require.Len(t, results, 1)
	assert.Equal(t, uint32(3), results[0].Header.TTL)
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

func TestCacheLookupEmpty(t *testing.T) {
	clock := newTestClock()
	ca := newCache(clock.now)

	results := ca.lookup("missing.local.", dnsmessage.TypeA, dnsmessage.ClassINET)
	assert.Empty(t, results)

	// Different class also returns empty.
	results = ca.lookup("missing.local.", dnsmessage.TypeA, dnsmessage.ClassCHAOS)
	assert.Empty(t, results)
}

func TestCacheLen(t *testing.T) {
	clock := newTestClock()
	ca := newCache(clock.now)

	assert.Equal(t, 0, ca.len())

	ca.insert(mustBuildA(t, "host.local.", "10.0.0.1", 60), clock.now())
	ca.insert(mustBuildA(t, "host.local.", "10.0.0.2", 120), clock.now())
	assert.Equal(t, 2, ca.len())

	// Expire the first record.
	clock.advance(60 * time.Second)
	assert.Equal(t, 1, ca.len())
}

// ---------------------------------------------------------------------------
// Concurrency — run with -race
// ---------------------------------------------------------------------------

func TestCacheConcurrency(t *testing.T) {
	clock := newTestClock()
	ca := newCache(clock.now)
	rec := mustBuildA(t, "host.local.", "192.168.1.1", 120)

	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(3)

		go func() {
			defer wg.Done()
			ca.insert(rec, clock.now())
		}()

		go func() {
			defer wg.Done()
			ca.lookup("host.local.", dnsmessage.TypeA, dnsmessage.ClassINET)
		}()

		go func() {
			defer wg.Done()
			ca.sweep()
		}()
	}

	wg.Wait()
}

// ---------------------------------------------------------------------------
// resourceDataEqual — per-type coverage
// ---------------------------------------------------------------------------

func TestResourceDataEqualA(t *testing.T) {
	recA := mustBuildA(t, "host.local.", "192.168.1.1", 120)
	recB := mustBuildA(t, "host.local.", "192.168.1.1", 60)
	recC := mustBuildA(t, "host.local.", "192.168.1.2", 120)

	assert.True(t, resourceDataEqual(recA, recB), "same A rdata, different TTL")
	assert.False(t, resourceDataEqual(recA, recC), "different A address")
}

func TestResourceDataEqualAAAA(t *testing.T) {
	recA := mustBuildAAAA(t, "host.local.", "fd00::1", 120)
	recB := mustBuildAAAA(t, "host.local.", "fd00::1", 60)
	recC := mustBuildAAAA(t, "host.local.", "fd00::2", 120)

	assert.True(t, resourceDataEqual(recA, recB), "same AAAA rdata")
	assert.False(t, resourceDataEqual(recA, recC), "different AAAA address")
}

func TestResourceDataEqualPTR(t *testing.T) {
	recA := mustBuildPTR(t, "_http._tcp.local.", "Web._http._tcp.local.", 4500)
	recB := mustBuildPTR(t, "_http._tcp.local.", "Web._http._tcp.local.", 120)
	recC := mustBuildPTR(t, "_ipp._tcp.local.", "Other._ipp._tcp.local.", 4500)

	assert.True(t, resourceDataEqual(recA, recB), "same PTR target")
	assert.False(t, resourceDataEqual(recA, recC), "different PTR target")
}

func TestResourceDataEqualSRV(t *testing.T) {
	recA := mustBuildSRV(t, "svc._tcp.local.", "host.local.", 80, 120)
	recB := mustBuildSRV(t, "svc._tcp.local.", "host.local.", 80, 60)
	recC := mustBuildSRV(t, "svc._tcp.local.", "host.local.", 8080, 120)

	assert.True(t, resourceDataEqual(recA, recB), "same SRV rdata")
	assert.False(t, resourceDataEqual(recA, recC), "different SRV port")
}

func TestResourceDataEqualTXT(t *testing.T) {
	recA := mustBuildTXT(t, "svc._tcp.local.", []string{"a=1", "b=2"}, 120)
	recB := mustBuildTXT(t, "svc._tcp.local.", []string{"a=1", "b=2"}, 60)
	recC := mustBuildTXT(t, "svc._tcp.local.", []string{"a=1", "c=3"}, 120)
	recD := mustBuildTXT(t, "svc._tcp.local.", []string{"a=1"}, 120)

	assert.True(t, resourceDataEqual(recA, recB), "same TXT strings")
	assert.False(t, resourceDataEqual(recA, recC), "different TXT strings")
	assert.False(t, resourceDataEqual(recA, recD), "different TXT length")
}

func TestResourceDataEqualDifferentTypes(t *testing.T) {
	recA := mustBuildA(t, "host.local.", "192.168.1.1", 120)
	recAAAA := mustBuildAAAA(t, "host.local.", "fd00::1", 120)

	assert.False(t, resourceDataEqual(recA, recAAAA))
}

func TestResourceDataEqualNilBody(t *testing.T) {
	recA := mustBuildA(t, "host.local.", "192.168.1.1", 120)
	recNil := dnsmessage.Resource{
		Header: recA.Header,
		Body:   nil,
	}

	assert.False(t, resourceDataEqual(recA, recNil))
}

func TestResourceDataEqualDifferentNames(t *testing.T) {
	recA := mustBuildA(t, "a.local.", "192.168.1.1", 120)
	recB := mustBuildA(t, "b.local.", "192.168.1.1", 120)

	assert.False(t, resourceDataEqual(recA, recB))
}
