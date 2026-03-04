// SPDX-FileCopyrightText: The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package mdns

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
)

func TestRefreshAt80Percent(t *testing.T) {
	clock := newTestClock()
	ca := newCache(clock.now)

	rec := mustBuildA(t, "host.local.", "192.168.1.1", 100)
	ca.insert(rec, clock.now())

	key := cacheKey{
		name:    "host.local.",
		rrType:  dnsmessage.TypeA,
		rrClass: dnsmessage.ClassINET,
	}

	// At 79s — not yet due.
	clock.advance(79 * time.Second)
	candidates := ca.dueForRefresh([]cacheKey{key})
	assert.Empty(t, candidates)

	// At 82s — past 80% threshold (even with up to 2% jitter = 82%).
	clock.advance(3 * time.Second)
	candidates = ca.dueForRefresh([]cacheKey{key})
	require.Len(t, candidates, 1)
	assert.Equal(t, "host.local.", candidates[0].name)
	assert.Equal(t, dnsmessage.TypeA, candidates[0].rrType)
}

func TestRefreshAllFourThresholds(t *testing.T) {
	clock := newTestClock()
	ca := newCache(clock.now)

	rec := mustBuildA(t, "host.local.", "10.0.0.1", 100)
	ca.insert(rec, clock.now())

	key := cacheKey{
		name:    "host.local.",
		rrType:  dnsmessage.TypeA,
		rrClass: dnsmessage.ClassINET,
	}

	var totalCandidates int

	// Advance past each threshold (with jitter margin).
	// 80% + 2% jitter max = 82s, 85%+2% = 87s, 90%+2% = 92s, 95%+2% = 97s.
	thresholdTimes := []time.Duration{
		82 * time.Second,
		87 * time.Second,
		92 * time.Second,
		97 * time.Second,
	}

	for _, target := range thresholdTimes {
		elapsed := target - clock.current.Sub(
			time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		)
		if elapsed > 0 {
			clock.advance(elapsed)
		}

		candidates := ca.dueForRefresh([]cacheKey{key})
		totalCandidates += len(candidates)
	}

	assert.Equal(t, 4, totalCandidates)
}

func TestRefreshResetOnUpdate(t *testing.T) {
	clock := newTestClock()
	ca := newCache(clock.now)

	rec := mustBuildA(t, "host.local.", "192.168.1.1", 100)
	ca.insert(rec, clock.now())

	key := cacheKey{
		name:    "host.local.",
		rrType:  dnsmessage.TypeA,
		rrClass: dnsmessage.ClassINET,
	}

	// Advance to 82s, trigger first refresh.
	clock.advance(82 * time.Second)
	candidates := ca.dueForRefresh([]cacheKey{key})
	require.Len(t, candidates, 1)

	// Re-insert same record with new TTL (simulates receiving a refresh response).
	rec2 := mustBuildA(t, "host.local.", "192.168.1.1", 100)
	ca.insert(rec2, clock.now())

	// refreshesSent should be reset. Advance to ~82% of new TTL.
	clock.advance(82 * time.Second)
	candidates = ca.dueForRefresh([]cacheKey{key})
	require.Len(t, candidates, 1, "should get refresh candidate after TTL reset")
}

func TestRefreshOnlyMonitoredKeys(t *testing.T) {
	clock := newTestClock()
	ca := newCache(clock.now)

	// Insert two records.
	ca.insert(mustBuildA(t, "monitored.local.", "10.0.0.1", 100), clock.now())
	ca.insert(mustBuildA(t, "unmonitored.local.", "10.0.0.2", 100), clock.now())

	// Only monitor one.
	monitoredKey := cacheKey{
		name:    "monitored.local.",
		rrType:  dnsmessage.TypeA,
		rrClass: dnsmessage.ClassINET,
	}

	clock.advance(82 * time.Second)
	candidates := ca.dueForRefresh([]cacheKey{monitoredKey})

	// Only the monitored record should be a candidate.
	require.Len(t, candidates, 1)
	assert.Equal(t, "monitored.local.", candidates[0].name)
}

func TestRefreshJitter(t *testing.T) {
	// With 2% jitter on a 100s TTL, the first threshold is between 80s and 82s.
	// At 81s (fraction=0.81), some attempts should trigger (jitter < 0.01)
	// and some should not (jitter > 0.01).
	key := cacheKey{
		name:    "host.local.",
		rrType:  dnsmessage.TypeA,
		rrClass: dnsmessage.ClassINET,
	}

	triggeredAt81 := 0

	for range 200 {
		clock := newTestClock()
		ca := newCache(clock.now)

		rec := mustBuildA(t, "host.local.", "192.168.1.1", 100)
		ca.insert(rec, clock.now())

		clock.advance(81 * time.Second)
		candidates := ca.dueForRefresh([]cacheKey{key})

		if len(candidates) > 0 {
			triggeredAt81++
		}
	}

	// At fraction=0.81, triggers when jitter < 0.01 (~50% of [0, 0.02)).
	// Verify it's not deterministic: some trigger, some don't.
	assert.Greater(t, triggeredAt81, 0, "should sometimes trigger at 81%%")
	assert.Less(t, triggeredAt81, 200, "should not always trigger at 81%%")
}

func TestRefreshExpiredEntrySkipped(t *testing.T) {
	clock := newTestClock()
	ca := newCache(clock.now)

	rec := mustBuildA(t, "host.local.", "192.168.1.1", 100)
	ca.insert(rec, clock.now())

	key := cacheKey{
		name:    "host.local.",
		rrType:  dnsmessage.TypeA,
		rrClass: dnsmessage.ClassINET,
	}

	// Advance past TTL expiry.
	clock.advance(101 * time.Second)
	candidates := ca.dueForRefresh([]cacheKey{key})
	assert.Empty(t, candidates)
}
