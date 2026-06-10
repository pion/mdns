// SPDX-FileCopyrightText: The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package mdns

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pion/logging"
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
	candidates := ca.takeRefreshCandidates([]cacheKey{key})
	assert.Empty(t, candidates)

	// At 82s — past 80% threshold (even with up to 2% jitter = 82%).
	clock.advance(3 * time.Second)
	candidates = ca.takeRefreshCandidates([]cacheKey{key})
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

	var elapsed time.Duration

	for _, target := range thresholdTimes {
		clock.advance(target - elapsed)
		elapsed = target

		candidates := ca.takeRefreshCandidates([]cacheKey{key})
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
	candidates := ca.takeRefreshCandidates([]cacheKey{key})
	require.Len(t, candidates, 1)

	// Re-insert same record with new TTL (simulates receiving a refresh response).
	rec2 := mustBuildA(t, "host.local.", "192.168.1.1", 100)
	ca.insert(rec2, clock.now())

	// refreshesSent should be reset. Advance to ~82% of new TTL.
	clock.advance(82 * time.Second)
	candidates = ca.takeRefreshCandidates([]cacheKey{key})
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
	candidates := ca.takeRefreshCandidates([]cacheKey{monitoredKey})

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
		candidates := ca.takeRefreshCandidates([]cacheKey{key})

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
	candidates := ca.takeRefreshCandidates([]cacheKey{key})
	assert.Empty(t, candidates)
}

func TestRefreshSkipsGoodbyeEntries(t *testing.T) {
	clock := newTestClock()
	ca := newCache(clock.now)

	ca.insert(mustBuildA(t, "host.local.", "192.168.1.1", 100), clock.now())

	// Goodbye the record (TTL=0): retained ~1s but must not be refreshed.
	ca.insert(mustBuildA(t, "host.local.", "192.168.1.1", 0), clock.now())

	key := cacheKey{
		name:    "host.local.",
		rrType:  dnsmessage.TypeA,
		rrClass: dnsmessage.ClassINET,
	}

	// 900ms is past 80% of the 1s goodbye retention.
	clock.advance(900 * time.Millisecond)
	candidates := ca.takeRefreshCandidates([]cacheKey{key})
	assert.Empty(t, candidates)
}

func TestRefreshDuplicateKeysCoalesced(t *testing.T) {
	clock := newTestClock()
	ca := newCache(clock.now)

	ca.insert(mustBuildA(t, "host.local.", "192.168.1.1", 100), clock.now())

	key := cacheKey{
		name:    "host.local.",
		rrType:  dnsmessage.TypeA,
		rrClass: dnsmessage.ClassINET,
	}

	// The same key monitored by multiple sessions must yield one candidate.
	clock.advance(82 * time.Second)
	candidates := ca.takeRefreshCandidates([]cacheKey{key, key, key})
	assert.Len(t, candidates, 1)
}

// ---------------------------------------------------------------------------
// Refresh question sending and background loops
// ---------------------------------------------------------------------------

// captureWriter is a questionWriter that records written packets.
type captureWriter struct {
	mu      sync.Mutex
	packets [][]byte
}

func (w *captureWriter) writeQuestion(raw []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.packets = append(w.packets, append([]byte(nil), raw...))
}

func (w *captureWriter) count() int {
	w.mu.Lock()
	defer w.mu.Unlock()

	return len(w.packets)
}

func TestSendRefreshQuestionsBatching(t *testing.T) {
	log := logging.NewDefaultLoggerFactory().NewLogger("test")
	writer := &captureWriter{}
	cli := newClient(log, "test", writer, true, false, newCache(time.Now))

	// 25 keys batch into 3 messages (10 + 10 + 5).
	keys := make([]cacheKey, 0, 25)
	for i := range 25 {
		keys = append(keys, cacheKey{
			name:    fmt.Sprintf("host%d.local.", i),
			rrType:  dnsmessage.TypeA,
			rrClass: dnsmessage.ClassINET,
		})
	}

	cli.sendRefreshQuestions(keys)
	require.Equal(t, 3, writer.count())

	var total int

	for _, raw := range writer.packets {
		var msg dnsmessage.Message

		require.NoError(t, msg.Unpack(raw))
		assert.False(t, msg.Response)
		total += len(msg.Questions)
	}

	assert.Equal(t, 25, total)
}

func TestSendRefreshQuestionsSkipsInvalidName(t *testing.T) {
	log := logging.NewDefaultLoggerFactory().NewLogger("test")
	writer := &captureWriter{}
	cli := newClient(log, "test", writer, true, false, newCache(time.Now))

	keys := []cacheKey{
		// Longer than the 255-byte DNS name limit: dropped with a warning.
		{name: strings.Repeat("a", 300) + ".", rrType: dnsmessage.TypeA, rrClass: dnsmessage.ClassINET},
		{name: "ok.local.", rrType: dnsmessage.TypeAAAA, rrClass: dnsmessage.ClassINET},
	}

	cli.sendRefreshQuestions(keys)
	require.Equal(t, 1, writer.count())

	var msg dnsmessage.Message

	require.NoError(t, msg.Unpack(writer.packets[0]))
	require.Len(t, msg.Questions, 1)
	assert.Equal(t, "ok.local.", msg.Questions[0].Name.String())
	assert.Equal(t, dnsmessage.TypeAAAA, msg.Questions[0].Type)
}

func TestAnswerHandlerMonitoredCacheKeys(t *testing.T) {
	log := logging.NewDefaultLoggerFactory().NewLogger("test")
	handler := newAnswerHandler(log, "test", newCache(time.Now))

	assert.Empty(t, handler.monitoredCacheKeys())

	browse := newBrowseSession(t.Context(), "_http._tcp", func(ServiceEvent) {})
	handler.registerBrowseSession(browse)

	enum := newEnumerateSession(t.Context(), func(string) {})
	handler.registerEnumerateSession(enum)

	keys := handler.monitoredCacheKeys()
	require.Len(t, keys, 2)
	assert.Equal(t, "_http._tcp.local.", keys[0].name)
	assert.Equal(t, "_services._dns-sd._udp.local.", keys[1].name)
}

func TestRefreshLoopSendsQuestions(t *testing.T) {
	log := logging.NewDefaultLoggerFactory().NewLogger("test")
	writer := &captureWriter{}
	ca := newCache(time.Now)
	cli := newClient(log, "test", writer, true, false, ca)

	browse := newBrowseSession(t.Context(), "_http._tcp", func(ServiceEvent) {})
	cli.handler.registerBrowseSession(browse)

	// Insert a monitored PTR record already past its first refresh threshold.
	rec := mustBuildPTR(t, "_http._tcp.local.", "My Web._http._tcp.local.", 100)
	ca.insert(rec, time.Now().Add(-99*time.Second))

	conn := &Conn{
		client:               cli,
		cache:                ca,
		stopBackground:       make(chan struct{}),
		cacheRefresh:         true,
		refreshCheckInterval: 10 * time.Millisecond,
	}

	done := make(chan struct{})

	go func() {
		defer close(done)
		conn.refreshLoop()
	}()

	assert.Eventually(t, func() bool {
		return writer.count() > 0
	}, time.Second, 10*time.Millisecond)

	close(conn.stopBackground)
	<-done

	var msg dnsmessage.Message

	require.NoError(t, msg.Unpack(writer.packets[0]))
	require.NotEmpty(t, msg.Questions)
	assert.Equal(t, "_http._tcp.local.", msg.Questions[0].Name.String())
	assert.Equal(t, dnsmessage.TypePTR, msg.Questions[0].Type)
}

func TestSweepLoopRemovesExpired(t *testing.T) {
	ca := newCache(time.Now)

	// Insert a record that expired one second ago.
	ca.insert(mustBuildA(t, "host.local.", "10.0.0.1", 1), time.Now().Add(-2*time.Second))

	conn := &Conn{
		cache:          ca,
		stopBackground: make(chan struct{}),
		sweepInterval:  10 * time.Millisecond,
	}

	done := make(chan struct{})

	go func() {
		defer close(done)
		conn.sweepLoop()
	}()

	assert.Eventually(t, func() bool {
		ca.mu.RLock()
		defer ca.mu.RUnlock()

		return len(ca.entries) == 0
	}, time.Second, 10*time.Millisecond)

	close(conn.stopBackground)
	<-done
}
