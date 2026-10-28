// SPDX-FileCopyrightText: The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package mdns

import (
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
)

// fakeTimer implements probeTimer for deterministic testing.
type fakeTimer struct {
	ch      chan time.Time
	stopped bool
}

func (t *fakeTimer) Chan() <-chan time.Time { return t.ch }

func (t *fakeTimer) Stop() bool {
	old := !t.stopped
	t.stopped = true

	return old
}

func (t *fakeTimer) fire() { t.ch <- time.Time{} }

// testHarness sets up a probeManager with deterministic time, fake writers,
// and helpers for driving the event loop.
type testHarness struct {
	pm        *probeManager
	questions [][]byte
	answers   [][]byte
	renames   []renameEvent
	closed    chan any
	cond      *sync.Cond
	clock     time.Time
	timers    []*fakeTimer
}

func newTestHarness() *testHarness {
	log := logging.NewDefaultLoggerFactory().NewLogger("test")
	th := &testHarness{
		closed: make(chan any),
		clock:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	th.cond = sync.NewCond(&sync.Mutex{})

	qw := &probeTestQuestionWriter{th: th}
	aw := &probeTestAnswerWriter{th: th}

	th.pm = newProbeManager(qw, aw, log, "test", nil, func(oldName, newName string, isHost bool) {
		th.cond.L.Lock()
		th.renames = append(th.renames, renameEvent{oldName: oldName, newName: newName, isHost: isHost})
		th.cond.L.Unlock()
		th.cond.Broadcast()
	})
	th.pm.now = func() time.Time {
		th.cond.L.Lock()
		defer th.cond.L.Unlock()

		return th.clock
	}
	th.pm.randFloat = func() float64 { return 0 } // zero delay.
	th.pm.newTimer = func(d time.Duration) probeTimer {
		ft := &fakeTimer{ch: make(chan time.Time, 1)}
		th.cond.L.Lock()
		th.timers = append(th.timers, ft)
		th.cond.L.Unlock()
		th.cond.Broadcast()

		return ft
	}

	return th
}

func (th *testHarness) advance(d time.Duration) {
	th.cond.L.Lock()
	th.clock = th.clock.Add(d)
	th.cond.L.Unlock()
}

func (th *testHarness) timerCount() int {
	th.cond.L.Lock()
	defer th.cond.L.Unlock()

	return len(th.timers)
}

func (th *testHarness) lastTimer() *fakeTimer {
	th.cond.L.Lock()
	defer th.cond.L.Unlock()

	if len(th.timers) == 0 {
		return nil
	}

	return th.timers[len(th.timers)-1]
}

// await blocks until fn() returns true (checked under cond.L).
// fn is called while holding cond.L.
func (th *testHarness) await(fn func() bool) bool {
	done := make(chan struct{})

	var timedOut atomic.Bool

	go func() {
		th.cond.L.Lock()
		defer th.cond.L.Unlock()

		for !fn() && !timedOut.Load() {
			th.cond.Wait()
		}

		if fn() {
			close(done)
		}
	}()

	select {
	case <-done:
		return true
	case <-time.After(5 * time.Second):
		timedOut.Store(true)
		th.cond.Broadcast()

		return false
	}
}

// awaitTimer blocks until at least n timers exist, returns the last one.
func (th *testHarness) awaitTimer(n int) *fakeTimer {
	ok := th.await(func() bool { return len(th.timers) >= n })
	if !ok {
		return nil
	}

	return th.lastTimer()
}

func (th *testHarness) questionCount() int {
	th.cond.L.Lock()
	defer th.cond.L.Unlock()

	return len(th.questions)
}

func (th *testHarness) answerCount() int {
	th.cond.L.Lock()
	defer th.cond.L.Unlock()

	return len(th.answers)
}

func (th *testHarness) renameCount() int {
	th.cond.L.Lock()
	defer th.cond.L.Unlock()

	return len(th.renames)
}

// awaitAnswers blocks until at least n answers have been written.
func (th *testHarness) awaitAnswers(n int) bool {
	return th.await(func() bool { return len(th.answers) >= n })
}

// awaitRenames blocks until at least n renames have occurred.
func (th *testHarness) awaitRenames(n int) bool { //nolint:unparam
	return th.await(func() bool { return len(th.renames) >= n })
}

// driveToProbing starts run() and waits for the first probe to be sent
// (delay=0). Returns the timer count after the first probe.
func (th *testHarness) driveToProbing(t *testing.T) int {
	t.Helper()

	go th.pm.run(th.closed)
	ft := th.awaitTimer(1)
	require.NotNil(t, ft, "expected timer after first probe")
	require.Equal(t, 1, th.questionCount(), "first probe should be sent")

	return 1 // timer count.
}

// driveToAnnouncing drives through all 3 probes into announcing state.
// Returns the timer count after entering announcing.
func (th *testHarness) driveToAnnouncing(t *testing.T) int {
	t.Helper()
	tc := th.driveToProbing(t)

	// Probes 2 and 3.
	for i := 2; i <= probeCount; i++ {
		th.advance(probeInterval)
		ft := th.awaitTimer(tc)
		require.NotNil(t, ft)
		ft.fire()
		tc++
		th.awaitTimer(tc)
	}

	// Transition to announcing.
	th.advance(probeInterval)
	ft := th.awaitTimer(tc)
	require.NotNil(t, ft)
	ft.fire()
	tc++
	th.awaitTimer(tc)
	require.Equal(t, 1, th.answerCount(), "first announcement")

	return tc
}

// driveToEstablished drives through probing and announcing to established state.
func (th *testHarness) driveToEstablished(t *testing.T) {
	t.Helper()
	tc := th.driveToAnnouncing(t)

	// Second announcement.
	th.advance(announceInterval)
	ft := th.awaitTimer(tc)
	require.NotNil(t, ft)
	ft.fire()
	require.True(t, th.awaitAnswers(2), "second announcement")
}

type probeTestQuestionWriter struct{ th *testHarness }

func (w *probeTestQuestionWriter) writeQuestion(b []byte) {
	w.th.cond.L.Lock()
	w.th.questions = append(w.th.questions, b)
	w.th.cond.L.Unlock()
	w.th.cond.Broadcast()
}

type probeTestAnswerWriter struct{ th *testHarness }

func (w *probeTestAnswerWriter) writeAnswer(_ int, b []byte, _, _ bool, _ *net.UDPAddr) {
	w.th.cond.L.Lock()
	w.th.answers = append(w.th.answers, b)
	w.th.cond.L.Unlock()
	w.th.cond.Broadcast()
}

func testARecord(name string) dnsmessage.Resource {
	n, _ := dnsmessage.NewName(name)

	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  n,
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
			TTL:   120,
		},
		Body: &dnsmessage.AResource{A: [4]byte{192, 168, 1, 1}},
	}
}

func testAAAARecord(name string) dnsmessage.Resource {
	n, _ := dnsmessage.NewName(name)

	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  n,
			Type:  dnsmessage.TypeAAAA,
			Class: dnsmessage.ClassINET,
			TTL:   120,
		},
		Body: &dnsmessage.AAAAResource{AAAA: [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
	}
}

// TestProbeManagerNoSessions verifies that a manager with no sessions
// closes ready immediately and exits.
func TestProbeManagerNoSessions(t *testing.T) {
	th := newTestHarness()

	go th.pm.run(th.closed)
	<-th.pm.ready

	close(th.closed)
	<-th.pm.done
}

// TestProbeManagerFullLifecycle drives a single session through
// delay → probing (3 probes) → announcing (2 announcements) → established.
func TestProbeManagerFullLifecycle(t *testing.T) {
	th := newTestHarness()

	rec := testARecord("myhost.local.")
	th.pm.addSession("myhost.local.", []dnsmessage.Resource{rec}, true)
	assert.True(t, th.pm.isProbing("myhost.local."))

	go th.pm.run(th.closed)

	// Delay is 0 → first probe fires immediately, then a timer is created.
	ft := th.awaitTimer(1)
	require.NotNil(t, ft)
	assert.Equal(t, 1, th.questionCount(), "first probe")

	// Second probe.
	th.advance(probeInterval)
	ft.fire()
	ft = th.awaitTimer(2)
	require.NotNil(t, ft)
	assert.Equal(t, 2, th.questionCount(), "second probe")

	// Third probe.
	th.advance(probeInterval)
	ft.fire()
	ft = th.awaitTimer(3)
	require.NotNil(t, ft)
	assert.Equal(t, 3, th.questionCount(), "third probe")

	// Transition to announcing → first announcement.
	th.advance(probeInterval)
	ft.fire()
	ft = th.awaitTimer(4)
	require.NotNil(t, ft)
	assert.Equal(t, 1, th.answerCount(), "first announcement")

	// Second announcement.
	th.advance(announceInterval)
	ft.fire()
	require.True(t, th.awaitAnswers(2), "second announcement")

	// Should be established now; ready closed.
	<-th.pm.ready
	assert.False(t, th.pm.isProbing("myhost.local."))

	close(th.closed)
	<-th.pm.done
}

// TestProbeQueryFormat verifies the wire format of a probe query.
func TestProbeQueryFormat(t *testing.T) {
	rec := testARecord("myhost.local.")

	raw, err := buildProbeQuery("myhost.local.", []dnsmessage.Resource{rec})
	require.NoError(t, err)

	var msg dnsmessage.Message
	require.NoError(t, msg.Unpack(raw))

	assert.False(t, msg.Header.Response)
	require.Len(t, msg.Questions, 1)
	assert.Equal(t, typeANY, msg.Questions[0].Type)
	assert.True(t, msg.Questions[0].Class&qClassUnicastResponse != 0, "QU bit should be set")
	require.Len(t, msg.Authorities, 1)
	assert.Equal(t, dnsmessage.TypeA, msg.Authorities[0].Header.Type)
}

// TestAnnouncementFormat verifies the wire format of an announcement.
func TestAnnouncementFormat(t *testing.T) {
	aRec := testARecord("myhost.local.")

	ptrName, _ := dnsmessage.NewName("_http._tcp.local.")
	ptrRec := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  ptrName,
			Type:  dnsmessage.TypePTR,
			Class: dnsmessage.ClassINET,
			TTL:   4500,
		},
		Body: &dnsmessage.PTRResource{PTR: ptrName},
	}

	raw, err := buildAnnouncement([]dnsmessage.Resource{aRec}, []dnsmessage.Resource{ptrRec})
	require.NoError(t, err)

	var msg dnsmessage.Message
	require.NoError(t, msg.Unpack(raw))

	assert.True(t, msg.Header.Response)
	assert.True(t, msg.Header.Authoritative)
	require.Len(t, msg.Answers, 2)

	// A record should have cache-flush bit.
	assert.NotZero(t, msg.Answers[0].Header.Class&rrClassCacheFlush, "A record should have cache-flush bit")
	// PTR record should NOT have cache-flush bit (shared).
	assert.Zero(t, msg.Answers[1].Header.Class&rrClassCacheFlush, "PTR record should not have cache-flush bit")
}

// TestConflictDuringProbing verifies that an answer for our name during
// probing triggers a conflict and rename.
func TestConflictDuringProbing(t *testing.T) {
	th := newTestHarness()

	rec := testARecord("myhost.local.")
	th.pm.addSession("myhost.local.", []dnsmessage.Resource{rec}, true)
	th.driveToProbing(t)

	// Send a conflicting response.
	conflicting := &dnsmessage.Message{
		Header: dnsmessage.Header{Response: true},
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{
				Name:  rec.Header.Name,
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
				TTL:   120,
			},
			Body: &dnsmessage.AResource{A: [4]byte{10, 0, 0, 1}},
		}},
	}
	th.pm.handleMessage(conflicting)

	// The conflict triggers a rename and re-probe after a delay.
	th.advance(probeDelay)
	require.True(t, th.awaitRenames(1), "expected one rename")
	assert.True(t, th.pm.isProbing("myhost-2.local."), "should be probing renamed host")

	close(th.closed)
	<-th.pm.done
}

// TestNoConflictOwnRData verifies that our own responses (matching rdata)
// do not trigger false conflicts.
func TestNoConflictOwnRData(t *testing.T) {
	th := newTestHarness()

	rec := testARecord("myhost.local.")
	th.pm.addSession("myhost.local.", []dnsmessage.Resource{rec}, true)
	tc := th.driveToAnnouncing(t)

	// Send back our own announcement (same rdata).
	ownAnswer := &dnsmessage.Message{
		Header: dnsmessage.Header{Response: true},
		Answers: []dnsmessage.Resource{{
			Header: rec.Header,
			Body:   rec.Body,
		}},
	}
	th.pm.handleMessage(ownAnswer)

	// Complete announcing.
	th.advance(announceInterval)
	ft := th.awaitTimer(tc)
	require.NotNil(t, ft)
	ft.fire()

	<-th.pm.ready
	assert.False(t, th.pm.isProbing("myhost.local."))
	assert.Equal(t, 0, th.renameCount(), "no rename for our own rdata")

	close(th.closed)
	<-th.pm.done
}

// TestNoConflictMultipleAddresses verifies that a response matching one
// of multiple A records does not trigger a false conflict.
func TestNoConflictMultipleAddresses(t *testing.T) {
	th := newTestHarness()

	name := "myhost.local."
	n, _ := dnsmessage.NewName(name)
	rec1 := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 120},
		Body:   &dnsmessage.AResource{A: [4]byte{192, 168, 1, 1}},
	}
	rec2 := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 120},
		Body:   &dnsmessage.AResource{A: [4]byte{10, 0, 0, 5}},
	}

	th.pm.addSession(name, []dnsmessage.Resource{rec1, rec2}, true)
	tc := th.driveToAnnouncing(t)

	// Send response matching only the first address — should NOT conflict.
	th.pm.handleMessage(&dnsmessage.Message{
		Header:  dnsmessage.Header{Response: true},
		Answers: []dnsmessage.Resource{{Header: rec1.Header, Body: rec1.Body}},
	})

	// Send response matching only the second address — also not a conflict.
	th.pm.handleMessage(&dnsmessage.Message{
		Header:  dnsmessage.Header{Response: true},
		Answers: []dnsmessage.Resource{{Header: rec2.Header, Body: rec2.Body}},
	})

	// Complete announcing.
	th.advance(announceInterval)
	ft := th.awaitTimer(tc)
	require.NotNil(t, ft)
	ft.fire()

	<-th.pm.ready
	assert.Equal(t, 0, th.renameCount(), "no rename for our own addresses")

	close(th.closed)
	<-th.pm.done
}

// TestTiebreakingWeWin verifies that when our records are lexicographically
// greater, we continue probing (we win the tiebreak).
func TestTiebreakingWeWin(t *testing.T) {
	th := newTestHarness()

	dnsName, _ := dnsmessage.NewName("myhost.local.")
	ours := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: dnsName, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 120},
		Body:   &dnsmessage.AResource{A: [4]byte{192, 168, 1, 100}},
	}
	th.pm.addSession("myhost.local.", []dnsmessage.Resource{ours}, true)
	th.driveToProbing(t)

	// Simultaneous probe from another host with lower address (we win).
	th.pm.handleMessage(&dnsmessage.Message{
		Header:    dnsmessage.Header{Response: false},
		Questions: []dnsmessage.Question{{Name: dnsName, Type: typeANY, Class: dnsmessage.ClassINET}},
		Authorities: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: dnsName, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 120},
			Body:   &dnsmessage.AResource{A: [4]byte{10, 0, 0, 1}},
		}},
	})

	// Wait for event loop to process the message (creates next timer).
	th.awaitTimer(2)
	assert.Equal(t, 0, th.renameCount())
	assert.True(t, th.pm.isProbing("myhost.local."))

	close(th.closed)
	<-th.pm.done
}

// TestTiebreakingWeLose verifies that when our records are lexicographically
// lower, we defer (lose the tiebreak) and re-probe the same name after 1s
// (§8.2 — no rename, just a delay to guard against stale probes).
func TestTiebreakingWeLose(t *testing.T) {
	th := newTestHarness()

	dnsName, _ := dnsmessage.NewName("myhost.local.")
	ours := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: dnsName, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 120},
		Body:   &dnsmessage.AResource{A: [4]byte{10, 0, 0, 1}},
	}
	th.pm.addSession("myhost.local.", []dnsmessage.Resource{ours}, true)
	tc := th.driveToProbing(t)

	// Simultaneous probe from another host with higher address (we lose).
	th.pm.handleMessage(&dnsmessage.Message{
		Header:    dnsmessage.Header{Response: false},
		Questions: []dnsmessage.Question{{Name: dnsName, Type: typeANY, Class: dnsmessage.ClassINET}},
		Authorities: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: dnsName, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 120},
			Body:   &dnsmessage.AResource{A: [4]byte{192, 168, 1, 100}},
		}},
	})

	// Tiebreak loss waits 1s and re-probes the same name (no rename).
	th.advance(time.Second)
	ft := th.awaitTimer(tc + 1)
	require.NotNil(t, ft)
	assert.Equal(t, 0, th.renameCount(), "tiebreak should not rename")
	assert.True(t, th.pm.isProbing("myhost.local."), "should re-probe same name")

	close(th.closed)
	<-th.pm.done
}

// TestConflictHandlerStop verifies the user can stop probing via the handler.
func TestConflictHandlerStop(t *testing.T) {
	th := newTestHarness()
	th.pm.conflictHandler = func(evt ConflictEvent) ConflictAction {
		return ConflictAction{Stop: true}
	}

	rec := testARecord("myhost.local.")
	th.pm.addSession("myhost.local.", []dnsmessage.Resource{rec}, true)
	th.driveToProbing(t)

	// Send conflicting response.
	th.pm.handleMessage(&dnsmessage.Message{
		Header: dnsmessage.Header{Response: true},
		Answers: []dnsmessage.Resource{{
			Header: rec.Header,
			Body:   &dnsmessage.AResource{A: [4]byte{10, 0, 0, 1}},
		}},
	})

	// Should be stopped — ready closed.
	<-th.pm.ready
	assert.False(t, th.pm.isProbing("myhost.local."))
	assert.Equal(t, 0, th.renameCount(), "handler stopped, no rename")

	close(th.closed)
	<-th.pm.done
}

// TestConflictHandlerCustomRename verifies the user can provide a custom name.
func TestConflictHandlerCustomRename(t *testing.T) {
	th := newTestHarness()
	th.pm.conflictHandler = func(evt ConflictEvent) ConflictAction {
		return ConflictAction{Rename: "custom.local."}
	}

	rec := testARecord("myhost.local.")
	th.pm.addSession("myhost.local.", []dnsmessage.Resource{rec}, true)
	th.driveToProbing(t)

	// Send conflicting response.
	th.pm.handleMessage(&dnsmessage.Message{
		Header: dnsmessage.Header{Response: true},
		Answers: []dnsmessage.Resource{{
			Header: rec.Header,
			Body:   &dnsmessage.AResource{A: [4]byte{10, 0, 0, 1}},
		}},
	})

	// Process conflict.
	th.advance(probeDelay)
	require.True(t, th.awaitRenames(1))

	assert.True(t, th.pm.isProbing("custom.local."), "should be probing custom name")
	th.cond.L.Lock()
	require.NotEmpty(t, th.renames)
	r := th.renames[0]
	th.cond.L.Unlock()
	assert.Equal(t, "myhost.local.", r.oldName)
	assert.Equal(t, "custom.local.", r.newName)

	close(th.closed)
	<-th.pm.done
}

// TestLexicographicCompare tests the tiebreaking comparison.
func TestLexicographicCompare(t *testing.T) {
	n, _ := dnsmessage.NewName("x.local.")
	makeA := func(addr [4]byte) dnsmessage.Resource {
		return dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
			Body:   &dnsmessage.AResource{A: addr},
		}
	}

	tests := []struct {
		desc string
		ours []dnsmessage.Resource
		them []dnsmessage.Resource
		want int
	}{
		{
			desc: "equal",
			ours: []dnsmessage.Resource{makeA([4]byte{1, 2, 3, 4})},
			them: []dnsmessage.Resource{makeA([4]byte{1, 2, 3, 4})},
			want: 0,
		},
		{
			desc: "ours higher",
			ours: []dnsmessage.Resource{makeA([4]byte{192, 168, 1, 1})},
			them: []dnsmessage.Resource{makeA([4]byte{10, 0, 0, 1})},
			want: 1,
		},
		{
			desc: "ours lower",
			ours: []dnsmessage.Resource{makeA([4]byte{10, 0, 0, 1})},
			them: []dnsmessage.Resource{makeA([4]byte{192, 168, 1, 1})},
			want: -1,
		},
		{
			desc: "ours has more records wins",
			ours: []dnsmessage.Resource{makeA([4]byte{1, 2, 3, 4}), makeA([4]byte{5, 6, 7, 8})},
			them: []dnsmessage.Resource{makeA([4]byte{1, 2, 3, 4})},
			want: 1,
		},
		{
			desc: "ours has fewer records loses",
			ours: []dnsmessage.Resource{makeA([4]byte{1, 2, 3, 4})},
			them: []dnsmessage.Resource{makeA([4]byte{1, 2, 3, 4}), makeA([4]byte{5, 6, 7, 8})},
			want: -1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			got := lexicographicCompare(tc.ours, tc.them)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestDefaultRenameHost tests hostname rename strategy.
func TestDefaultRenameHost(t *testing.T) {
	tests := []struct {
		input string
		count int
		want  string
	}{
		{"myhost.local.", 1, "myhost-2.local."},
		{"myhost.local.", 2, "myhost-3.local."},
		// A base name that itself ends in "-2" is preserved, not stripped.
		{"myhost-2.local.", 3, "myhost-2-4.local."},
	}
	for _, tc := range tests {
		got := defaultRename(tc.input, tc.count, true)
		assert.Equal(t, tc.want, got, "rename %q count=%d", tc.input, tc.count)
	}
}

// TestDefaultRenameServiceInstance tests service instance rename strategy.
func TestDefaultRenameServiceInstance(t *testing.T) {
	tests := []struct {
		input string
		count int
		want  string
	}{
		{"My Service._http._tcp.local.", 1, "My Service (2)._http._tcp.local."},
		{"My Service._http._tcp.local.", 2, "My Service (3)._http._tcp.local."},
		// A base name that itself ends in " (2)" is preserved, not stripped.
		{"My Service (2)._http._tcp.local.", 3, "My Service (2) (4)._http._tcp.local."},
	}
	for _, tc := range tests {
		got := defaultRename(tc.input, tc.count, false)
		assert.Equal(t, tc.want, got, "rename %q count=%d", tc.input, tc.count)
	}
}

// TestIsProbingCaseInsensitive verifies case-insensitive matching.
func TestIsProbingCaseInsensitive(t *testing.T) {
	th := newTestHarness()
	rec := testARecord("MyHost.local.")
	th.pm.addSession("MyHost.local.", []dnsmessage.Resource{rec}, true)

	assert.True(t, th.pm.isProbing("myhost.local."))
	assert.True(t, th.pm.isProbing("MYHOST.LOCAL."))
	assert.False(t, th.pm.isProbing("other.local."))
}

// TestHandleMessageAfterDone verifies handleMessage does not block after
// the event loop exits.
func TestHandleMessageAfterDone(t *testing.T) {
	th := newTestHarness()

	go th.pm.run(th.closed)
	<-th.pm.ready
	close(th.closed)
	<-th.pm.done

	// Should return immediately, not block.
	returned := make(chan struct{})

	go func() {
		th.pm.handleMessage(&dnsmessage.Message{})
		close(returned)
	}()

	select {
	case <-returned:
	case <-time.After(time.Second):
		assert.Fail(t, "handleMessage blocked after done")
	}
}

// TestConflictInEstablishedState verifies §9 semantics: a response with
// foreign rdata in established state resets the record to probing with the
// SAME name. A rename happens only if the re-probe also conflicts.
func TestConflictInEstablishedState(t *testing.T) {
	th := newTestHarness()

	rec := testARecord("myhost.local.")
	th.pm.addSession("myhost.local.", []dnsmessage.Resource{rec}, true)
	th.driveToEstablished(t)
	<-th.pm.ready

	probesBefore := th.questionCount()
	timersBefore := th.timerCount()

	// Now send a conflicting response in established state.
	conflicting := &dnsmessage.Message{
		Header: dnsmessage.Header{Response: true},
		Answers: []dnsmessage.Resource{{
			Header: rec.Header,
			Body:   &dnsmessage.AResource{A: [4]byte{10, 0, 0, 99}},
		}},
	}
	th.pm.handleMessage(conflicting)

	// §9: re-probe the same name, no rename yet.
	delayTimer := th.awaitTimer(timersBefore + 1)
	require.NotNil(t, delayTimer, "expected re-probe delay timer")
	assert.True(t, th.pm.isProbing("myhost.local."), "should re-probe the same name")
	assert.Equal(t, 0, th.renameCount(), "established conflict must not rename directly")

	// Fire the delay timer: the first probe of the re-probe round goes out.
	th.advance(probeDelay)
	delayTimer.fire()
	require.True(t, th.await(func() bool { return len(th.questions) > probesBefore }),
		"expected a new probe after established conflict")

	// A conflict during the re-probe now triggers the rename (§8.1).
	th.pm.handleMessage(conflicting)
	th.advance(probeDelay)
	require.True(t, th.awaitRenames(1), "conflict during re-probe should rename")

	th.cond.L.Lock()
	r := th.renames[0]
	th.cond.L.Unlock()
	assert.Equal(t, "myhost.local.", r.oldName)
	// Count includes the established-state conflict, so the suffix is 3.
	assert.Equal(t, "myhost-3.local.", r.newName)

	close(th.closed)
	<-th.pm.done
}

// TestIsConflictingRData verifies the rdata conflict detection logic.
func TestIsConflictingRData(t *testing.T) {
	th := newTestHarness()

	dnsName, _ := dnsmessage.NewName("test.local.")
	rec1 := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: dnsName, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
		Body:   &dnsmessage.AResource{A: [4]byte{192, 168, 1, 1}},
	}
	rec2 := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: dnsName, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
		Body:   &dnsmessage.AResource{A: [4]byte{10, 0, 0, 5}},
	}
	session := &probeSession{
		name:    "test.local.",
		records: []dnsmessage.Resource{rec1, rec2},
	}

	// Answer matching first record — not a conflict.
	ans1 := &dnsmessage.Resource{Header: rec1.Header, Body: &dnsmessage.AResource{A: [4]byte{192, 168, 1, 1}}}
	assert.False(t, th.pm.isConflictingRData(session, ans1), "matching first record")

	// Answer matching second record — not a conflict.
	ans2 := &dnsmessage.Resource{Header: rec2.Header, Body: &dnsmessage.AResource{A: [4]byte{10, 0, 0, 5}}}
	assert.False(t, th.pm.isConflictingRData(session, ans2), "matching second record")

	// Answer matching neither — conflict.
	ansForeign := &dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: dnsName, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
		Body:   &dnsmessage.AResource{A: [4]byte{172, 16, 0, 1}},
	}
	assert.True(t, th.pm.isConflictingRData(session, ansForeign), "foreign address")

	// Answer with different type — not a conflict.
	ansAAAA := &dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: dnsName, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET},
		Body:   &dnsmessage.AAAAResource{},
	}
	assert.False(t, th.pm.isConflictingRData(session, ansAAAA), "different record type")
}

// TestConflictEventFields verifies the ConflictEvent passed to the handler.
func TestConflictEventFields(t *testing.T) {
	th := newTestHarness()

	var captured ConflictEvent
	th.pm.conflictHandler = func(evt ConflictEvent) ConflictAction {
		captured = evt

		return ConflictAction{}
	}

	rec := testARecord("myhost.local.")
	th.pm.addSession("myhost.local.", []dnsmessage.Resource{rec}, true)
	th.driveToProbing(t)

	// Conflict.
	th.pm.handleMessage(&dnsmessage.Message{
		Header: dnsmessage.Header{Response: true},
		Answers: []dnsmessage.Resource{{
			Header: rec.Header,
			Body:   &dnsmessage.AResource{A: [4]byte{10, 0, 0, 1}},
		}},
	})

	th.advance(probeDelay)
	require.True(t, th.awaitRenames(1))

	assert.True(t, strings.EqualFold(captured.Name, "myhost.local."))
	assert.Equal(t, 1, captured.Count)
	assert.True(t, captured.Host)

	close(th.closed)
	<-th.pm.done
}

// TestPackRData covers the rdata serialization for comparison.
func TestPackRData(t *testing.T) {
	// A record.
	aBody := &dnsmessage.AResource{A: [4]byte{1, 2, 3, 4}}
	assert.Equal(t, []byte{1, 2, 3, 4}, packRData(aBody))

	// AAAA record.
	aaaa := [16]byte{0xfe, 0x80}
	assert.Equal(t, aaaa[:], packRData(&dnsmessage.AAAAResource{AAAA: aaaa}))

	// TXT record.
	txtData := packRData(&dnsmessage.TXTResource{TXT: []string{"k=v"}})
	assert.Equal(t, []byte{3, 'k', '=', 'v'}, txtData)

	// SRV record.
	target, _ := dnsmessage.NewName("myhost.local.")
	srvData := packRData(&dnsmessage.SRVResource{
		Priority: 0, Weight: 0, Port: 8080, Target: target,
	})
	assert.NotNil(t, srvData)
	assert.Equal(t, uint16(8080), binary.BigEndian.Uint16(srvData[4:6]))

	// PTR record.
	ptrName, _ := dnsmessage.NewName("_http._tcp.local.")
	ptrData := packRData(&dnsmessage.PTRResource{PTR: ptrName})
	assert.NotNil(t, ptrData)
	assert.NotEmpty(t, ptrData)

	// Unknown type returns nil.
	assert.Nil(t, packRData(&dnsmessage.NSResource{}))

	// Nil body.
	assert.Nil(t, packRData(nil))
}

// TestShouldBackoff verifies the rate-limiting backoff logic directly.
func TestShouldBackoff(t *testing.T) {
	th := newTestHarness()
	now := th.clock

	session := &probeSession{name: "test.local."}

	// Fill conflict times within the rate window.
	for i := range conflictRateLimit - 1 {
		session.conflictTimes = append(session.conflictTimes, now.Add(time.Duration(i)*time.Second))
	}

	// Not yet at the limit.
	assert.Equal(t, time.Duration(0), th.pm.shouldBackoff(session, now.Add(9*time.Second)))

	// Add one more to hit the limit.
	session.conflictTimes = append(session.conflictTimes, now.Add(9*time.Second))
	assert.Equal(t, conflictBackoff, th.pm.shouldBackoff(session, now.Add(9*time.Second)))

	// After the window passes, old entries are pruned.
	assert.Equal(t, time.Duration(0), th.pm.shouldBackoff(session, now.Add(20*time.Second)))
}

// TestConflictGiveUp verifies that handleConflictForSession stops the
// session after sustained conflicts over the give-up period.
func TestConflictGiveUp(t *testing.T) {
	th := newTestHarness()
	now := th.clock

	rec := testARecord("test.local.")
	session := &probeSession{
		name:    "test.local.",
		state:   probeStateProbing,
		isHost:  true,
		records: []dnsmessage.Resource{rec},
	}

	step := conflictGiveUp/time.Duration(conflictRateLimit) + time.Second

	for i := 0; i <= conflictRateLimit+1; i++ {
		now = now.Add(step)
		session.conflict = true

		var pio pendingIO

		th.pm.mu.Lock()
		th.pm.handleConflictForSession(session, now, &pio)
		th.pm.mu.Unlock()

		if session.state == probeStateStopped {
			break
		}
	}

	assert.Equal(t, probeStateStopped, session.state, "session should stop after sustained conflicts")
}

// TestDefaultRenameHostNoDot tests hostname rename with no domain part.
func TestDefaultRenameHostNoDot(t *testing.T) {
	got := defaultRename("myhost", 1, true)
	assert.Equal(t, "myhost-2", got)
}

// TestDefaultRenameHostNonNumericSuffix verifies a host with a non-numeric
// dash suffix keeps the dash.
func TestDefaultRenameHostNonNumericSuffix(t *testing.T) {
	got := defaultRename("my-host.local.", 1, true)
	assert.Equal(t, "my-host-2.local.", got)
}

// TestDefaultRenameServiceNoUnderscore tests service rename with no
// underscore boundary.
func TestDefaultRenameServiceNoUnderscore(t *testing.T) {
	got := defaultRename("noservice.local.", 1, false)
	assert.Equal(t, "noservice.local. (2)", got)
}

// TestDefaultRenameServiceNonNumericParen tests service rename where the
// paren suffix is non-numeric.
func TestDefaultRenameServiceNonNumericParen(t *testing.T) {
	got := defaultRename("My Service (beta)._http._tcp.local.", 1, false)
	assert.Equal(t, "My Service (beta) (2)._http._tcp.local.", got)
}

// TestCompareResourceDifferentClass verifies class comparison in tiebreaking.
func TestCompareResourceDifferentClass(t *testing.T) {
	n, _ := dnsmessage.NewName("x.local.")

	// Class CSNET(2) < Class IN(1) is false; IN < CSNET.
	resClass1 := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
		Body:   &dnsmessage.AResource{A: [4]byte{1, 2, 3, 4}},
	}
	resClass2 := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassCSNET},
		Body:   &dnsmessage.AResource{A: [4]byte{1, 2, 3, 4}},
	}

	assert.NotEqual(t, 0, compareResource(resClass1, resClass2))
}

// TestCompareResourceDifferentType verifies type comparison in tiebreaking.
func TestCompareResourceDifferentType(t *testing.T) {
	n, _ := dnsmessage.NewName("x.local.")

	resA := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
		Body:   &dnsmessage.AResource{A: [4]byte{1, 2, 3, 4}},
	}
	resAAAA := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: n, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET},
		Body:   &dnsmessage.AAAAResource{AAAA: [16]byte{1}},
	}

	// TypeA=1 < TypeAAAA=28 → negative.
	assert.Equal(t, -1, compareResource(resA, resAAAA))
	assert.Equal(t, 1, compareResource(resAAAA, resA))
}

// TestProbeQueryMultipleRecords verifies probe with multiple authority records.
func TestProbeQueryMultipleRecords(t *testing.T) {
	aRec := testARecord("myhost.local.")
	aaaaRec := testAAAARecord("myhost.local.")

	raw, err := buildProbeQuery("myhost.local.", []dnsmessage.Resource{aRec, aaaaRec})
	require.NoError(t, err)

	var msg dnsmessage.Message
	require.NoError(t, msg.Unpack(raw))

	require.Len(t, msg.Questions, 1)
	require.Len(t, msg.Authorities, 2)
	assert.Equal(t, dnsmessage.TypeA, msg.Authorities[0].Header.Type)
	assert.Equal(t, dnsmessage.TypeAAAA, msg.Authorities[1].Header.Type)
}

// TestProbeWithQuestionNoAuthority verifies that an incoming query without
// authority records does not cause a tiebreak.
func TestProbeWithQuestionNoAuthority(t *testing.T) {
	th := newTestHarness()

	rec := testARecord("myhost.local.")
	th.pm.addSession("myhost.local.", []dnsmessage.Resource{rec}, true)
	th.driveToProbing(t)

	n, _ := dnsmessage.NewName("myhost.local.")
	th.pm.handleMessage(&dnsmessage.Message{
		Header:    dnsmessage.Header{Response: false},
		Questions: []dnsmessage.Question{{Name: n, Type: typeANY, Class: dnsmessage.ClassINET}},
		// No authority section.
	})

	// Wait for event loop to process (creates next timer).
	th.awaitTimer(2)
	assert.Equal(t, 0, th.renameCount(), "no tiebreak without authority records")
	assert.True(t, th.pm.isProbing("myhost.local."))

	close(th.closed)
	<-th.pm.done
}

// TestMultipleSessions verifies that host and service sessions can probe
// concurrently.
func TestMultipleSessions(t *testing.T) {
	th := newTestHarness()

	hostRec := testARecord("myhost.local.")
	th.pm.addSession("myhost.local.", []dnsmessage.Resource{hostRec}, true)

	svcName, _ := dnsmessage.NewName("My Service._http._tcp.local.")
	srvRec := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: svcName, Type: dnsmessage.TypeSRV, Class: dnsmessage.ClassINET, TTL: 120},
		Body:   &dnsmessage.SRVResource{Port: 8080, Target: hostRec.Header.Name},
	}
	th.pm.addSession("My Service._http._tcp.local.", []dnsmessage.Resource{srvRec}, false)

	assert.True(t, th.pm.isProbing("myhost.local."))
	assert.True(t, th.pm.isProbing("My Service._http._tcp.local."))

	// Drive manually: with 2 sessions, each step produces 2 probes/announces.
	go th.pm.run(th.closed)

	// First probes (both sessions fire together).
	ft := th.awaitTimer(1)
	require.NotNil(t, ft)
	assert.Equal(t, 2, th.questionCount(), "both sessions probe initially")

	// Second probes.
	th.advance(probeInterval)
	ft.fire()
	ft = th.awaitTimer(2)
	require.NotNil(t, ft)
	assert.Equal(t, 4, th.questionCount())

	// Third probes.
	th.advance(probeInterval)
	ft.fire()
	ft = th.awaitTimer(3)
	require.NotNil(t, ft)
	assert.Equal(t, 6, th.questionCount())

	// Transition to announcing → first announcements.
	th.advance(probeInterval)
	ft.fire()
	ft = th.awaitTimer(4)
	require.NotNil(t, ft)
	assert.Equal(t, 2, th.answerCount(), "first announcements for both")

	// Second announcements → established.
	th.advance(announceInterval)
	ft.fire()
	require.True(t, th.awaitAnswers(4), "second announcements for both")

	<-th.pm.ready
	assert.False(t, th.pm.isProbing("myhost.local."))
	assert.False(t, th.pm.isProbing("My Service._http._tcp.local."))

	close(th.closed)
	<-th.pm.done
}

// TestConflictDuringAnnouncing verifies that a conflict detected during
// announcing resets the record to probing with the same name (§9 — probing
// already completed, so this is not a probing conflict).
func TestConflictDuringAnnouncing(t *testing.T) {
	th := newTestHarness()

	rec := testARecord("myhost.local.")
	th.pm.addSession("myhost.local.", []dnsmessage.Resource{rec}, true)
	th.driveToAnnouncing(t)

	timersBefore := th.timerCount()

	// Send a conflicting response during announcing.
	th.pm.handleMessage(&dnsmessage.Message{
		Header: dnsmessage.Header{Response: true},
		Answers: []dnsmessage.Resource{{
			Header: rec.Header,
			Body:   &dnsmessage.AResource{A: [4]byte{10, 0, 0, 42}},
		}},
	})

	require.NotNil(t, th.awaitTimer(timersBefore+1), "expected re-probe delay timer")
	assert.True(t, th.pm.isProbing("myhost.local."), "should re-probe the same name")
	assert.Equal(t, 0, th.renameCount(), "post-probing conflict must not rename directly")

	close(th.closed)
	<-th.pm.done
}

// TestAnnouncementCacheFlushBits verifies that unique A/AAAA/SRV/TXT
// records have the cache-flush bit set, while the shared PTR does not.
func TestAnnouncementCacheFlushBits(t *testing.T) {
	dnsName, _ := dnsmessage.NewName("myhost.local.")
	ptrName, _ := dnsmessage.NewName("_http._tcp.local.")
	svcName, _ := dnsmessage.NewName("My Svc._http._tcp.local.")

	unique := []dnsmessage.Resource{
		{
			Header: dnsmessage.ResourceHeader{Name: dnsName, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 120},
			Body:   &dnsmessage.AResource{A: [4]byte{1, 2, 3, 4}},
		},
		{
			Header: dnsmessage.ResourceHeader{Name: dnsName, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET, TTL: 120},
			Body:   &dnsmessage.AAAAResource{AAAA: [16]byte{0xfe, 0x80}},
		},
		{
			Header: dnsmessage.ResourceHeader{Name: svcName, Type: dnsmessage.TypeSRV, Class: dnsmessage.ClassINET, TTL: 120},
			Body:   &dnsmessage.SRVResource{Port: 80, Target: dnsName},
		},
		{
			Header: dnsmessage.ResourceHeader{Name: svcName, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET, TTL: 120},
			Body:   &dnsmessage.TXTResource{TXT: []string{"k=v"}},
		},
	}
	shared := []dnsmessage.Resource{
		{
			Header: dnsmessage.ResourceHeader{Name: ptrName, Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET, TTL: 4500},
			Body:   &dnsmessage.PTRResource{PTR: svcName},
		},
	}

	raw, err := buildAnnouncement(unique, shared)
	require.NoError(t, err)

	var msg dnsmessage.Message
	require.NoError(t, msg.Unpack(raw))
	require.Len(t, msg.Answers, 5)

	// A, AAAA, SRV, TXT should have cache-flush bit.
	for _, idx := range []int{0, 1, 2, 3} {
		assert.NotZero(t, msg.Answers[idx].Header.Class&rrClassCacheFlush,
			"record type %d should have cache-flush bit", msg.Answers[idx].Header.Type)
	}

	// PTR should NOT have cache-flush bit.
	assert.Zero(t, msg.Answers[4].Header.Class&rrClassCacheFlush, "PTR should not have cache-flush bit")
}

// TestPackDNSName covers edge cases in DNS name serialization.
func TestPackDNSName(t *testing.T) {
	// Normal name.
	n, _ := dnsmessage.NewName("foo.local.")
	data := packDNSName(n)
	assert.NotEmpty(t, data)
	assert.Equal(t, byte(0), data[len(data)-1], "should end with zero byte")

	// Root/empty name.
	root, _ := dnsmessage.NewName(".")
	data = packDNSName(root)
	assert.Equal(t, []byte{0}, data)
}

// TestSequentialConflicts drives the full event loop through two
// consecutive rename cycles: myhost → myhost-2 → myhost-3.
// Verifies rename events, session state, and that record headers
// are rewritten to the new name.
func TestSequentialConflicts(t *testing.T) {
	th := newTestHarness()

	rec := testARecord("myhost.local.")
	th.pm.addSession("myhost.local.", []dnsmessage.Resource{rec}, true)

	tc := th.driveToProbing(t)

	// fire advances the clock, awaits the next timer, and fires it.
	fire := func(d time.Duration) {
		t.Helper()
		tc++
		ft := th.awaitTimer(tc)
		require.NotNil(t, ft, "expected timer %d", tc)
		th.advance(d)
		ft.fire()
	}

	// conflictResponse builds a response with a foreign address for the given name.
	conflictResponse := func(name string, addr [4]byte) *dnsmessage.Message {
		n, _ := dnsmessage.NewName(name)

		return &dnsmessage.Message{
			Header: dnsmessage.Header{Response: true},
			Answers: []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 120},
				Body:   &dnsmessage.AResource{A: addr},
			}},
		}
	}

	// First conflict → myhost-2.
	th.pm.handleMessage(conflictResponse("myhost.local.", [4]byte{10, 0, 0, 1}))
	th.advance(probeDelay)
	require.True(t, th.awaitRenames(1))

	th.pm.mu.RLock()
	assert.Equal(t, "myhost-2.local.", th.pm.sessions[0].name)
	assert.Equal(t, "myhost-2.local.", th.pm.sessions[0].records[0].Header.Name.String())
	th.pm.mu.RUnlock()

	// Drive myhost-2 into probing.
	fire(probeDelay)

	// Second conflict → myhost-3.
	th.pm.handleMessage(conflictResponse("myhost-2.local.", [4]byte{10, 0, 0, 2}))
	th.advance(probeDelay)
	require.True(t, th.awaitRenames(2))

	th.pm.mu.RLock()
	assert.Equal(t, "myhost-3.local.", th.pm.sessions[0].name)
	assert.Equal(t, "myhost-3.local.", th.pm.sessions[0].records[0].Header.Name.String())
	th.pm.mu.RUnlock()

	// Verify the full rename chain.
	th.cond.L.Lock()
	require.Len(t, th.renames, 2)
	assert.Equal(t, "myhost.local.", th.renames[0].oldName)
	assert.Equal(t, "myhost-2.local.", th.renames[0].newName)
	assert.True(t, th.renames[0].isHost)
	assert.Equal(t, "myhost-2.local.", th.renames[1].oldName)
	assert.Equal(t, "myhost-3.local.", th.renames[1].newName)
	th.cond.L.Unlock()

	close(th.closed)
	<-th.pm.done
}

// TestConflictRenameAnnounce drives a full conflict → rename → re-probe →
// announce cycle and verifies the announcement wire data contains the
// renamed name with cache-flush bits set.
func TestConflictRenameAnnounce(t *testing.T) {
	th := newTestHarness()

	rec := testARecord("myhost.local.")
	th.pm.addSession("myhost.local.", []dnsmessage.Resource{rec}, true)

	tc := th.driveToProbing(t)

	// fire advances the clock, awaits the next timer, and fires it.
	fire := func(d time.Duration) {
		t.Helper()
		tc++
		ft := th.awaitTimer(tc)
		require.NotNil(t, ft, "expected timer %d", tc)
		th.advance(d)
		ft.fire()
	}

	// Inject conflict during probing.
	th.pm.handleMessage(&dnsmessage.Message{
		Header: dnsmessage.Header{Response: true},
		Answers: []dnsmessage.Resource{{
			Header: rec.Header,
			Body:   &dnsmessage.AResource{A: [4]byte{10, 0, 0, 1}},
		}},
	})
	th.advance(probeDelay)
	require.True(t, th.awaitRenames(1))

	// Drive renamed session: delay, 3 probes, transition, 2 announcements.
	fire(probeDelay)    // delay, first re-probe
	fire(probeInterval) // second re-probe
	fire(probeInterval) // third re-probe
	fire(probeInterval) // transition to announcing
	require.True(t, th.awaitAnswers(1))
	fire(announceInterval) // second announcement
	require.True(t, th.awaitAnswers(2))
	<-th.pm.ready

	// Unpack the first announcement and verify wire content.
	th.cond.L.Lock()
	raw := th.answers[0]
	th.cond.L.Unlock()

	var msg dnsmessage.Message
	require.NoError(t, msg.Unpack(raw))

	assert.True(t, msg.Header.Response)
	assert.True(t, msg.Header.Authoritative)
	require.Len(t, msg.Answers, 1)

	// Answer must use the renamed name.
	assert.Equal(t, "myhost-2.local.", msg.Answers[0].Header.Name.String())
	assert.Equal(t, dnsmessage.TypeA, msg.Answers[0].Header.Type)

	// Cache-flush bit set (unique record).
	assert.NotZero(t, msg.Answers[0].Header.Class&rrClassCacheFlush)

	// Rdata is our original address (rename changes name, not address).
	body, ok := msg.Answers[0].Body.(*dnsmessage.AResource)
	require.True(t, ok)
	assert.Equal(t, [4]byte{192, 168, 1, 1}, body.A)

	close(th.closed)
	<-th.pm.done
}

// TestResponseForUnrelatedName verifies that answers for names we don't
// own are ignored.
func TestResponseForUnrelatedName(t *testing.T) {
	th := newTestHarness()

	rec := testARecord("myhost.local.")
	th.pm.addSession("myhost.local.", []dnsmessage.Resource{rec}, true)
	th.driveToProbing(t)

	// Send response for a completely different name.
	otherName, _ := dnsmessage.NewName("other.local.")
	th.pm.handleMessage(&dnsmessage.Message{
		Header: dnsmessage.Header{Response: true},
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: otherName, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 120},
			Body:   &dnsmessage.AResource{A: [4]byte{10, 0, 0, 1}},
		}},
	})

	// Wait for event loop to process (creates next timer).
	th.awaitTimer(2)
	assert.Equal(t, 0, th.renameCount(), "unrelated name should not trigger conflict")
	assert.True(t, th.pm.isProbing("myhost.local."))

	close(th.closed)
	<-th.pm.done
}

// testSRVRecord builds an SRV record for a service instance.
func testSRVRecord(instance, target string) dnsmessage.Resource {
	instName, _ := dnsmessage.NewName(instance)
	targetName, _ := dnsmessage.NewName(target)

	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  instName,
			Type:  dnsmessage.TypeSRV,
			Class: dnsmessage.ClassINET,
			TTL:   120,
		},
		Body: &dnsmessage.SRVResource{Port: 8080, Target: targetName},
	}
}

// testPTRRecord builds a shared PTR record: service type → instance.
func testPTRRecord(serviceType, instance string) dnsmessage.Resource {
	typeName, _ := dnsmessage.NewName(serviceType)
	instName, _ := dnsmessage.NewName(instance)

	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  typeName,
			Type:  dnsmessage.TypePTR,
			Class: dnsmessage.ClassINET,
			TTL:   4500,
		},
		Body: &dnsmessage.PTRResource{PTR: instName},
	}
}

// TestAnnounceIncludesSharedPTR verifies that announcements carry the
// shared PTR record (no cache-flush) alongside the unique records, while
// probe queries carry only the unique records.
func TestAnnounceIncludesSharedPTR(t *testing.T) {
	th := newTestHarness()

	const instance = "My Service._http._tcp.local."
	srvRec := testSRVRecord(instance, "myhost.local.")
	ptrRec := testPTRRecord("_http._tcp.local.", instance)
	th.pm.addSession(instance, []dnsmessage.Resource{srvRec}, false, ptrRec)

	th.driveToAnnouncing(t)

	// Probe queries must not contain the shared PTR.
	th.cond.L.Lock()
	rawProbe := th.questions[0]
	rawAnnounce := th.answers[0]
	th.cond.L.Unlock()

	var probe dnsmessage.Message
	require.NoError(t, probe.Unpack(rawProbe))
	require.Len(t, probe.Authorities, 1, "probe authority: unique records only")
	assert.Equal(t, dnsmessage.TypeSRV, probe.Authorities[0].Header.Type)

	var announce dnsmessage.Message
	require.NoError(t, announce.Unpack(rawAnnounce))
	require.Len(t, announce.Answers, 2, "announcement: SRV + shared PTR")

	assert.Equal(t, dnsmessage.TypeSRV, announce.Answers[0].Header.Type)
	assert.NotZero(t, announce.Answers[0].Header.Class&rrClassCacheFlush, "unique SRV gets cache-flush")

	assert.Equal(t, dnsmessage.TypePTR, announce.Answers[1].Header.Type)
	assert.Zero(t, announce.Answers[1].Header.Class&rrClassCacheFlush, "shared PTR must not cache-flush")

	ptrBody, ok := announce.Answers[1].Body.(*dnsmessage.PTRResource)
	require.True(t, ok)
	assert.True(t, strings.EqualFold(instance, ptrBody.PTR.String()), "PTR targets the instance")

	close(th.closed)
	<-th.pm.done
}

// TestRenameRetargetsSharedPTR verifies that renaming a session rewrites
// unique record headers and the shared PTR's target, but not the PTR's
// header (which names the service type).
func TestRenameRetargetsSharedPTR(t *testing.T) {
	th := newTestHarness()

	const instance = "My Service._http._tcp.local."
	srvRec := testSRVRecord(instance, "myhost.local.")
	ptrRec := testPTRRecord("_http._tcp.local.", instance)

	sess := &probeSession{
		name:     instance,
		baseName: instance,
		records:  []dnsmessage.Resource{srvRec},
		shared:   []dnsmessage.Resource{ptrRec},
	}

	const renamed = "My Service (2)._http._tcp.local."
	th.pm.renameSession(sess, renamed)

	assert.Equal(t, renamed, sess.name)
	assert.Equal(t, renamed, sess.records[0].Header.Name.String(), "unique header renamed")
	assert.Equal(t, "_http._tcp.local.", sess.shared[0].Header.Name.String(), "PTR header unchanged")

	ptrBody, ok := sess.shared[0].Body.(*dnsmessage.PTRResource)
	require.True(t, ok)
	assert.Equal(t, renamed, ptrBody.PTR.String(), "PTR target retargeted")
}

// TestReProbeRateLimitBackoff verifies that post-probing conflicts respect
// the §8.1 rate limit when scheduling the re-probe.
func TestReProbeRateLimitBackoff(t *testing.T) {
	th := newTestHarness()
	now := th.clock

	sess := &probeSession{
		name:    "myhost.local.",
		state:   probeStateEstablished,
		records: []dnsmessage.Resource{testARecord("myhost.local.")},
	}

	// Fill the rate window to the limit.
	for range conflictRateLimit {
		sess.conflictTimes = append(sess.conflictTimes, now)
	}

	th.pm.mu.Lock()
	th.pm.handleReProbe(sess, now)
	th.pm.mu.Unlock()

	assert.Equal(t, probeStateDelay, sess.state, "session resets to probing")
	assert.Equal(t, "myhost.local.", sess.name, "name unchanged")
	assert.Equal(t, now.Add(probeDelay+conflictBackoff), sess.nextEvent, "backoff applied")
}

// TestReProbeGiveUp verifies that sustained post-probing conflicts stop the
// session entirely.
func TestReProbeGiveUp(t *testing.T) {
	th := newTestHarness()
	now := th.clock

	sess := &probeSession{
		name:          "myhost.local.",
		state:         probeStateEstablished,
		records:       []dnsmessage.Resource{testARecord("myhost.local.")},
		conflictCount: conflictRateLimit + 1,
		firstConflict: now.Add(-conflictGiveUp - time.Second),
	}

	th.pm.mu.Lock()
	th.pm.handleReProbe(sess, now)
	th.pm.mu.Unlock()

	assert.Equal(t, probeStateStopped, sess.state, "session gives up after sustained conflicts")
}

// TestCustomRenameBecomesBase verifies that a user-supplied rename becomes
// the base for subsequent default renames.
func TestCustomRenameBecomesBase(t *testing.T) {
	th := newTestHarness()

	first := true
	th.pm.conflictHandler = func(ConflictEvent) ConflictAction {
		if first {
			first = false

			return ConflictAction{Rename: "custom.local."}
		}

		return ConflictAction{} // fall back to default rename.
	}

	rec := testARecord("myhost.local.")
	th.pm.addSession("myhost.local.", []dnsmessage.Resource{rec}, true)
	th.driveToProbing(t)

	conflict := func(name string) {
		n, _ := dnsmessage.NewName(name)
		th.pm.handleMessage(&dnsmessage.Message{
			Header: dnsmessage.Header{Response: true},
			Answers: []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 120},
				Body:   &dnsmessage.AResource{A: [4]byte{10, 0, 0, 1}},
			}},
		})
	}

	// First conflict → custom rename.
	conflict("myhost.local.")
	th.advance(probeDelay)
	require.True(t, th.awaitRenames(1))
	assert.True(t, th.pm.isProbing("custom.local."))

	// Drive the renamed session into probing, then conflict again.
	ft := th.awaitTimer(2)
	require.NotNil(t, ft)
	th.advance(probeDelay)
	ft.fire()
	require.True(t, th.await(func() bool { return len(th.questions) >= 2 }),
		"expected probe for custom name")

	conflict("custom.local.")
	th.advance(probeDelay)
	require.True(t, th.awaitRenames(2))

	th.cond.L.Lock()
	second := th.renames[1]
	th.cond.L.Unlock()
	assert.Equal(t, "custom.local.", second.oldName)
	// Default rename derives from the custom base: count=2 → suffix 3.
	assert.Equal(t, "custom-3.local.", second.newName)

	close(th.closed)
	<-th.pm.done
}
