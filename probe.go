// SPDX-FileCopyrightText: The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package mdns

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/pion/logging"
	"golang.org/x/net/dns/dnsmessage"
)

// Probing constants per RFC 6762 §8.
const (
	// probeDelay is the maximum random delay before the first probe (§8.1).
	probeDelay = 250 * time.Millisecond

	// probeInterval is the time between successive probe queries (§8.1).
	probeInterval = 250 * time.Millisecond

	// probeCount is the number of probe queries to send (§8.1).
	probeCount = 3

	// announceInterval is the time between unsolicited announcements (§8.3).
	announceInterval = 1 * time.Second

	// announceCount is the number of unsolicited announcements to send (§8.3).
	announceCount = 2

	// conflictRateWindow is the sliding window for rate limiting (§8.1).
	conflictRateWindow = 10 * time.Second

	// conflictRateLimit is the max conflicts before backoff kicks in (§8.1).
	conflictRateLimit = 15

	// conflictBackoff is the delay when rate limited (§8.1).
	conflictBackoff = 5 * time.Second

	// conflictGiveUp is the total duration of continuous conflicts before
	// we stop retrying a name.
	conflictGiveUp = 60 * time.Second

	// typeANY is the QTYPE for "ANY" queries (RFC 1035 §3.2.3).
	typeANY = dnsmessage.TypeALL // 255
)

// probeTimer abstracts time.Timer for testability.
type probeTimer interface {
	Chan() <-chan time.Time
	Stop() bool
}

// realTimer wraps time.Timer to implement probeTimer.
type realTimer struct{ *time.Timer }

func (t *realTimer) Chan() <-chan time.Time { return t.Timer.C }
func (t *realTimer) Stop() bool             { return t.Timer.Stop() }

func newRealTimer(d time.Duration) probeTimer {
	return &realTimer{time.NewTimer(d)}
}

// ConflictEvent describes a naming conflict detected during probing
// or in established state (RFC 6762 §9). Passed to a user-provided
// conflict handler so it can influence rename behavior.
type ConflictEvent struct {
	// Name is the conflicting DNS name (FQDN with trailing dot).
	Name string

	// Count is the number of times this name has conflicted (1-based).
	Count int

	// Host is true when the conflicting name is a hostname (A/AAAA),
	// false when it is a service instance name (SRV/TXT).
	Host bool
}

// ConflictAction tells the probing system how to handle a naming conflict.
type ConflictAction struct {
	// Rename is the replacement DNS name to probe next. If empty, the
	// default rename strategy is used (append " (N)" for services,
	// "-N" for hostnames).
	Rename string

	// Stop signals that probing should stop for this name. No further
	// rename attempts will be made.
	Stop bool
}

// probeState represents the current phase of a probe session.
type probeState int

const (
	probeStateDelay       probeState = iota // random 0–250 ms wait.
	probeStateProbing                       // sending 3 probes at 250 ms.
	probeStateAnnouncing                    // sending 2 announcements at 1 s.
	probeStateEstablished                   // name claimed.
	probeStateStopped                       // gave up or user stopped.
)

// probeSession tracks the probing lifecycle for a single DNS name.
type probeSession struct {
	name    string                // FQDN being probed (e.g. "myhost.local.").
	records []dnsmessage.Resource // proposed records (authority / announce).
	isHost  bool                  // hostname vs service instance.

	state         probeState
	probesSent    int
	announcesSent int
	nextEvent     time.Time

	conflictCount int
	conflictTimes []time.Time // for rate limiting.
	firstConflict time.Time   // for give-up timeout.
	conflict      bool        // flag set by message handler.
	tiebreakDefer bool        // flag set by simultaneous probe handler.
}

// pendingIO collects I/O operations determined under the lock, to be
// executed after the lock is released (avoids holding mu during sends).
type pendingIO struct {
	probes    [][]byte // probe query packets.
	announces [][]byte // announcement packets.
	renames   []renameEvent
}

type renameEvent struct {
	oldName string
	newName string
	isHost  bool
}

// probeManager orchestrates probing, announcing, and conflict detection
// for all names owned by a server. It runs a single event-loop goroutine.
type probeManager struct {
	mu       sync.RWMutex
	sessions []*probeSession

	questionWriter questionWriter
	answerWriter   answerWriter
	log            logging.LeveledLogger
	logName        string
	ttl            uint32

	// Injected dependencies for deterministic testing (PR #266 pattern).
	now       func() time.Time
	newTimer  func(time.Duration) probeTimer
	randFloat func() float64

	conflictHandler func(ConflictEvent) ConflictAction
	onRenamed       func(oldName, newName string, isHost bool)

	inbound chan *dnsmessage.Message
	ready   chan struct{} // closed when initial probing completes.
	done    chan struct{} // closed when run() exits.
}

func newProbeManager(
	questionWriter questionWriter,
	answerWriter answerWriter,
	log logging.LeveledLogger,
	logName string,
	ttl uint32,
	conflictHandler func(ConflictEvent) ConflictAction,
	onRenamed func(oldName, newName string, isHost bool),
) *probeManager {
	return &probeManager{
		questionWriter:  questionWriter,
		answerWriter:    answerWriter,
		log:             log,
		logName:         logName,
		ttl:             ttl,
		conflictHandler: conflictHandler,
		onRenamed:       onRenamed,
		now:             time.Now,
		newTimer:        newRealTimer,
		randFloat:       rand.Float64, //nolint:gosec
		inbound:         make(chan *dnsmessage.Message, 64),
		ready:           make(chan struct{}),
		done:            make(chan struct{}),
	}
}

// addSession registers a name for probing. Must be called before run().
func (m *probeManager) addSession(name string, records []dnsmessage.Resource, isHost bool) {
	delay := time.Duration(m.randFloat() * float64(probeDelay))

	m.sessions = append(m.sessions, &probeSession{
		name:      name,
		records:   records,
		isHost:    isHost,
		state:     probeStateDelay,
		nextEvent: m.now().Add(delay),
	})
}

// isProbing reports whether the given name is currently being probed
// (not yet established). Safe to call from any goroutine.
func (m *probeManager) isProbing(name string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	lower := strings.ToLower(name)
	for _, s := range m.sessions {
		if strings.ToLower(s.name) == lower && s.state != probeStateEstablished && s.state != probeStateStopped {
			return true
		}
	}

	return false
}

// handleMessage feeds an incoming DNS message to the probe manager for
// conflict detection. Called from readLoop goroutines. Blocks until the
// message is accepted or the event loop has exited.
func (m *probeManager) handleMessage(msg *dnsmessage.Message) {
	select {
	case m.inbound <- msg:
	case <-m.done:
	}
}

// run is the event loop. It processes timer ticks and inbound messages
// until the closed channel is signaled. Call in a goroutine.
//
//nolint:gocognit,gocyclo,cyclop
func (m *probeManager) run(closed <-chan any) {
	defer close(m.done)

	if len(m.sessions) == 0 {
		close(m.ready)

		return
	}

	readyClosed := false
	signalReady := func() {
		if readyClosed {
			return
		}

		m.mu.RLock()
		all := m.allDone()
		m.mu.RUnlock()

		if all {
			close(m.ready)
			readyClosed = true
		}
	}

	for {
		// Process any overdue events (state under lock, I/O after).
		pio := m.processOverdue()
		m.executeIO(pio)
		signalReady()

		m.mu.RLock()
		dur := m.durationToNext()
		m.mu.RUnlock()

		if dur < 0 {
			// No pending timer events, wait for messages or close.
			select {
			case msg := <-m.inbound:
				m.mu.Lock()
				m.processMessage(msg)
				m.mu.Unlock()
				signalReady()
			case <-closed:
				if !readyClosed {
					close(m.ready)
				}

				return
			}

			continue
		}

		timer := m.newTimer(dur)

		select {
		case <-timer.Chan():
			timer.Stop()
			// Will process overdue on next iteration.
		case msg := <-m.inbound:
			timer.Stop()
			m.mu.Lock()
			m.processMessage(msg)
			m.mu.Unlock()
			signalReady()
		case <-closed:
			timer.Stop()
			if !readyClosed {
				close(m.ready)
			}

			return
		}
	}
}

// allDone reports whether all sessions are established or stopped.
// Caller must hold at least mu.RLock.
func (m *probeManager) allDone() bool {
	for _, s := range m.sessions {
		if s.state != probeStateEstablished && s.state != probeStateStopped {
			return false
		}
	}

	return true
}

// durationToNext returns the duration until the next timer event,
// or -1 if there are no pending events. Caller must hold mu.RLock.
func (m *probeManager) durationToNext() time.Duration {
	now := m.now()
	earliest := time.Duration(-1)

	for _, s := range m.sessions {
		if s.state == probeStateEstablished || s.state == probeStateStopped {
			continue
		}

		d := s.nextEvent.Sub(now)
		if d < 0 {
			d = 0
		}

		if earliest < 0 || d < earliest {
			earliest = d
		}
	}

	return earliest
}

// processOverdue advances sessions under the lock and returns pending I/O
// to be executed without the lock.
func (m *probeManager) processOverdue() pendingIO {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.now()
	var pio pendingIO

	for _, sess := range m.sessions {
		if sess.state == probeStateStopped {
			continue
		}

		if sess.conflict {
			m.handleConflictForSession(sess, now, &pio)

			continue
		}

		if sess.tiebreakDefer {
			m.handleTiebreakDefer(sess, now)

			continue
		}

		if sess.state == probeStateEstablished {
			continue
		}

		if now.Before(sess.nextEvent) {
			continue
		}

		m.stepSession(sess, now, &pio)
	}

	return pio
}

// executeIO sends all collected packets and fires rename callbacks
// without holding the lock.
func (m *probeManager) executeIO(pio pendingIO) {
	for _, raw := range pio.probes {
		m.questionWriter.writeQuestion(raw)
	}

	for _, raw := range pio.announces {
		m.answerWriter.writeAnswer(-1, raw, false, false, nil)
	}

	for _, re := range pio.renames {
		if m.onRenamed != nil {
			m.onRenamed(re.oldName, re.newName, re.isHost)
		}
	}
}

// stepSession advances a session by one step in the state machine.
// Caller must hold mu.Lock.
func (m *probeManager) stepSession(sess *probeSession, now time.Time, pio *pendingIO) {
	switch sess.state {
	case probeStateDelay:
		sess.state = probeStateProbing
		m.enqueueProbe(sess, pio)
		sess.probesSent++
		sess.nextEvent = now.Add(probeInterval)

	case probeStateProbing:
		if sess.probesSent < probeCount {
			m.enqueueProbe(sess, pio)
			sess.probesSent++
			sess.nextEvent = now.Add(probeInterval)
		} else {
			sess.state = probeStateAnnouncing
			m.enqueueAnnounce(sess, pio)
			sess.announcesSent++
			sess.nextEvent = now.Add(announceInterval)
		}

	case probeStateAnnouncing:
		m.enqueueAnnounce(sess, pio)
		sess.announcesSent++

		if sess.announcesSent < announceCount {
			sess.nextEvent = now.Add(announceInterval)
		} else {
			sess.state = probeStateEstablished
			m.log.Infof("[%s] probe: %s established", m.logName, sess.name)
		}

	case probeStateEstablished, probeStateStopped:
		// No-op.
	}
}

// handleTiebreakDefer processes a simultaneous probe tiebreak loss (§8.2).
// The session waits 1 second and then re-probes with the same name. No rename
// occurs — the 1s delay guards against stale packets on the network.
// Caller must hold mu.Lock.
func (m *probeManager) handleTiebreakDefer(sess *probeSession, now time.Time) {
	sess.tiebreakDefer = false
	sess.state = probeStateDelay
	sess.probesSent = 0
	sess.announcesSent = 0
	sess.nextEvent = now.Add(time.Second)
	m.log.Infof("[%s] probe: tiebreak loss for %s, re-probing in 1s", m.logName, sess.name)
}

// handleConflictForSession processes a naming conflict.
// Caller must hold mu.Lock.
//
//nolint:cyclop
func (m *probeManager) handleConflictForSession(sess *probeSession, now time.Time, pio *pendingIO) {
	sess.conflict = false
	sess.tiebreakDefer = false
	sess.conflictCount++

	// Track rate limiting.
	sess.conflictTimes = append(sess.conflictTimes, now)
	if sess.firstConflict.IsZero() {
		sess.firstConflict = now
	}

	m.log.Warnf("[%s] probe: conflict #%d for %s", m.logName, sess.conflictCount, sess.name)

	// Give up after sustained conflicts.
	if now.Sub(sess.firstConflict) > conflictGiveUp && sess.conflictCount > conflictRateLimit {
		m.log.Errorf("[%s] probe: giving up on %s after %d conflicts", m.logName, sess.name, sess.conflictCount)
		sess.state = probeStateStopped

		return
	}

	// Ask user for rename action.
	action := m.resolveConflict(sess)
	if action.Stop {
		m.log.Infof("[%s] probe: user stopped probing for %s", m.logName, sess.name)
		sess.state = probeStateStopped

		return
	}

	// Determine new name.
	oldName := sess.name
	newName := action.Rename

	if newName == "" {
		newName = defaultRename(sess.name, sess.conflictCount, sess.isHost)
	}

	m.log.Infof("[%s] probe: renaming %s -> %s", m.logName, oldName, newName)

	// Update session records with new name.
	m.renameSession(sess, newName)

	// Queue server notification (executed without lock).
	pio.renames = append(pio.renames, renameEvent{
		oldName: oldName,
		newName: newName,
		isHost:  sess.isHost,
	})

	// Rate-limit backoff.
	delay := probeDelay
	backoff := m.shouldBackoff(sess, now)

	if backoff > 0 {
		delay += backoff
	}

	sess.state = probeStateDelay
	sess.probesSent = 0
	sess.announcesSent = 0
	sess.nextEvent = now.Add(delay)
}

// resolveConflict calls the user conflict handler or returns an empty action.
func (m *probeManager) resolveConflict(sess *probeSession) ConflictAction {
	if m.conflictHandler == nil {
		return ConflictAction{}
	}

	return m.conflictHandler(ConflictEvent{
		Name:  sess.name,
		Count: sess.conflictCount,
		Host:  sess.isHost,
	})
}

// shouldBackoff checks rate limiting: 15 conflicts in 10s → 5s backoff.
func (m *probeManager) shouldBackoff(sess *probeSession, now time.Time) time.Duration {
	cutoff := now.Add(-conflictRateWindow)
	valid := 0

	for _, t := range sess.conflictTimes {
		if !t.Before(cutoff) {
			sess.conflictTimes[valid] = t
			valid++
		}
	}

	sess.conflictTimes = sess.conflictTimes[:valid]

	if len(sess.conflictTimes) >= conflictRateLimit {
		return conflictBackoff
	}

	return 0
}

// renameSession updates the session's name and rewrites all record headers.
func (m *probeManager) renameSession(sess *probeSession, newName string) {
	sess.name = newName

	newDNSName, err := dnsmessage.NewName(newName)
	if err != nil {
		m.log.Warnf("[%s] probe: failed to create DNS name %s: %v", m.logName, newName, err)

		return
	}

	for i := range sess.records {
		sess.records[i].Header.Name = newDNSName
	}
}

// enqueueProbe builds a probe query and appends it to the pending I/O.
func (m *probeManager) enqueueProbe(sess *probeSession, pio *pendingIO) {
	raw, err := buildProbeQuery(sess.name, sess.records)
	if err != nil {
		m.log.Warnf("[%s] probe: failed to build probe for %s: %v", m.logName, sess.name, err)

		return
	}

	m.log.Debugf("[%s] probe: queueing probe %d/%d for %s", m.logName, sess.probesSent+1, probeCount, sess.name)
	pio.probes = append(pio.probes, raw)
}

// enqueueAnnounce builds an announcement and appends it to the pending I/O.
func (m *probeManager) enqueueAnnounce(sess *probeSession, pio *pendingIO) {
	raw, err := buildAnnouncement(sess.records)
	if err != nil {
		m.log.Warnf("[%s] probe: failed to build announce for %s: %v", m.logName, sess.name, err)

		return
	}

	m.log.Debugf("[%s] probe: queueing announce %d/%d for %s", m.logName, sess.announcesSent+1, announceCount, sess.name)
	pio.announces = append(pio.announces, raw)
}

// processMessage handles an inbound DNS message for conflict detection.
// Caller must hold mu.Lock.
func (m *probeManager) processMessage(msg *dnsmessage.Message) {
	if msg.Header.Response {
		m.processResponse(msg)
	} else {
		m.processProbe(msg)
	}
}

// processResponse checks response answers against probed/established names.
// An answer matching our name during probing or with conflicting rdata during
// established state triggers a conflict.
// Caller must hold mu.Lock.
func (m *probeManager) processResponse(msg *dnsmessage.Message) {
	// §9: check "any of the Resource Record Sections" for conflicts.
	allRecords := msg.Answers
	allRecords = append(allRecords, msg.Authorities...)
	allRecords = append(allRecords, msg.Additionals...)

	for _, sess := range m.sessions {
		if sess.state == probeStateStopped {
			continue
		}

		for idx := range allRecords {
			rec := &allRecords[idx]
			if !strings.EqualFold(rec.Header.Name.String(), sess.name) {
				continue
			}

			switch sess.state {
			case probeStateDelay:
				// Responses before the first probe MUST be silently
				// ignored (§8.1 — stale probe guard).
			case probeStateProbing:
				// Any record for our name during probing = conflict (§8.1).
				sess.conflict = true
			case probeStateAnnouncing, probeStateEstablished:
				// Record with different rdata for our unique record = conflict.
				if m.isConflictingRData(sess, rec) {
					sess.conflict = true
				}
			case probeStateStopped:
				// No-op.
			}
		}
	}
}

// processProbe handles incoming probes (questions with authority section)
// for simultaneous probe tiebreaking (§8.2).
// Caller must hold mu.Lock.
func (m *probeManager) processProbe(msg *dnsmessage.Message) {
	if len(msg.Authorities) == 0 {
		return
	}

	for _, sess := range m.sessions {
		if sess.state != probeStateProbing {
			continue
		}

		for _, q := range msg.Questions {
			if !strings.EqualFold(q.Name.String(), sess.name) {
				continue
			}

			m.tiebreakQuestion(sess, q, msg.Authorities)
		}
	}
}

// tiebreakQuestion performs simultaneous probe tiebreaking (section 8.2) for a
// single question against the session's proposed records.
// Caller must hold mu.Lock.
func (m *probeManager) tiebreakQuestion(sess *probeSession, _ dnsmessage.Question, authorities []dnsmessage.Resource) {
	// Collect their authority records for our name.
	var theirs []dnsmessage.Resource
	for _, auth := range authorities {
		if strings.EqualFold(auth.Header.Name.String(), sess.name) {
			theirs = append(theirs, auth)
		}
	}

	if len(theirs) == 0 {
		return
	}

	// Tiebreak: compare our records vs theirs.
	result := lexicographicCompare(sess.records, theirs)
	if result < 0 {
		// We lose -- defer to them.
		sess.tiebreakDefer = true
	}
	// If we win (result > 0) or tie (result == 0), continue probing.
}

// isConflictingRData checks whether an answer has rdata we do not own for
// the same name and record type. A conflict exists only when the answer's
// rdata matches none of our records of that type.
func (m *probeManager) isConflictingRData(sess *probeSession, answer *dnsmessage.Resource) bool {
	ansType := answer.Header.Type
	theirs := packRData(answer.Body)
	hasType := false

	for _, rec := range sess.records {
		if rec.Header.Type != ansType {
			continue
		}

		hasType = true

		if bytes.Equal(packRData(rec.Body), theirs) {
			return false // matches one of ours.
		}
	}

	return hasType // conflict only if we have this type but no match.
}

// buildProbeQuery creates a probe query message (§8.1):
//
//	Questions:   [Name=target, Type=ANY(255), Class=IN|QU]
//	Authorities: proposed records
func buildProbeQuery(name string, records []dnsmessage.Resource) ([]byte, error) {
	dnsName, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, err
	}

	msg := dnsmessage.Message{
		Questions: []dnsmessage.Question{{
			Name:  dnsName,
			Type:  typeANY,
			Class: dnsmessage.ClassINET | qClassUnicastResponse,
		}},
		Authorities: records,
	}

	return msg.Pack()
}

// buildAnnouncement creates an unsolicited announcement (§8.3).
// Unique records get the cache-flush bit; PTR records (shared) do not.
func buildAnnouncement(records []dnsmessage.Resource) ([]byte, error) {
	answers := make([]dnsmessage.Resource, len(records))
	copy(answers, records)

	for i := range answers {
		// PTR records are shared — no cache-flush bit.
		if answers[i].Header.Type == dnsmessage.TypePTR {
			continue
		}

		answers[i].Header.Class |= rrClassCacheFlush
	}

	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			Response:      true,
			Authoritative: true,
		},
		Answers: answers,
	}

	return msg.Pack()
}

// lexicographicCompare compares two sets of resource records using the
// algorithm from RFC 6762 §8.2 for simultaneous probe tiebreaking.
//
// Each set is sorted by class, then type, then rdata. Records are compared
// pairwise; the first difference decides the outcome.
//
// Returns -1 if ours < theirs, 0 if equal, +1 if ours > theirs.
func lexicographicCompare(ours, theirs []dnsmessage.Resource) int {
	// Work on copies to avoid mutating the originals.
	oCopy := make([]dnsmessage.Resource, len(ours))
	copy(oCopy, ours)
	sortResources(oCopy)

	tCopy := make([]dnsmessage.Resource, len(theirs))
	copy(tCopy, theirs)
	sortResources(tCopy)

	n := len(oCopy)
	if len(tCopy) < n {
		n = len(tCopy)
	}

	for i := 0; i < n; i++ {
		if c := compareResource(oCopy[i], tCopy[i]); c != 0 {
			return c
		}
	}

	return cmp.Compare(len(oCopy), len(tCopy))
}

// sortResources sorts records by class, then type, then rdata (§8.2).
func sortResources(rs []dnsmessage.Resource) {
	for i := 1; i < len(rs); i++ {
		for j := i; j > 0 && compareResource(rs[j-1], rs[j]) > 0; j-- {
			rs[j-1], rs[j] = rs[j], rs[j-1]
		}
	}
}

// compareResource compares two resource records: class (mask cache-flush),
// then type, then raw rdata.
func compareResource(resA, resB dnsmessage.Resource) int {
	// Compare class without cache-flush bit.
	aClass := resA.Header.Class &^ rrClassCacheFlush
	bClass := resB.Header.Class &^ rrClassCacheFlush

	if c := cmp.Compare(aClass, bClass); c != 0 {
		return c
	}

	if c := cmp.Compare(resA.Header.Type, resB.Header.Type); c != 0 {
		return c
	}

	aData := packRData(resA.Body)
	bData := packRData(resB.Body)

	return bytes.Compare(aData, bData)
}

// packRData serializes the rdata portion of a resource record body into
// wire-format bytes for lexicographic comparison.
//
//nolint:cyclop
func packRData(body dnsmessage.ResourceBody) []byte {
	if body == nil {
		return nil
	}

	switch rec := body.(type) {
	case *dnsmessage.AResource:
		return rec.A[:]
	case *dnsmessage.AAAAResource:
		return rec.AAAA[:]
	case *dnsmessage.SRVResource:
		buf := make([]byte, 0, 6+255)
		buf = append(buf, 0, 0, 0, 0, 0, 0)
		binary.BigEndian.PutUint16(buf[0:2], rec.Priority)
		binary.BigEndian.PutUint16(buf[2:4], rec.Weight)
		binary.BigEndian.PutUint16(buf[4:6], rec.Port)

		return append(buf, packDNSName(rec.Target)...)
	case *dnsmessage.TXTResource:
		var buf []byte
		for _, txt := range rec.TXT {
			buf = append(buf, byte(len(txt)))
			buf = append(buf, txt...)
		}

		return buf
	case *dnsmessage.PTRResource:
		return packDNSName(rec.PTR)
	default:
		return nil
	}
}

// packDNSName serializes a DNS name into wire-format bytes (sequence of
// length-prefixed labels ending with a zero byte).
func packDNSName(n dnsmessage.Name) []byte {
	s := n.String()
	if s == "" || s == "." {
		return []byte{0}
	}

	s = strings.TrimSuffix(s, ".")
	labels := strings.Split(s, ".")

	var buf []byte
	for _, label := range labels {
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}

	return append(buf, 0)
}

// defaultRename generates a conflict-avoidance name per RFC 6762 §9.
//
// Hostnames: "myhost.local." → "myhost-2.local."
// Service instances: "My Service._http._tcp.local." → "My Service (2)._http._tcp.local.".
func defaultRename(fqdn string, conflictCount int, isHost bool) string {
	suffix := conflictCount + 1

	if isHost {
		return defaultRenameHost(fqdn, suffix)
	}

	return defaultRenameServiceInstance(fqdn, suffix)
}

func defaultRenameHost(fqdn string, num int) string {
	// "myhost.local." → split into ["myhost", "local."]
	idx := strings.IndexByte(fqdn, '.')
	if idx < 0 {
		return fmt.Sprintf("%s-%d", fqdn, num)
	}

	host := fqdn[:idx]

	// Strip previous rename suffix: "myhost-2" → "myhost".
	if dashIdx := strings.LastIndexByte(host, '-'); dashIdx >= 0 {
		candidate := host[dashIdx+1:]
		allDigit := true

		for _, c := range candidate {
			if c < '0' || c > '9' {
				allDigit = false

				break
			}
		}

		if allDigit && len(candidate) > 0 {
			host = host[:dashIdx]
		}
	}

	return fmt.Sprintf("%s-%d%s", host, num, fqdn[idx:])
}

func defaultRenameServiceInstance(fqdn string, num int) string {
	// Service instance FQDN: "My\.Service._http._tcp.local."
	// The instance part is everything before the service type (first
	// unescaped underscore label).
	//
	// Find the service type boundary: first label starting with '_'.
	parts := strings.SplitN(fqdn, "._", 2)
	if len(parts) < 2 {
		return fmt.Sprintf("%s (%d)", fqdn, num)
	}

	instance := stripServiceSuffix(parts[0])

	return fmt.Sprintf("%s (%d)._%s", instance, num, parts[1])
}

// stripServiceSuffix removes a previous " (N)" rename suffix from the
// service instance name, e.g. "My Service (2)" becomes "My Service".
func stripServiceSuffix(instance string) string {
	parenIdx := strings.LastIndex(instance, " (")
	if parenIdx < 0 {
		return instance
	}

	candidate := instance[parenIdx+2:]
	if !strings.HasSuffix(candidate, ")") {
		return instance
	}

	inner := candidate[:len(candidate)-1]
	if len(inner) == 0 {
		return instance
	}

	for _, c := range inner {
		if c < '0' || c > '9' {
			return instance
		}
	}

	return instance[:parenIdx]
}
