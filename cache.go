// SPDX-FileCopyrightText: The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package mdns

import (
	"math/rand"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// rrClassCacheFlush is the cache-flush bit in the rrclass field of a
// resource record (RFC 6762 §10.2).
const rrClassCacheFlush = 1 << 15

// goodbyeTTL is the time-to-live for goodbye packets (RFC 6762 §10.1).
// Records with TTL=0 are retained for one second before removal.
const goodbyeTTL = 1 * time.Second

// cacheFlushDelay is the grace period before flushing stale records
// after receiving a cache-flush response (RFC 6762 §10.2).
const cacheFlushDelay = 1 * time.Second

// maxRecordTTL caps the lifetime of cached records. RFC 6762 §10
// recommends TTLs of 75 minutes or less; clamping protects against
// hostile or misconfigured responders advertising near-immortal records.
const maxRecordTTL = 75 * time.Minute

// maxCacheEntries caps the total number of cached records so that a busy
// or hostile network cannot grow the cache without bound. When full, the
// entry closest to expiry is evicted to make room.
const maxCacheEntries = 4096

// cacheKey identifies a set of records by lowercased name, type, and
// class (with the cache-flush bit masked).
type cacheKey struct {
	name    string
	rrType  dnsmessage.Type
	rrClass dnsmessage.Class
}

// cacheEntry stores one cached resource record with timing metadata.
type cacheEntry struct {
	resource      dnsmessage.Resource
	createdAt     time.Time
	expiresAt     time.Time
	originalTTL   time.Duration
	refreshJitter float64
	refreshesSent uint8
}

// cache is a thread-safe mDNS record cache (RFC 6762 §10).
type cache struct {
	mu      sync.RWMutex
	entries map[cacheKey][]cacheEntry
	size    int
	now     func() time.Time
}

// newCache creates a cache with the given clock function.
func newCache(now func() time.Time) *cache {
	return &cache{
		entries: make(map[cacheKey][]cacheEntry),
		now:     now,
	}
}

// makeCacheKey builds a cache key from a resource header.
// The name is lowercased for case-insensitive matching.
func makeCacheKey(hdr dnsmessage.ResourceHeader) cacheKey {
	return cacheKey{
		name:    strings.ToLower(hdr.Name.String()),
		rrType:  hdr.Type,
		rrClass: hdr.Class,
	}
}

// insert adds or updates a record in the cache. It handles goodbye
// packets (TTL=0, §10.1), the cache-flush bit (§10.2), and normal
// insert/update operations.
func (c *cache) insert(res dnsmessage.Resource, receivedAt time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	hasCacheFlush := res.Header.Class&rrClassCacheFlush != 0
	res.Header.Class &^= rrClassCacheFlush

	key := makeCacheKey(res.Header)

	if res.Header.TTL == 0 {
		c.insertGoodbye(key, res, receivedAt)

		return
	}

	if hasCacheFlush {
		c.applyCacheFlush(key, receivedAt)
	}

	c.insertOrUpdate(key, res, receivedAt)
}

// insertGoodbye handles a record with TTL=0 (RFC 6762 §10.1).
// If a matching record exists, its expiry is set to now+1s.
// Otherwise a new entry is created with a 1s TTL. Goodbye entries
// keep originalTTL=0 so they are never refresh candidates.
func (c *cache) insertGoodbye(key cacheKey, res dnsmessage.Resource, receivedAt time.Time) {
	entries := c.entries[key]
	for idx := range entries {
		if resourceDataEqual(entries[idx].resource, res) {
			entries[idx].expiresAt = receivedAt.Add(goodbyeTTL)
			entries[idx].originalTTL = 0

			return
		}
	}

	// Unknown record: insert with 1s TTL so that late listeners see
	// the goodbye briefly before it expires.
	res.Header.TTL = 1
	c.appendEntry(key, cacheEntry{
		resource:  res,
		createdAt: receivedAt,
		expiresAt: receivedAt.Add(goodbyeTTL),
	})
}

// applyCacheFlush marks old entries for the same key as expiring in 1s
// (RFC 6762 §10.2). Entries created within the last second are preserved.
func (c *cache) applyCacheFlush(key cacheKey, receivedAt time.Time) {
	entries := c.entries[key]
	deadline := receivedAt.Add(-cacheFlushDelay)

	for idx := range entries {
		if entries[idx].createdAt.Before(deadline) {
			entries[idx].expiresAt = receivedAt.Add(cacheFlushDelay)
		}
	}
}

// insertOrUpdate adds a new record or updates the TTL of an existing
// record with the same rdata. TTLs are clamped to maxRecordTTL.
func (c *cache) insertOrUpdate(key cacheKey, res dnsmessage.Resource, receivedAt time.Time) {
	ttl := min(time.Duration(res.Header.TTL)*time.Second, maxRecordTTL)
	entries := c.entries[key]

	for idx := range entries {
		if resourceDataEqual(entries[idx].resource, res) {
			entries[idx].resource.Header.TTL = res.Header.TTL
			entries[idx].createdAt = receivedAt
			entries[idx].expiresAt = receivedAt.Add(ttl)
			entries[idx].originalTTL = ttl
			entries[idx].refreshJitter = newRefreshJitter()
			entries[idx].refreshesSent = 0

			return
		}
	}

	c.appendEntry(key, cacheEntry{
		resource:      res,
		createdAt:     receivedAt,
		expiresAt:     receivedAt.Add(ttl),
		originalTTL:   ttl,
		refreshJitter: newRefreshJitter(),
	})
}

// appendEntry adds a new entry under key, evicting the entry closest to
// expiry when the cache is at capacity.
func (c *cache) appendEntry(key cacheKey, entry cacheEntry) {
	if c.size >= maxCacheEntries {
		c.evictSoonestExpiring()
	}

	c.entries[key] = append(c.entries[key], entry)
	c.size++
}

// evictSoonestExpiring removes the entry with the earliest expiry.
func (c *cache) evictSoonestExpiring() {
	var victimKey cacheKey
	victimIdx := -1
	var victimExpiry time.Time

	for key, entries := range c.entries {
		for idx := range entries {
			if victimIdx == -1 || entries[idx].expiresAt.Before(victimExpiry) {
				victimKey = key
				victimIdx = idx
				victimExpiry = entries[idx].expiresAt
			}
		}
	}

	if victimIdx == -1 {
		return
	}

	entries := c.entries[victimKey]
	entries = append(entries[:victimIdx], entries[victimIdx+1:]...)

	if len(entries) == 0 {
		delete(c.entries, victimKey)
	} else {
		c.entries[victimKey] = entries
	}

	c.size--
}

// lookup returns non-expired records matching the name, type, and class.
// The name match is case-insensitive. Each returned record has its TTL
// set to the remaining time before expiry.
func (c *cache) lookup(name string, rrType dnsmessage.Type, rrClass dnsmessage.Class) []dnsmessage.Resource {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := cacheKey{
		name:    strings.ToLower(name),
		rrType:  rrType,
		rrClass: rrClass,
	}

	now := c.now()
	var results []dnsmessage.Resource

	for _, entry := range c.entries[key] {
		if !now.Before(entry.expiresAt) {
			continue
		}

		res := entry.resource
		remaining := entry.expiresAt.Sub(now)
		res.Header.TTL = uint32(remaining / time.Second) //nolint:gosec // remaining is positive after expiry check
		results = append(results, res)
	}

	return results
}

// sweep removes all expired entries from the cache.
func (c *cache) sweep() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	size := 0

	for key, entries := range c.entries {
		var alive []cacheEntry

		for _, entry := range entries {
			if now.Before(entry.expiresAt) {
				alive = append(alive, entry)
			}
		}

		if len(alive) == 0 {
			delete(c.entries, key)
		} else {
			c.entries[key] = alive
			size += len(alive)
		}
	}

	c.size = size
}

// refreshThresholds returns the fractions of TTL at which refresh queries
// are sent (RFC 6762 §5.2): 80%, 85%, 90%, 95%.
func refreshThresholds() [4]float64 {
	return [4]float64{0.80, 0.85, 0.90, 0.95}
}

// maxRefreshJitter is the maximum random jitter added to each threshold.
const maxRefreshJitter = 0.02

// newRefreshJitter returns a random 0-2% addition to the next refresh
// threshold (RFC 6762 §5.2). Rolled once per threshold so that repeated
// polling does not bias refreshes toward the unjittered threshold.
func newRefreshJitter() float64 {
	return rand.Float64() * maxRefreshJitter //nolint:gosec // weak random is fine for jitter
}

// dueForRefresh checks the given cache keys and returns those with entries
// that have reached their next refresh threshold (RFC 6762 §5.2).
// Duplicate keys are checked once. For each returned candidate,
// refreshesSent is incremented; entries with originalTTL = 0 (goodbyes)
// are skipped and at most four refreshes are sent per entry per TTL.
func (c *cache) dueForRefresh(keys []cacheKey) []cacheKey {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	thresholds := refreshThresholds()

	var candidates []cacheKey
	seen := make(map[cacheKey]struct{}, len(keys))

	for _, key := range keys {
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		entries := c.entries[key]
		for idx := range entries {
			entry := &entries[idx]
			if entry.originalTTL <= 0 || int(entry.refreshesSent) >= len(thresholds) {
				continue
			}

			if !now.Before(entry.expiresAt) {
				continue
			}

			startedAt := entry.expiresAt.Add(-entry.originalTTL)
			fraction := float64(now.Sub(startedAt)) / float64(entry.originalTTL)

			if fraction >= thresholds[entry.refreshesSent]+entry.refreshJitter {
				candidates = append(candidates, key)
				entry.refreshesSent++
				entry.refreshJitter = newRefreshJitter()
			}
		}
	}

	return candidates
}

// flushAll drops all entries (RFC 6762 §10.3 topology change).
func (c *cache) flushAll() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make(map[cacheKey][]cacheEntry)
	c.size = 0
}

// reduceTTLs caps the remaining TTL of every entry to maxRemaining.
// Entries that already expire sooner are left unchanged.
func (c *cache) reduceTTLs(maxRemaining time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	deadline := now.Add(maxRemaining)

	for _, entries := range c.entries {
		for idx := range entries {
			if entries[idx].expiresAt.After(deadline) {
				entries[idx].expiresAt = deadline
			}
		}
	}
}

// len returns the count of non-expired entries.
func (c *cache) len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	now := c.now()
	count := 0

	for _, entries := range c.entries {
		for _, entry := range entries {
			if now.Before(entry.expiresAt) {
				count++
			}
		}
	}

	return count
}

// resourceDataEqual reports whether two resources have the same name,
// type, and body content. Name comparison is case-insensitive.
func resourceDataEqual(resA, resB dnsmessage.Resource) bool {
	if !strings.EqualFold(resA.Header.Name.String(), resB.Header.Name.String()) {
		return false
	}

	if resA.Header.Type != resB.Header.Type {
		return false
	}

	return resourceBodyEqual(resA.Body, resB.Body)
}

// resourceBodyEqual compares two resource bodies by type-specific fields.
//
//nolint:cyclop
func resourceBodyEqual(bodyA, bodyB dnsmessage.ResourceBody) bool {
	switch valA := bodyA.(type) {
	case *dnsmessage.AResource:
		valB, ok := bodyB.(*dnsmessage.AResource)

		return ok && valA.A == valB.A
	case *dnsmessage.AAAAResource:
		valB, ok := bodyB.(*dnsmessage.AAAAResource)

		return ok && valA.AAAA == valB.AAAA
	case *dnsmessage.PTRResource:
		valB, ok := bodyB.(*dnsmessage.PTRResource)

		return ok && strings.EqualFold(valA.PTR.String(), valB.PTR.String())
	case *dnsmessage.SRVResource:
		valB, ok := bodyB.(*dnsmessage.SRVResource)

		return ok && srvFieldsEqual(valA, valB)
	case *dnsmessage.TXTResource:
		valB, ok := bodyB.(*dnsmessage.TXTResource)

		return ok && txtSlicesEqual(valA.TXT, valB.TXT)
	default:
		return false
	}
}

// srvFieldsEqual compares two SRV resource bodies field by field.
func srvFieldsEqual(resA, resB *dnsmessage.SRVResource) bool {
	return strings.EqualFold(resA.Target.String(), resB.Target.String()) &&
		resA.Port == resB.Port &&
		resA.Priority == resB.Priority &&
		resA.Weight == resB.Weight
}

// txtSlicesEqual reports whether two TXT string slices are identical.
func txtSlicesEqual(sliceA, sliceB []string) bool {
	if len(sliceA) != len(sliceB) {
		return false
	}

	for idx := range sliceA {
		if sliceA[idx] != sliceB[idx] {
			return false
		}
	}

	return true
}
