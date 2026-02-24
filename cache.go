// SPDX-FileCopyrightText: The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package mdns

import (
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

// cacheKey identifies a set of records by lowercased name, type, and
// class (with the cache-flush bit masked).
type cacheKey struct {
	name    string
	rrType  dnsmessage.Type
	rrClass dnsmessage.Class
}

// cacheEntry stores one cached resource record with timing metadata.
type cacheEntry struct {
	resource  dnsmessage.Resource
	createdAt time.Time
	expiresAt time.Time
}

// cache is a thread-safe mDNS record cache (RFC 6762 §10).
type cache struct {
	mu      sync.RWMutex
	entries map[cacheKey][]cacheEntry
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
// Otherwise a new entry is created with a 1s TTL.
func (c *cache) insertGoodbye(key cacheKey, res dnsmessage.Resource, receivedAt time.Time) {
	entries := c.entries[key]
	for idx := range entries {
		if resourceDataEqual(entries[idx].resource, res) {
			entries[idx].expiresAt = receivedAt.Add(goodbyeTTL)

			return
		}
	}

	// Unknown record: insert with 1s TTL so that late listeners see
	// the goodbye briefly before it expires.
	res.Header.TTL = 1
	c.entries[key] = append(entries, cacheEntry{
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
// record with the same rdata.
func (c *cache) insertOrUpdate(key cacheKey, res dnsmessage.Resource, receivedAt time.Time) {
	ttl := time.Duration(res.Header.TTL) * time.Second
	entries := c.entries[key]

	for idx := range entries {
		if resourceDataEqual(entries[idx].resource, res) {
			entries[idx].resource.Header.TTL = res.Header.TTL
			entries[idx].expiresAt = receivedAt.Add(ttl)

			return
		}
	}

	c.entries[key] = append(entries, cacheEntry{
		resource:  res,
		createdAt: receivedAt,
		expiresAt: receivedAt.Add(ttl),
	})
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
		}
	}
}

// flushAll drops all entries (RFC 6762 §10.3 topology change).
func (c *cache) flushAll() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = make(map[cacheKey][]cacheEntry)
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
