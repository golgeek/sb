// Package dedupcache provides a small, library-agnostic TTL set used to
// deduplicate short-lived identifiers. The replication daemon uses it to avoid
// acting on the same replication entry more than once when that entry is
// observed multiple times within a time window.
//
// As with the archive package, the indirection exists so that the underlying
// TTL-cache library can be swapped without touching callers (they depend only
// on the Seen/Mark/Close API declared here) and so the deduplication behavior
// can be covered by a hermetic unit test that knows nothing about the library.
package dedupcache

import (
	"time"

	"github.com/ReneKroon/ttlcache"
)

// Cache records identifiers that have been "seen", expiring each one after a
// fixed TTL. It is safe for the concurrent use the daemon makes of it because
// the underlying cache is itself concurrency-safe.
type Cache struct {
	cache *ttlcache.Cache
}

// New returns a Cache whose entries expire after ttl has elapsed. Callers
// should Close the cache when it is no longer needed so its background eviction
// goroutine is released.
func New(ttl time.Duration) *Cache {
	c := ttlcache.NewCache()
	c.SetTTL(ttl)
	return &Cache{cache: c}
}

// Seen reports whether id was marked within the TTL window and has not yet
// expired.
func (c *Cache) Seen(id string) bool {
	_, ok := c.cache.Get(id)
	return ok
}

// Mark records id as seen, starting (or, for an id seen again, refreshing) its
// TTL window. The stored value is irrelevant; only the presence of the key
// matters, so an empty struct is used.
func (c *Cache) Mark(id string) {
	c.cache.Set(id, struct{}{})
}

// Close stops the cache's background eviction and releases its resources.
func (c *Cache) Close() {
	c.cache.Close()
}
