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

	"github.com/jellydator/ttlcache/v3"
)

// Cache records identifiers that have been "seen", expiring each one after a
// fixed TTL. It is safe for the concurrent use the daemon makes of it because
// the underlying cache is itself concurrency-safe.
//
// The stored value type is an empty struct: only the presence of a key matters,
// never its value.
type Cache struct {
	cache *ttlcache.Cache[string, struct{}]
}

// New returns a Cache whose entries expire after ttl has elapsed. A background
// eviction goroutine is started so that entries which are marked but never
// looked up again are still reclaimed; callers must Close the cache when it is
// no longer needed to stop that goroutine.
func New(ttl time.Duration) *Cache {
	c := ttlcache.New[string, struct{}](
		ttlcache.WithTTL[string, struct{}](ttl),
	)

	// Start runs the periodic eviction loop and blocks until Stop is called, so
	// it must run in its own goroutine. Without it, expired entries would only
	// be reclaimed lazily on access, letting never-revisited ids accumulate.
	go c.Start()

	return &Cache{cache: c}
}

// Seen reports whether id was marked within the TTL window and has not yet
// expired. It relies on Get, which evaluates expiration lazily and returns a nil
// item for an absent or expired key.
func (c *Cache) Seen(id string) bool {
	return c.cache.Get(id) != nil
}

// Mark records id as seen, starting (or, for an id seen again, refreshing) its
// TTL window. ttlcache.DefaultTTL selects the per-cache TTL configured in New.
func (c *Cache) Mark(id string) {
	c.cache.Set(id, struct{}{}, ttlcache.DefaultTTL)
}

// Close stops the cache's background eviction goroutine and releases its
// resources.
func (c *Cache) Close() {
	c.cache.Stop()
}
