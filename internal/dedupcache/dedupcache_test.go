package dedupcache

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestSeenAfterMark is a characterization test for the core deduplication
// contract the replication daemon relies on: an identifier is reported as seen
// only after it has been marked, and distinct identifiers are independent.
//
// It asserts only the Seen/Mark behavior and never references the underlying
// TTL-cache library, so it remains valid across a swap of that library.
func TestSeenAfterMark(t *testing.T) {
	c := New(time.Minute)
	defer c.Close()

	require.False(t, c.Seen("a"), "an unmarked id must not be reported as seen")

	c.Mark("a")
	require.True(t, c.Seen("a"), "a marked id must be reported as seen")
	require.False(t, c.Seen("b"), "a different, unmarked id must not be reported as seen")
}

// TestEntryExpires verifies the TTL property: an entry stops being reported as
// seen once its TTL has elapsed. A single check is performed after sleeping
// safely past the TTL (no intermediate Seen calls, which could refresh the
// entry), keeping the test deterministic.
func TestEntryExpires(t *testing.T) {
	const ttl = 50 * time.Millisecond

	c := New(ttl)
	defer c.Close()

	c.Mark("a")
	require.True(t, c.Seen("a"), "id must be seen immediately after marking")

	time.Sleep(5 * ttl)
	require.False(t, c.Seen("a"), "id must no longer be seen once its TTL has elapsed")
}
