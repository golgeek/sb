package cmd

import (
	"bytes"
	"io"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestLockedWriterSerializesConcurrentWrites verifies that lockedWriter makes
// concurrent writes to a shared, non-thread-safe writer safe: the stdout and
// stderr copiers in Ttyrec.Execute both record into one ttyrec.Encoder through
// a lockedWriter, so every byte written by every goroutine must reach the
// underlying writer exactly once with no interleaving within a single Write.
// Run under `go test -race` this also asserts there is no data race on the
// shared writer.
func TestLockedWriterSerializesConcurrentWrites(t *testing.T) {
	var underlying bytes.Buffer
	lw := &lockedWriter{w: &underlying}

	const writers = 8
	const writesPerWriter = 200
	// Each writer emits a distinct, fixed-size frame so we can both count total
	// bytes and confirm no frame was split by an interleaving write.
	frame := []byte("0123456789ABCDEF")

	var wg sync.WaitGroup
	wg.Add(writers)
	for range writers {
		go func() {
			defer wg.Done()
			for range writesPerWriter {
				n, err := lw.Write(frame)
				require.NoError(t, err)
				require.Equal(t, len(frame), n)
			}
		}()
	}
	wg.Wait()

	got := underlying.Bytes()
	require.Len(t, got, writers*writesPerWriter*len(frame))

	// Because each Write is atomic under the lock, the output must be an exact
	// concatenation of whole frames — every aligned slice equals the frame.
	for off := 0; off < len(got); off += len(frame) {
		require.True(t, bytes.Equal(got[off:off+len(frame)], frame),
			"frame at offset %d was corrupted by an interleaved write", off)
	}
}

// TestLockedWriterPropagatesError confirms lockedWriter returns the underlying
// writer's error unchanged, so a recording failure is surfaced rather than
// swallowed.
func TestLockedWriterPropagatesError(t *testing.T) {
	lw := &lockedWriter{w: errWriter{}}
	_, err := lw.Write([]byte("x"))
	require.ErrorIs(t, err, errWrite)
}

// errWriter is an io.Writer that always fails, used to check error propagation.
type errWriter struct{}

var errWrite = io.ErrShortWrite

func (errWriter) Write([]byte) (int, error) { return 0, errWrite }
