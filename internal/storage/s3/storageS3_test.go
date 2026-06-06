package s3

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

// fakeS3 is a minimal in-process stand-in for the subset of the S3 HTTP API the
// storage backend exercises: a path-style PUT that stores an object and a GET
// (optionally ranged, as the SDK's download manager issues) that returns it. It
// is deliberately library-agnostic so the same fake validates the storage
// backend both before and after the aws-sdk-go-v2 migration.
type fakeS3 struct {
	mu      sync.Mutex
	objects map[string][]byte
}

func newFakeS3() *fakeS3 {
	return &fakeS3{objects: map[string][]byte{}}
}

// get returns the stored bytes for a path (e.g. "/bucket/base/key").
func (f *fakeS3) get(path string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.objects[path]
	return b, ok
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPut:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "unable to read body", http.StatusInternalServerError)
			return
		}

		f.mu.Lock()
		f.objects[r.URL.Path] = body
		f.mu.Unlock()

		w.Header().Set("ETag", `"fake-etag"`)
		w.WriteHeader(http.StatusOK)

	case http.MethodGet:
		body, ok := f.get(r.URL.Path)
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		total := len(body)

		// Honor a single-range request the way real S3 does, since the SDK's
		// download manager fetches objects with a Range header.
		if rangeHeader := r.Header.Get("Range"); rangeHeader != "" {
			start, end := parseByteRange(rangeHeader, total)
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, total))
			w.Header().Set("Content-Length", strconv.Itoa(end-start+1))
			w.Header().Set("Accept-Ranges", "bytes")
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(body[start : end+1])
			return
		}

		w.Header().Set("Content-Length", strconv.Itoa(total))
		w.Header().Set("Accept-Ranges", "bytes")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)

	default:
		http.Error(w, "unexpected method", http.StatusMethodNotAllowed)
	}
}

// parseByteRange parses a single "bytes=start-end" (end optional) header against
// an object of the given total size, returning inclusive start/end indices.
func parseByteRange(header string, total int) (start, end int) {
	spec := strings.TrimPrefix(header, "bytes=")
	parts := strings.SplitN(spec, "-", 2)

	start, _ = strconv.Atoi(parts[0])
	end = total - 1
	if len(parts) == 2 && parts[1] != "" {
		if e, err := strconv.Atoi(parts[1]); err == nil && e < end {
			end = e
		}
	}
	if end > total-1 {
		end = total - 1
	}
	return start, end
}

// newTestStorage wires a StorageS3 to point at the given fake-S3 server using
// path-style addressing and dummy static credentials.
func newTestStorage(t *testing.T, endpoint string) *StorageS3 {
	t.Helper()

	v := viper.New()
	v.Set("bucket", "test-bucket")
	v.Set("region", "us-east-1")
	v.Set("keys-base-path", "base")
	v.Set("emulator-host", endpoint)
	v.Set("aws-access-key", "test")
	v.Set("aws-secret-key", "test")

	rs, err := NewStorageS3(v)
	require.NoError(t, err)
	return rs
}

// TestStorageS3RoundTrip is a characterization test for the S3 storage backend:
// a file pushed under a key can be fetched back byte-for-byte, and it is stored
// under the expected bucket/base-path/key location. It speaks only to the
// storage backend's own API and a generic S3 HTTP fake, so it stays valid across
// the aws-sdk-go-v2 migration.
func TestStorageS3RoundTrip(t *testing.T) {
	fake := newFakeS3()
	srv := httptest.NewServer(fake)
	defer srv.Close()

	rs := newTestStorage(t, srv.URL)

	// Push a file under "mykey".
	srcDir := t.TempDir()
	srcPath := filepath.Join(srcDir, "input.bin")
	want := []byte("the quick brown fox jumps over the lazy dog")
	require.NoError(t, os.WriteFile(srcPath, want, 0o600))

	require.NoError(t, rs.PushToStorage("mykey", srcPath))

	// It must be stored at /<bucket>/<base-path>/<key>.
	stored, ok := fake.get("/test-bucket/base/mykey")
	require.True(t, ok, "object should be stored under bucket/base-path/key")
	require.Equal(t, want, stored)

	// Fetch it back into a new file and confirm the content survives the round
	// trip.
	dstPath := filepath.Join(t.TempDir(), "output.bin")
	require.NoError(t, rs.GetFromStorage("mykey", dstPath))

	got, err := os.ReadFile(dstPath)
	require.NoError(t, err)
	require.Equal(t, want, got)
}

// TestStorageS3GetMissing verifies that fetching an absent key surfaces an
// error rather than silently producing an empty file.
func TestStorageS3GetMissing(t *testing.T) {
	fake := newFakeS3()
	srv := httptest.NewServer(fake)
	defer srv.Close()

	rs := newTestStorage(t, srv.URL)

	dstPath := filepath.Join(t.TempDir(), "missing.bin")
	require.Error(t, rs.GetFromStorage("does-not-exist", dstPath))
}
