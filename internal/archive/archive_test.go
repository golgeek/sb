package archive

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestArchiveRoundTrip is a characterization test for the archive seam: it
// pins the observable behavior of CreateArchive + ExtractArchive — namely that
// a tree of files and directories survives a round trip with its names,
// directory structure and byte content intact.
//
// It deliberately asserts only sb-level behavior (entry names, IsDir, content)
// and never references the underlying archiving library, so it remains valid
// and green across a swap of that library.
func TestArchiveRoundTrip(t *testing.T) {
	// Build a small source tree on disk: one top-level file and one file nested
	// inside a sub-directory, so the test covers both flat files and recursive
	// directory archiving.
	srcDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "a.txt"), []byte("hello a"), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(srcDir, "sub"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "sub", "b.txt"), []byte("hello b"), 0o600))

	// Archive the tree, mapping each disk path to a stable, relative name inside
	// the archive. The "sub" directory is added by name so its children are
	// archived recursively as "sub/...".
	diskToArchiveName := map[string]string{
		filepath.Join(srcDir, "a.txt"): "a.txt",
		filepath.Join(srcDir, "sub"):   "sub",
	}

	var buf bytes.Buffer
	require.NoError(t, CreateArchive(context.Background(), &buf, diskToArchiveName))
	require.NotZero(t, buf.Len(), "archive should not be empty")

	// Extract from a fresh reader over the produced bytes, collecting what the
	// handler observes: the content of every regular file and the set of
	// directory entries, keyed by their name in the archive.
	contents := map[string]string{}
	dirs := map[string]bool{}
	handler := func(af ArchivedFile) error {
		if af.IsDir {
			dirs[af.NameInArchive] = true
			return nil
		}

		rc, err := af.Open()
		if err != nil {
			return err
		}
		defer rc.Close()

		data, err := io.ReadAll(rc)
		if err != nil {
			return err
		}
		contents[af.NameInArchive] = string(data)
		return nil
	}

	require.NoError(t, ExtractArchive(context.Background(), bytes.NewReader(buf.Bytes()), handler))

	// The regular files must come back with identical names and byte content.
	require.Equal(t, "hello a", contents["a.txt"])
	require.Equal(t, "hello b", contents["sub/b.txt"])

	// The directory entry must be reported as a directory so the restore path
	// can recreate it before its children are written.
	require.True(t, dirs["sub"], "expected the sub directory to be reported as a directory entry")
}
