// Package archive provides a small, library-agnostic seam over the third-party
// archiving library sb uses for instance backups. The rest of the codebase
// (the backup/restore commands) depends only on the types and functions
// declared here, never on the underlying archiver package directly.
//
// The point of this indirection is twofold:
//
//  1. Testability — the round-trip behavior (archive a set of files, then
//     extract them and get the same content/structure back) can be exercised in
//     a hermetic unit test that knows nothing about the archiving library.
//  2. Swappability — the underlying library can be replaced without touching any
//     caller, because callers only speak in terms of sb's own ArchivedFile type.
//
// The on-the-wire format is a gzip-compressed tar (".tar.gz"), matching what the
// backup command has always produced.
package archive

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"io/fs"

	"github.com/mholt/archives"
)

// ArchivedFile is a library-agnostic view of a single entry encountered while
// extracting an archive. It intentionally exposes only the fields the restore
// path needs, so callers do not depend on the underlying archiving library's
// file type.
type ArchivedFile struct {
	// NameInArchive is the path of the entry as it was stored in the archive.
	NameInArchive string
	// Mode holds the file mode and permission bits recorded for the entry.
	Mode fs.FileMode
	// IsDir reports whether the entry is a directory.
	IsDir bool
	// UID and GID are the owning user and group ids recorded in the archive.
	// They default to 0 when the archive format does not carry ownership data.
	UID int
	GID int
	// Open returns a reader over the entry's content. It is nil for directories
	// and must be closed by the caller once it is done reading.
	Open func() (io.ReadCloser, error)
}

// compressedTarGz returns the gzip-compressed tar format descriptor used for
// every sb backup, both when writing and when reading. CompressedArchive layers
// a gzip Compression over a tar Archival/Extraction; both the Archival and
// Extraction fields are set so the same descriptor can create and read archives.
func compressedTarGz() archives.CompressedArchive {
	return archives.CompressedArchive{
		Compression: archives.Gz{},
		Archival:    archives.Tar{},
		Extraction:  archives.Tar{},
	}
}

// CreateArchive writes a gzip-compressed tar archive of the requested files to
// dst.
//
// diskToArchiveName maps each source path on disk to the name the corresponding
// entry should have inside the archive. Directories are added recursively, with
// their children named relative to the mapped name. The caller owns dst and is
// responsible for closing it; CreateArchive only writes to it.
//
// It returns an error if the source files cannot be enumerated or if writing the
// archive fails.
func CreateArchive(ctx context.Context, dst io.Writer, diskToArchiveName map[string]string) error {
	// Enumerate the on-disk files into the archiver's file list, preserving the
	// caller-provided disk-path -> archive-name mapping.
	files, err := archives.FilesFromDisk(ctx, &archives.FromDiskOptions{}, diskToArchiveName)
	if err != nil {
		return fmt.Errorf("unable to prepare files to archive: %w", err)
	}

	if err := compressedTarGz().Archive(ctx, dst, files); err != nil {
		return fmt.Errorf("unable to create archive: %w", err)
	}

	return nil
}

// ExtractArchive reads a gzip-compressed tar archive from src and invokes
// handler once for every entry it contains, in archive order. Each entry is
// presented as an sb-owned ArchivedFile so the handler never sees the underlying
// archiving library's types.
//
// The handler is responsible for materializing the entry (creating directories,
// writing file content via ArchivedFile.Open, applying ownership, etc.). If the
// handler returns an error, extraction stops and that error is propagated.
func ExtractArchive(ctx context.Context, src io.Reader, handler func(ArchivedFile) error) error {
	// Translate each underlying archiver.File into sb's ArchivedFile before
	// handing it to the caller. This translation layer is the only place that is
	// coupled to the archiving library, which is what makes the library
	// swappable without touching callers or their tests.
	err := compressedTarGz().Extract(ctx, src, func(_ context.Context, info archives.FileInfo) error {
		af := ArchivedFile{
			NameInArchive: info.NameInArchive,
			Mode:          info.Mode(),
			IsDir:         info.IsDir(),
			// archives' Open yields an fs.File, which satisfies io.ReadCloser
			// (it has Read and Close); wrap it so ArchivedFile stays decoupled
			// from the archiving library's return type.
			Open: func() (io.ReadCloser, error) {
				return info.Open()
			},
		}

		// tar entries carry numeric ownership in their header; surface it so the
		// restore path can re-apply the original uid/gid. Other underlying
		// formats may not, in which case the ids stay at their zero value.
		if hdr, ok := info.Header.(*tar.Header); ok {
			af.UID = hdr.Uid
			af.GID = hdr.Gid
		}

		return handler(af)
	})
	if err != nil {
		return fmt.Errorf("unable to extract archive: %w", err)
	}

	return nil
}
