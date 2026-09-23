package cmd

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/golgeek/sb/internal/archive"
	"github.com/golgeek/sb/internal/commands"
	"github.com/golgeek/sb/internal/config"
	"github.com/golgeek/sb/internal/helpers"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

const backupTestKey = "0123456789abcdef0123456789abcdef"

func TestBackupChecks(t *testing.T) {
	oldKey := config.GetEncryptionKey()
	t.Cleanup(func() { viper.Set("general.encryption-key", oldKey) })
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	require.NoError(t, os.WriteFile(file, nil, 0600))
	for _, tc := range []struct {
		name, directory, key string
		ok                   bool
	}{
		{"valid", dir, backupTestKey, true},
		{"missing directory", filepath.Join(dir, "missing"), backupTestKey, false},
		{"not directory", file, backupTestKey, false},
		{"empty key", dir, "", false},
		{"default key", dir, config.DefaultEncryptionKey, false},
		{"invalid length", dir, "short", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			viper.Set("general.encryption-key", tc.key)
			ct := &commands.Context{FormattedArguments: map[string]string{"backup-directory": tc.directory}}
			err := (&Backup{}).Checks(ct)
			if tc.ok {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				_, err = (&Backup{}).Execute(ct)
				require.Error(t, err)
			}
		})
	}
}

func TestPrivateBackupDirectoryCleanup(t *testing.T) {
	for _, fail := range []bool{false, true} {
		dir := t.TempDir()
		failure := errors.New("operation failed after writing plaintext")
		err := withPrivateBackupDirectory(dir, func(staging string) error {
			info, err := os.Stat(staging)
			require.NoError(t, err)
			require.Equal(t, os.FileMode(0700), info.Mode().Perm())
			require.NoError(t, os.WriteFile(filepath.Join(staging, "plain"), []byte("secret"), 0600))
			if fail {
				return failure
			}
			return nil
		})
		if fail {
			require.ErrorIs(t, err, failure)
		} else {
			require.NoError(t, err)
		}
		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		require.Empty(t, entries)
	}
}

func TestEncryptedBackupRoundTrip(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source")
	require.NoError(t, os.WriteFile(source, []byte("private backup contents"), 0600))
	dir := t.TempDir()
	destination := filepath.Join(dir, "backup.bin")
	require.NoError(t, createEncryptedBackup(destination, backupTestKey, map[string]string{source: "source"}))
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	info, err := os.Stat(destination)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())
	var files int
	var staging string
	require.NoError(t, withDecryptedBackup(destination, backupTestKey, func(reader io.Reader) error {
		file := reader.(*os.File)
		staging = filepath.Dir(file.Name())
		info, err := file.Stat()
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0600), info.Mode().Perm())
		return archive.ExtractArchive(context.Background(), reader, func(af archive.ArchivedFile) error {
			require.Equal(t, "source", af.NameInArchive)
			r, err := af.Open()
			require.NoError(t, err)
			defer r.Close()
			content, err := io.ReadAll(r)
			require.NoError(t, err)
			require.Equal(t, "private backup contents", string(content))
			files++
			return nil
		})
	}))
	require.Equal(t, 1, files)
	_, err = os.Stat(staging)
	require.True(t, os.IsNotExist(err))
}

func TestBackupFailurePreservesExistingFiles(t *testing.T) {
	for _, kind := range []string{"file", "symlink", "missing source", "empty key", "default key"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			destination := filepath.Join(dir, "backup.bin")
			source := filepath.Join(t.TempDir(), "source")
			require.NoError(t, os.WriteFile(source, []byte("original"), 0600))
			key := backupTestKey
			paths := map[string]string{source: "source"}
			wantEntries := 0
			switch kind {
			case "file":
				require.NoError(t, os.WriteFile(destination, []byte("existing backup"), 0600))
				wantEntries = 1
			case "symlink":
				require.NoError(t, os.Symlink(source, destination))
				wantEntries = 1
			case "missing source":
				paths = map[string]string{filepath.Join(dir, "absent"): "source"}
			case "empty key":
				key = ""
			case "default key":
				key = config.DefaultEncryptionKey
			}
			require.Error(t, createEncryptedBackup(destination, key, paths))
			entries, err := os.ReadDir(dir)
			require.NoError(t, err)
			require.Len(t, entries, wantEntries)
			content, err := os.ReadFile(source)
			require.NoError(t, err)
			require.Equal(t, "original", string(content))
			if kind == "file" {
				content, err = os.ReadFile(destination)
				require.NoError(t, err)
				require.Equal(t, "existing backup", string(content))
			}
			if kind == "symlink" {
				target, err := os.Readlink(destination)
				require.NoError(t, err)
				require.Equal(t, source, target)
			}
		})
	}
}

func TestDecryptedBackupCleanupOnFailure(t *testing.T) {
	for _, kind := range []string{"wrong key", "corrupt ciphertext", "extraction failure", "historical default key"} {
		t.Run(kind, func(t *testing.T) {
			// Isolate the process temp directory so even failures before the read
			// callback can be checked for leaked plaintext or ciphertext.
			stagingRoot := t.TempDir()
			sourceDir := t.TempDir()
			t.Setenv("TMPDIR", stagingRoot)
			plain := filepath.Join(sourceDir, "plain")
			cipher := filepath.Join(sourceDir, "backup.bin")
			adjacent := filepath.Join(sourceDir, "backup.tar.gz")
			require.NoError(t, os.WriteFile(adjacent, []byte("do not overwrite"), 0600))
			require.NoError(t, os.WriteFile(plain, []byte("private contents"), 0600))
			key := backupTestKey
			if kind == "historical default key" {
				key = config.DefaultEncryptionKey
			}
			require.NoError(t, helpers.EncryptFile(plain, cipher, key))
			if kind == "wrong key" {
				key = "different-key"
			}
			if kind == "corrupt ciphertext" {
				content, err := os.ReadFile(cipher)
				require.NoError(t, err)
				content[len(content)-1] ^= 1
				require.NoError(t, os.WriteFile(cipher, content, 0600))
			}
			failure := errors.New("extract failed")
			called := false
			err := withDecryptedBackup(cipher, key, func(reader io.Reader) error {
				called = true
				content, err := io.ReadAll(reader)
				require.NoError(t, err)
				require.Equal(t, "private contents", string(content))
				if kind == "extraction failure" {
					return failure
				}
				return nil
			})
			if kind == "historical default key" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			if kind == "extraction failure" {
				require.ErrorIs(t, err, failure)
			}
			require.Equal(t, kind == "extraction failure" || kind == "historical default key", called)
			entries, err := os.ReadDir(stagingRoot)
			require.NoError(t, err)
			require.Empty(t, entries)
			content, err := os.ReadFile(adjacent)
			require.NoError(t, err)
			require.Equal(t, "do not overwrite", string(content))
		})
	}
}
