package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/golgeek/sb/internal/archive"
	"github.com/golgeek/sb/internal/config"
	"github.com/golgeek/sb/internal/helpers"
)

func validateBackupKey(key string) error {
	if key == "" || key == config.DefaultEncryptionKey {
		return fmt.Errorf("backup requires a non-default general.encryption-key")
	}
	if !config.EncryptionKeyHasValidLength(key) {
		return fmt.Errorf("general.encryption-key must contain 16, 24, or 32 bytes")
	}
	return nil
}

// Private staging also protects against predictable-name/symlink attacks. Keep
// backup staging on the destination filesystem so publication can use Link:
// it exposes only complete ciphertext and never replaces an existing file.
func withPrivateBackupDirectory(parent string, run func(string) error) (err error) {
	dir, err := os.MkdirTemp(parent, ".sb-backup-")
	if err != nil {
		return fmt.Errorf("unable to create private backup directory: %w", err)
	}
	defer func() {
		if cleanupErr := os.RemoveAll(dir); cleanupErr != nil {
			err = errors.Join(err, fmt.Errorf("unable to remove private backup directory: %w", cleanupErr))
		}
	}()
	return run(dir)
}

func createEncryptedBackup(destination, key string, paths map[string]string) error {
	if err := validateBackupKey(key); err != nil {
		return err
	}
	return withPrivateBackupDirectory(filepath.Dir(destination), func(dir string) error {
		plain := filepath.Join(dir, "backup.tar.gz")
		out, err := os.OpenFile(plain, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		archiveErr := archive.CreateArchive(context.Background(), out, paths)
		if err = errors.Join(archiveErr, out.Close()); err != nil {
			return fmt.Errorf("unable to create backup archive: %w", err)
		}
		encrypted := filepath.Join(dir, "backup.bin")
		if err = helpers.EncryptFile(plain, encrypted, key); err != nil {
			return fmt.Errorf("unable to encrypt backup: %w", err)
		}
		if err = os.Link(encrypted, destination); err != nil {
			return fmt.Errorf("unable to publish backup without overwriting existing files: %w", err)
		}
		return nil
	})
}

// Restore remains compatible with historical keys and formats. Only creation
// rejects insecure keys; rejecting them here would strand existing backups.
func withDecryptedBackup(filename, key string, read func(io.Reader) error) error {
	return withPrivateBackupDirectory("", func(dir string) (err error) {
		plain := filepath.Join(dir, "backup.tar.gz")
		if err = helpers.DecryptFile(filename, plain, key); err != nil {
			return fmt.Errorf("unable to decrypt backup: %w", err)
		}
		file, err := os.Open(plain)
		if err != nil {
			return err
		}
		defer func() { err = errors.Join(err, file.Close()) }()
		return read(file)
	})
}
