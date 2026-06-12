package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/golgeek/sb/internal/archive"
	"github.com/golgeek/sb/internal/commands"
	"github.com/golgeek/sb/internal/helpers"
	"github.com/golgeek/sb/internal/models"
)

type Restore struct{}

func init() {
	commands.Register(commands.CommandSpec{
		Name:   "restore",
		Rights: models.Private,
		Help: helpers.Helper{
			Header:      "restores a backup archive of this sb instance",
			Usage:       "restore",
			Description: "restores a backup archive of this sb instance",
		},
		Args: map[string]commands.Argument{
			"file": {
				Required:    true,
				Description: "The filepath of the binary file to restore",
			},
			"decryption-key": {
				Required:    true,
				Description: "Key to use to decrypt the binary backup file",
			},
		},
		New: func() commands.Command { return new(Restore) },
	})
}

func (c *Restore) Checks(ct *commands.Context) (err error) {

	if !strings.HasSuffix(ct.FormattedArguments["file"], ".bin") {
		return fmt.Errorf("only .bin file format is supported")
	}

	_, err = os.Stat(ct.FormattedArguments["file"])
	if err != nil {
		return fmt.Errorf("unable to find file %s on disk", ct.FormattedArguments["file"])
	}

	return
}

func (c *Restore) Execute(ct *commands.Context) (res commands.Result, err error) {

	binFilepath := ct.FormattedArguments["file"]
	tgzFilepath := strings.Replace(ct.FormattedArguments["file"], ".bin", ".tar.gz", 1)

	err = helpers.DecryptFile(binFilepath, tgzFilepath, ct.FormattedArguments["decryption-key"])
	if err != nil {
		err = fmt.Errorf("unable to decrypt the backup file: %w", err)
		return
	}

	f, err := os.Open(tgzFilepath)
	if err != nil {
		err = fmt.Errorf("unable to open decrypted backup file: %w", err)
		return
	}

	// Re-materialize every entry from the archive. The handler speaks only in
	// terms of sb's ArchivedFile type, so this restore logic is independent of
	// the underlying archiving library.
	handler := func(af archive.ArchivedFile) error {

		if af.IsDir {
			err = os.MkdirAll(af.NameInArchive, af.Mode.Perm())
			if err != nil {
				return fmt.Errorf("unable to create directory: %w", err)
			}

			err = os.Chown(af.NameInArchive, af.UID, af.GID)
			if err != nil {
				return fmt.Errorf("unable to chown directory: %w", err)
			}

			return nil
		}

		src, err := af.Open()
		if err != nil {
			return fmt.Errorf("unable to open file for read: %w", err)
		}
		defer src.Close()

		dst, err := os.OpenFile(af.NameInArchive, os.O_RDWR|os.O_CREATE, af.Mode.Perm())
		if err != nil {
			return fmt.Errorf("unable to open file for write: %w", err)
		}
		defer dst.Close()

		_, err = io.Copy(dst, src)
		if err != nil {
			return fmt.Errorf("unable to write file content: %w", err)
		}

		err = os.Chown(af.NameInArchive, af.UID, af.GID)
		if err != nil {
			return fmt.Errorf("unable to chown file: %w", err)
		}

		return nil
	}

	err = archive.ExtractArchive(context.Background(), f, handler)
	if err != nil {
		err = fmt.Errorf("unable to restore backup file: %w", err)
		return
	}

	fmt.Printf("Backup successfully restored\n")

	return
}

func (c *Restore) PostExecute(repl models.ReplicationData) (err error) {
	return
}

func (c *Restore) Replicate(repl models.ReplicationData) (err error) {
	return
}
