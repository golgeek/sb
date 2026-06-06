package cmd

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/golgeek/sb/internal/commands"
	"github.com/golgeek/sb/internal/helpers"
	"github.com/golgeek/sb/internal/models"
	"github.com/mholt/archiver/v4"
	"github.com/pkg/errors"
)

type Restore struct{}

func init() {
	commands.RegisterCommand("restore", func() (c commands.Command, r models.Right, helper helpers.Helper, args map[string]commands.Argument) {
		return new(Restore), models.Private, helpers.Helper{
				Header:      "restores a backup archive of this sb instance",
				Usage:       "restore",
				Description: "restores a backup archive of this sb instance",
			}, map[string]commands.Argument{
				"file": {
					Required:    true,
					Description: "The filepath of the binary file to restore",
				},
				"decryption-key": {
					Required:    true,
					Description: "Key to use to decrypt the binary backup file",
				},
			}
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

func (c *Restore) Execute(ct *commands.Context) (repl models.ReplicationData, cmdError error, err error) {

	binFilepath := ct.FormattedArguments["file"]
	tgzFilepath := strings.Replace(ct.FormattedArguments["file"], ".bin", ".tar.gz", 1)

	err = helpers.DecryptFile(binFilepath, tgzFilepath, ct.FormattedArguments["decryption-key"])
	if err != nil {
		err = errors.Wrap(err, "unable to decrypt the backup file")
		return
	}

	f, err := os.Open(tgzFilepath)
	if err != nil {
		err = errors.Wrap(err, "unable to open decrypted backup file")
		return
	}

	format := archiver.CompressedArchive{
		Compression: archiver.Gz{},
		Archival:    archiver.Tar{},
	}

	handler := func(ctx context.Context, f archiver.File) error {

		stat := f.Sys().(*tar.Header)

		if f.IsDir() {
			err = os.MkdirAll(f.NameInArchive, f.Mode().Perm())
			if err != nil {
				return errors.Wrap(err, "unable to create directory")
			}

			err = os.Chown(f.NameInArchive, stat.Uid, stat.Gid)
			if err != nil {
				return errors.Wrap(err, "unable to chown directory")
			}

			return nil
		}

		src, err := f.Open()
		if err != nil {
			return errors.Wrap(err, "unable to open file for read")
		}

		dst, err := os.OpenFile(f.NameInArchive, os.O_RDWR|os.O_CREATE, f.Mode().Perm())
		if err != nil {
			return errors.Wrap(err, "unable to open file for write")
		}
		defer dst.Close()

		_, err = io.Copy(dst, src)
		if err != nil {
			return errors.Wrap(err, "unable to write file content")
		}

		err = os.Chown(f.NameInArchive, stat.Uid, stat.Gid)
		if err != nil {
			return errors.Wrap(err, "unable to chown file")
		}

		return nil
	}

	err = format.Extract(context.Background(), f, nil, handler)
	if err != nil {
		err = errors.Wrap(err, "unable to restore backup file")
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
