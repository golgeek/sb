package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/golgeek/sb/internal/archive"
	"github.com/golgeek/sb/internal/commands"
	"github.com/golgeek/sb/internal/config"
	"github.com/golgeek/sb/internal/helpers"
	"github.com/golgeek/sb/internal/models"
	"github.com/pkg/errors"
)

type Backup struct{}

func init() {
	commands.RegisterCommand("backup", func() (c commands.Command, r models.Right, helper helpers.Helper, args map[string]commands.Argument) {
		return new(Backup), models.Private, helpers.Helper{
				Header:      "creates a backup archive of this sb instance",
				Usage:       "backup",
				Description: "creates a backup file of this sb instance",
			}, map[string]commands.Argument{
				"backup-directory": {
					Required:    true,
					Description: "The directory where to output the backup file",
				},
			}
	})
}

func (c *Backup) Checks(ct *commands.Context) (err error) {

	if _, errStat := os.Stat(ct.FormattedArguments["backup-directory"]); err != nil && os.IsNotExist(err) {
		return errors.Wrap(errStat, "backup-directory does not exist")
	}

	return
}

func (c *Backup) Execute(ct *commands.Context) (repl models.ReplicationData, cmdError error, err error) {

	hostname, err := helpers.GetHostname()
	if err != nil {
		err = errors.Wrap(err, "unable to get hostname from host")
		return
	}

	users, err := models.GetAllSBUsers()
	if err != nil {
		err = errors.Wrap(err, "unable to list all sb users")
		return
	}

	groups, err := models.GetAllSBGroups()
	if err != nil {
		err = errors.Wrap(err, "unable to list all sb groups")
		return
	}

	// Build the filename (without extension)
	filename := fmt.Sprintf("%s/sb-backup_%s_%s_%s", ct.FormattedArguments["backup-directory"], config.GetSBName(), hostname, time.Now().Format("20060102T150405Z0700"))

	// List all the files to backup
	pathsToArchive := map[string]string{
		"/etc/shadow":                  "/etc/shadow",
		"/etc/group":                   "/etc/group",
		"/etc/passwd":                  "/etc/passwd",
		"/etc/sudoers.d":               "/etc/sudoers.d",
		config.GetGlobalDatabasePath(): config.GetGlobalDatabasePath(),
	}

	for _, user := range users {
		rootPath := fmt.Sprintf("/home/%s", user)
		pathsToArchive[rootPath] = rootPath
	}

	for _, group := range groups {
		rootPath := fmt.Sprintf("/home/%s", group.SystemName)
		pathsToArchive[rootPath] = rootPath

	}

	err = c.createArchive(fmt.Sprintf("%s.tar.gz", filename), pathsToArchive)
	if err != nil {
		return
	}

	// Encrypting it
	err = helpers.EncryptFile(fmt.Sprintf("%s.tar.gz", filename), fmt.Sprintf("%s.bin", filename), config.GetEncryptionKey())
	if err != nil {
		err = errors.Wrap(err, "unable to encrypt the backup file")
		return
	}

	// Deleting the temporary un-encrypted backup file
	err = os.Remove(fmt.Sprintf("%s.tar.gz", filename))
	if err != nil {
		err = errors.Wrap(err, "unable to remove the temporary un-encrypted backup file")
		return
	}

	// Printing the new backup location
	fmt.Printf("New backup available: %s.bin\n", filename)

	return
}

func (c *Backup) PostExecute(repl models.ReplicationData) (err error) {
	return
}

func (c *Backup) Replicate(repl models.ReplicationData) (err error) {
	return
}

func (c *Backup) createArchive(filename string, pathsToArchive map[string]string) error {

	// Create the backup file
	out, err := os.Create(filename)
	if err != nil {
		return errors.Wrap(err, "unable to create backup file on disk")
	}
	defer out.Close()

	// Delegate the actual gzip-tar archiving to the archive seam, which keeps
	// this command independent of the underlying archiving library.
	err = archive.CreateArchive(context.Background(), out, pathsToArchive)
	if err != nil {
		return errors.Wrap(err, "unable to create archive file")
	}

	return nil
}
