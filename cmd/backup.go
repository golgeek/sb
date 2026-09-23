package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/golgeek/sb/internal/commands"
	"github.com/golgeek/sb/internal/config"
	"github.com/golgeek/sb/internal/helpers"
	"github.com/golgeek/sb/internal/models"
)

type Backup struct{}

func init() {
	commands.Register(commands.CommandSpec{
		Name:   "backup",
		Rights: models.Private,
		Help: helpers.Helper{
			Header:      "creates a backup archive of this sb instance",
			Usage:       "backup",
			Description: "creates a backup file of this sb instance",
		},
		Args: map[string]commands.Argument{
			"backup-directory": {
				Required:    true,
				Description: "The directory where to output the backup file",
			},
		},
		New: func() commands.Command { return new(Backup) },
	})
}

func (c *Backup) Checks(ct *commands.Context) (err error) {

	info, err := os.Stat(ct.FormattedArguments["backup-directory"])
	if err != nil {
		return fmt.Errorf("unable to access backup-directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("backup-directory must be a directory")
	}

	return validateBackupKey(config.GetEncryptionKey())
}

func (c *Backup) Execute(ct *commands.Context) (res commands.Result, err error) {

	if err = c.Checks(ct); err != nil {
		return
	}

	hostname, err := helpers.GetHostname()
	if err != nil {
		err = fmt.Errorf("unable to get hostname from host: %w", err)
		return
	}

	users, err := models.GetAllSBUsers()
	if err != nil {
		err = fmt.Errorf("unable to list all sb users: %w", err)
		return
	}

	groups, err := models.GetAllSBGroups()
	if err != nil {
		err = fmt.Errorf("unable to list all sb groups: %w", err)
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

	err = createEncryptedBackup(filename+".bin", config.GetEncryptionKey(), pathsToArchive)
	if err != nil {
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
