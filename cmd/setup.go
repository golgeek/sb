package cmd

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"time"

	"github.com/golgeek/sb/internal/commands"
	"github.com/golgeek/sb/internal/config"
	"github.com/golgeek/sb/internal/helpers"
	"github.com/golgeek/sb/internal/models"
	"github.com/pkg/errors"
)

// Setup describes the help command
type Setup struct{}

var (
	DefaultSSHDConfigFile     = "/etc/ssh/sshd_config"
	DefaultPAMConfigFile      = "/etc/pam.d/sshd"
	DefaultSudoersdOwnersFile = "/etc/sudoers.d/bg_owners-o"
	DefaultSystemdServiceFile = "/etc/systemd/system/sb.service"
)

func init() {
	commands.RegisterCommand("setup", func() (c commands.Command, r models.Right, helper helpers.Helper, args map[string]commands.Argument) {
		return new(Setup), models.Private, helpers.Helper{
			Header:      "setup sb on the host",
			Usage:       "setup'",
			Description: "setup sb on the host",
		}, map[string]commands.Argument{}
	})
}

// Checks checks whether or not the user can execute this method
func (c *Setup) Checks(ct *commands.Context) error {

	return nil
}

// Execute executes the command
func (c *Setup) Execute(ct *commands.Context) (repl models.ReplicationData, cmdError error, err error) {

	log.Printf("[SETUP     ] Gonna setup sb on this host")

	// Backup SSHD config file
	backupSSHD, err := c._backupFile(DefaultSSHDConfigFile)
	if err != nil {
		log.Printf("[SETUP     ] Fail to backup sshd config file: %s", err)
		return
	}
	log.Printf("[SETUP     ] Backuped config file %s to %s", DefaultSSHDConfigFile, backupSSHD)

	// Set SSHD options
	log.Printf("[SETUP     ] Set SSHD options....")
	err = c._SetSSHDOptions()
	if err != nil {
		log.Printf("[SETUP     ] Fail to set sshd options: %s", err)
		return
	}

	// Remove password auth in PAM
	_, err = exec.LookPath("google-authenticator")
	if err == nil {

		// Backup PAM sshd file
		backupPAM, errBackup := c._backupFile(DefaultPAMConfigFile)
		if errBackup != nil {
			log.Printf("[SETUP     ] Fail to backup pamd sshd config file: %s", errBackup)
			return
		}
		log.Printf("[SETUP     ] Backuped config file %s to %s", DefaultPAMConfigFile, backupPAM)

		err = exec.Command("sed", "-i", "s/^\\@include common-auth/#@include common-auth/g", DefaultPAMConfigFile).Run()
		if err != nil {
			log.Printf("[SETUP     ] Fail to remove password auth in PAM: %s", err)
			return
		}
		log.Printf("[SETUP     ] Removed @include common-auth line from pamd sshd config file")

		// Add required PAM modules
		err = c._appendLineIfNotPresentAlready(DefaultPAMConfigFile, "auth required pam_google_authenticator.so nullok")
		if err != nil {
			log.Printf("[SETUP     ] Fail to add pam_google_authenticator module to PAM: %s", err)
			return
		}
		log.Printf("[SETUP     ] Added pam_google_authenticator module to PAM")

		err = c._appendLineIfNotPresentAlready(DefaultPAMConfigFile, "auth required pam_permit.so")
		if err != nil {
			log.Printf("[SETUP     ] Fail to add pam_permit module to PAM: %s", err)
			return
		}
		log.Printf("[SETUP     ] Added pam_permit module to PAM")

	}

	// Restart SSH
	log.Printf("[SETUP     ] Restarting SSHD service...")
	err = exec.Command("service", "ssh", "restart").Run()
	if err != nil {
		log.Printf("[SETUP     ] Fail to restart sshd: %s", err)
		return
	}

	// System stuff
	log.Printf("[SETUP     ] Creating sb user")
	err = c._createSBUser()
	if err != nil {
		log.Printf("[SETUP     ] Failed to create sb user: %s", err)
		return
	}

	// Create the sudoers.d file for the owners group
	err = c._createSudoersFileForOwners()
	if err != nil {
		log.Printf("[SETUP     ] Failed to create the sudoers file for the owners' group: %s", err)
		return
	}

	err = c._createSystemdServiceFile()
	if err != nil {
		log.Printf("[SETUP     ] Failed to create systemd service file: %s", err)
	}

	log.Printf("[SETUP     ] Done!")
	return
}

func (c *Setup) PostExecute(repl models.ReplicationData) (err error) {
	return
}

func (c *Setup) Replicate(repl models.ReplicationData) (err error) {
	return
}

func (c *Setup) _backupFile(path string) (backup string, err error) {

	// Get date
	now := time.Now().Format("20060102-150405")
	backup = fmt.Sprintf("%s.bak.%s", path, now)

	// Exec command
	err = exec.Command("cp", path, backup).Run()
	return
}

func (c *Setup) _SetSSHDOptions() (err error) {

	p, err := helpers.ParseSSHDConfigFile(DefaultSSHDConfigFile)
	if err != nil {
		return
	}

	log.Printf("[SETUP     ]   -> Switch %-32s to yes", "ChallengeResponseAuthentication")
	p.SetParam("ChallengeResponseAuthentication", "yes")

	log.Printf("[SETUP     ]   -> Switch %-32s to yes", "KbdInteractiveAuthentication")
	p.SetParam("KbdInteractiveAuthentication", "yes")

	log.Printf("[SETUP     ]   -> Switch %-32s to yes", "PasswordAuthentication")
	p.SetParam("PasswordAuthentication", "no")

	log.Printf("[SETUP     ]   -> Switch %-32s to yes", "PermitRootLogin")
	p.SetParam("PermitRootLogin", "yes")

	log.Printf("[SETUP     ]   -> Switch %-32s to publickey,keyboard-interactive", "AuthenticationMethods")
	p.SetParam("AuthenticationMethods", "publickey,keyboard-interactive")

	return p.WriteToFile(DefaultSSHDConfigFile)
}

func (c *Setup) _appendLineIfNotPresentAlready(file, line string) (err error) {

	// Open file
	f, err := ioutil.ReadFile(file)
	if err != nil {
		return
	}

	// Read all lines
	lines := strings.Split(string(f), "\n")
	for _, currentFileLine := range lines {

		// Line already in file, no need to go further
		if strings.HasPrefix(currentFileLine, line) {
			return nil
		}
	}

	// Append line in file
	appendOnlyFile, err := os.OpenFile(file, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return
	}

	_, err = appendOnlyFile.WriteString(fmt.Sprintf("%s\n", line))
	return
}

func (c *Setup) _createSBUser() (err error) {

	log.Printf("[SETUP     ] Checking if user %s already exists", config.GetSBUsername())
	_, err = user.Lookup(config.GetSBUsername())
	if err != nil {
		if _, ok := err.(user.UnknownUserError); !ok {
			return
		}
	} else {
		log.Printf("[SETUP     ] SB user %s already exists, doing nothing", config.GetSBUsername())
		return
	}

	homedir := config.GetSBUserHome()

	log.Printf("[SETUP     ] Creating %s user", config.GetSBUsername())
	err = exec.Command("adduser", fmt.Sprintf("--home=%s", homedir), "--shell=/usr/sbin/nologin", "--disabled-password", "--gecos", "", config.GetSBUsername()).Run()
	if err != nil {
		return
	}

	log.Printf("[SETUP     ] Creating sb's main logs database file")
	err = exec.Command("touch", fmt.Sprintf("%s/logs.db", homedir)).Run()
	if err != nil {
		return
	}

	log.Printf("[SETUP     ] Creating sb's main replication database file")
	err = exec.Command("touch", fmt.Sprintf("%s/replication.db", homedir)).Run()
	if err != nil {
		return
	}

	log.Printf("[SETUP     ] Change ownership of %s to %s:%s", homedir, config.GetSBUsername(), config.GetSBUsername())
	err = exec.Command("chown", "-R", fmt.Sprintf("%s:%s", config.GetSBUsername(), config.GetSBUsername()), homedir).Run()
	if err != nil {
		return
	}

	log.Printf("[SETUP     ] Change %s permissions to 0770", homedir)
	err = exec.Command("chmod", "0770", homedir).Run()
	if err != nil {
		return
	}

	for _, file := range []string{"logs.db", "replication.db"} {
		log.Printf("[SETUP     ] Change %-35s permissions to 0660", fmt.Sprintf("%s/%s", homedir, file))
		err = exec.Command("chmod", "0660", fmt.Sprintf("%s/%s", homedir, file)).Run()
		if err != nil {
			return
		}
	}

	return
}

func (c *Setup) _createSudoersFileForOwners() (err error) {

	file, err := os.OpenFile(DefaultSudoersdOwnersFile, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return errors.Wrapf(err, "unable to open file %s", DefaultSudoersdOwnersFile)
	}

	_, err = file.WriteString(helpers.GetGroupSudoersTemplateOwners(config.GetBinaryPath(), config.GetSBUsername()))
	if err != nil {
		return errors.Wrapf(err, "unable to write to file %s", DefaultSudoersdOwnersFile)
	}

	return
}

func (c *Setup) _createSystemdServiceFile() (err error) {

	file, err := os.OpenFile(DefaultSystemdServiceFile, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return errors.Wrapf(err, "unable to open file %s", DefaultSystemdServiceFile)
	}

	_, err = file.WriteString(helpers.GetSystemdServiceFile(config.GetBinaryPath(), config.GetSBUserHome()))
	if err != nil {
		return errors.Wrapf(err, "unable to write file %s", DefaultSystemdServiceFile)
	}

	return
}
