package cmd

import (
	"fmt"
	"os/exec"

	"github.com/golgeek/sb/internal/commands"
	"github.com/golgeek/sb/internal/helpers"
	"github.com/golgeek/sb/internal/models"

	"github.com/fatih/color"
)

// SelfDisableTOTP describes the selfDisableTOTP command
type SelfDisableTOTP struct{}

func init() {
	commands.RegisterCommand("self totp disable", func() (c commands.Command, r models.Right, helper helpers.Helper, args map[string]commands.Argument) {
		return new(SelfDisableTOTP), models.Public, helpers.Helper{
			Header:      "disable TOTP on the account",
			Usage:       "self totp disable",
			Description: "disable TOTP on the account",
			Aliases:     []string{"selfDisableTOTP"},
		}, map[string]commands.Argument{}
	})
}

// Checks checks whether or not the user can execute this method
func (c *SelfDisableTOTP) Checks(ct *commands.Context) error {
	// We're building on top of pam_google_authenticator, let's check the server is setup correctly
	_, err := exec.LookPath("google-authenticator")
	if err != nil {
		return fmt.Errorf("the server is not configured for TOTP")
	}
	return nil
}

// Execute executes the command
func (c *SelfDisableTOTP) Execute(ct *commands.Context) (repl models.ReplicationData, cmdError error, err error) {

	repl = models.ReplicationData{
		"account": ct.User.User.Username,
	}

	err = c.Replicate(repl)

	return
}

func (c *SelfDisableTOTP) PostExecute(repl models.ReplicationData) (err error) {
	return
}

func (c *SelfDisableTOTP) Replicate(repl models.ReplicationData) (err error) {

	user, err := models.LoadUser(repl["account"])
	if err != nil {
		return
	}

	err = user.RemoveTOTPSecret()
	if err != nil {
		return
	}

	green := color.New(color.FgGreen).SprintFunc()
	fmt.Printf("%s\n", green("TOTP was successfully deactivated on your account!"))

	return
}
