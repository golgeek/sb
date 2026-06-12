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
	commands.Register(commands.CommandSpec{
		Name:    "self totp disable",
		Aliases: []string{"selfDisableTOTP"},
		Rights:  models.Public,
		Help: helpers.Helper{
			Header:      "disable TOTP on the account",
			Usage:       "self totp disable",
			Description: "disable TOTP on the account",
		},
		Args: map[string]commands.Argument{},
		New:  func() commands.Command { return new(SelfDisableTOTP) },
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
func (c *SelfDisableTOTP) Execute(ct *commands.Context) (res commands.Result, err error) {

	res.Repl = models.ReplicationData{
		"account": ct.User.User.Username,
	}

	err = c.Replicate(res.Repl)

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
