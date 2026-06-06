package cmd

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/golgeek/sb/internal/commands"
	"github.com/golgeek/sb/internal/helpers"
	"github.com/golgeek/sb/internal/models"
)

// SelfGenerateTOTPCodes describes the SelfGenerateTOTPCodes command
type SelfGenerateTOTPCodes struct{}

func init() {
	commands.RegisterCommand("self totp emergency-codes generate", func() (c commands.Command, r models.Right, helper helpers.Helper, args map[string]commands.Argument) {
		return new(SelfGenerateTOTPCodes), models.Public, helpers.Helper{
			Header:      "generate TOTP emergency codes",
			Usage:       "self totp emergency-codes generate",
			Description: "generate TOTP emergency codes",
			Aliases:     []string{"selfGenerateTOTPCodes"},
		}, map[string]commands.Argument{}
	})
}

// Checks checks whether or not the user can execute this method
func (c *SelfGenerateTOTPCodes) Checks(ct *commands.Context) error {

	// We're building on top of pam_google_authenticator, let's check the server is setup correctly
	_, err := exec.LookPath("google-authenticator")
	if err != nil {
		return fmt.Errorf("the server is not configured for TOTP")
	}

	// Check that TOTP is enabled for current account
	enabled, _, _ := ct.User.GetTOTP()
	if !enabled {
		return fmt.Errorf("TOTP is disabled on this account")
	}

	return nil
}

// Execute executes the command
func (c *SelfGenerateTOTPCodes) Execute(ct *commands.Context) (repl models.ReplicationData, cmdError error, err error) {

	_, currentSecret, _ := ct.User.GetTOTP()

	random := helpers.GetRandomStrings(5, 8)

	repl = models.ReplicationData{
		"account":      ct.User.User.Username,
		"secret":       currentSecret,
		"random-codes": strings.Join(random, ";"),
	}

	err = c.Replicate(repl)
	if err != nil {
		return
	}

	fmt.Printf("Here are your %d emergency codes:\n", len(random))
	for _, str := range random {
		fmt.Printf("%s", str)
	}
	fmt.Printf("Be sure to store them in a secure place, they will never be displayed again\n")

	return
}

func (c *SelfGenerateTOTPCodes) PostExecute(repl models.ReplicationData) (err error) {
	return
}

func (c *SelfGenerateTOTPCodes) Replicate(repl models.ReplicationData) (err error) {

	user, err := models.LoadUser(repl["account"])
	if err != nil {
		return
	}

	// Store the secrets (and thus, enable the TOTP on the account)
	err = user.SetTOTPSecret(repl["secret"], strings.Split(repl["random-codes"], ";"))
	if err != nil {
		return
	}

	return
}
