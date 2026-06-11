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
	commands.Register(commands.CommandSpec{
		Name:    "self totp emergency-codes generate",
		Aliases: []string{"selfGenerateTOTPCodes"},
		Rights:  models.Public,
		Help: helpers.Helper{
			Header:      "generate TOTP emergency codes",
			Usage:       "self totp emergency-codes generate",
			Description: "generate TOTP emergency codes",
		},
		Args: map[string]commands.Argument{},
		New:  func() commands.Command { return new(SelfGenerateTOTPCodes) },
	})
}

// Checks checks whether or not the user can execute this method
func (c *SelfGenerateTOTPCodes) Checks(ct *commands.Context) error {

	// We're building on top of pam_google_authenticator, let's check the server is setup correctly
	_, err := exec.LookPath("google-authenticator")
	if err != nil {
		return fmt.Errorf("the server is not configured for TOTP")
	}

	// Check that TOTP is enabled for current account. Fail closed if the state
	// cannot be read so we never try to regenerate codes against a corrupt file.
	enabled, _, _, err := ct.User.GetTOTP()
	if err != nil {
		return err
	}
	if !enabled {
		return fmt.Errorf("TOTP is disabled on this account")
	}

	return nil
}

// Execute executes the command
func (c *SelfGenerateTOTPCodes) Execute(ct *commands.Context) (repl models.ReplicationData, cmdError error, err error) {

	// Re-read the current secret so the regenerated codes stay bound to it. Fail
	// closed if it cannot be read rather than replicating an empty secret.
	_, currentSecret, _, err := ct.User.GetTOTP()
	if err != nil {
		return
	}

	// Generate fresh emergency codes from a cryptographically secure source.
	// These codes bypass TOTP, so a secure-RNG failure must abort rather than
	// overwrite the user's recovery codes with predictable or empty ones.
	random, err := helpers.GetRandomStrings(5, 8)
	if err != nil {
		err = fmt.Errorf("failed to generate TOTP emergency codes: %w", err)
		return
	}

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
