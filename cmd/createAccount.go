package cmd

import (
	"fmt"

	"github.com/golgeek/sb/internal/commands"
	"github.com/golgeek/sb/internal/config"
	"github.com/golgeek/sb/internal/helpers"
	"github.com/golgeek/sb/internal/models"
)

// CreateAccount describes the command
type CreateAccount struct {
	PK *helpers.PublicKey
}

func init() {
	commands.RegisterCommand("account create", func() (c commands.Command, r models.Right, helper helpers.Helper, args map[string]commands.Argument) {
		return new(CreateAccount), models.SBOwner, helpers.Helper{
				Header:      "create a new account on sb",
				Usage:       "createAccount --username USERNAME --public-key 'KEY'",
				Description: "create a new account on sb",
				Aliases:     []string{"createAccount"},
			}, map[string]commands.Argument{
				"username": {
					Required:    true,
					Description: "The username of the account you want to create",
				},
				"public-key": {
					Required:    true,
					Description: "The ingress (user -> sb) SSH public key of the account you want to create (you will need to '\"double escape it\"')",
				},
			}
	})
}

// Checks checks whether or not the user can execute this method
func (c *CreateAccount) Checks(ct *commands.Context) error {

	// Validate the requested username up front so a malformed name is rejected
	// with a clear message before any system change is attempted. The same
	// validation is enforced again deeper in helpers.AddUser as the fail-closed
	// security boundary.
	if err := helpers.ValidateSystemName(ct.FormattedArguments["username"]); err != nil {
		return err
	}

	// We check the user doesn't exist yet
	_, err := models.LoadUser(ct.FormattedArguments["username"])
	if err == nil {
		return fmt.Errorf("this username already exists")
	}

	// We try to validate the provided public-key
	pk, err := helpers.CheckStringPK(ct.FormattedArguments["public-key"], []helpers.PublicKey{})
	if err != nil {
		return err
	}

	c.PK = pk

	return nil
}

// Execute executes the command
func (c *CreateAccount) Execute(ct *commands.Context) (repl models.ReplicationData, cmdError error, err error) {

	repl = models.ReplicationData{
		"username":   ct.FormattedArguments["username"],
		"public-key": c.PK.String(),
	}
	repl["home-dir"] = fmt.Sprintf("/home/%s", repl["username"])
	repl["ssh-dir"] = fmt.Sprintf("%s/.ssh", repl["home-dir"])

	err = c.Replicate(repl)

	return
}

func (c *CreateAccount) PostExecute(repl models.ReplicationData) (err error) {
	return
}

func (c *CreateAccount) Replicate(repl models.ReplicationData) (err error) {

	fmt.Println("Adding user")
	err = helpers.AddUser(repl["home-dir"], repl["username"], config.GetBinaryPath())
	if err != nil {
		return
	}

	fmt.Println("Creating home skeleton")
	err = helpers.CreateHomeSkeleton(repl["home-dir"], repl["username"], "user")
	if err != nil {
		return
	}

	fmt.Println("Pushing pk in authorized_keys file")
	err = helpers.FillUserAuthorizedKeysFile(repl["ssh-dir"], repl["username"], repl["public-key"])
	if err != nil {
		return
	}

	fmt.Printf("User %s was successfully created\n", repl["username"])

	return
}
