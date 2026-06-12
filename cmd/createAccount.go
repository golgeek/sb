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
	commands.Register(commands.CommandSpec{
		Name:    "account create",
		Aliases: []string{"createAccount"},
		Rights:  models.SBOwner,
		Help: helpers.Helper{
			Header:      "create a new account on sb",
			Usage:       "createAccount --username USERNAME --public-key 'KEY'",
			Description: "create a new account on sb",
		},
		Args: map[string]commands.Argument{
			"username": {
				Required:    true,
				Description: "The username of the account you want to create",
			},
			"public-key": {
				Required:    true,
				Description: "The ingress (user -> sb) SSH public key of the account you want to create (you will need to '\"double escape it\"')",
			},
		},
		New: func() commands.Command { return new(CreateAccount) },
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
func (c *CreateAccount) Execute(ct *commands.Context) (res commands.Result, err error) {

	res.Repl = models.ReplicationData{
		"username":   ct.FormattedArguments["username"],
		"public-key": c.PK.String(),
	}
	res.Repl["home-dir"] = fmt.Sprintf("/home/%s", res.Repl["username"])
	res.Repl["ssh-dir"] = fmt.Sprintf("%s/.ssh", res.Repl["home-dir"])

	err = c.Replicate(res.Repl)

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
