package cmd

import (
	"fmt"

	"github.com/golgeek/sb/internal/commands"
	"github.com/golgeek/sb/internal/helpers"
	"github.com/golgeek/sb/internal/models"
)

// SelfDelAccess describes the help command
type SelfDelAccess struct{}

func init() {
	commands.Register(commands.CommandSpec{
		Name:    "self access remove",
		Aliases: []string{"selfDelAccess"},
		Rights:  models.Public,
		Help: helpers.Helper{
			Header:      "remove a personal access to a distant host",
			Usage:       "self access remove --host HOST --user USER --port PORT",
			Description: "remove a personal access to a distant host",
		},
		Args: map[string]commands.Argument{
			"host": {
				Required:    true,
				Description: "An IP, IP range or hostname you're granting access to",
			},
			"user": {
				Required:    true,
				Description: "The user you're granting access to",
			},
			"port": {
				Required:    true,
				Description: "The port you're granting access to",
			},
		},
		New: func() commands.Command { return new(SelfDelAccess) },
	})
}

// Checks checks whether or not the user can execute this method
func (c *SelfDelAccess) Checks(ct *commands.Context) error {
	return nil
}

// Execute executes the command
func (c *SelfDelAccess) Execute(ct *commands.Context) (repl models.ReplicationData, cmdError error, err error) {

	repl = models.ReplicationData{
		"account": ct.User.User.Username,
		"host":    ct.FormattedArguments["host"],
		"user":    ct.FormattedArguments["user"],
		"port":    ct.FormattedArguments["port"],
	}

	err = c.Replicate(repl)

	return
}

func (c *SelfDelAccess) PostExecute(repl models.ReplicationData) (err error) {
	return
}

func (c *SelfDelAccess) Replicate(repl models.ReplicationData) (err error) {

	user, err := models.LoadUser(repl["account"])
	if err != nil {
		return
	}

	ba, err := user.DeleteAccess(
		repl["host"],
		repl["user"],
		repl["port"],
	)
	if err != nil {
		return
	}

	fmt.Printf("The access %s has been removed\n", ba.ShortString())

	return
}
