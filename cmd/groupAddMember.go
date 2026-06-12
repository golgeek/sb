package cmd

import (
	"fmt"

	"github.com/golgeek/sb/internal/commands"
	"github.com/golgeek/sb/internal/helpers"
	"github.com/golgeek/sb/internal/models"
)

// GroupAddMember describes the command
type GroupAddMember struct{}

func init() {
	commands.Register(commands.CommandSpec{
		Name:    "group member add",
		Aliases: []string{"groupAddMember"},
		Rights:  models.GroupGateKeeper,
		Help: helpers.Helper{
			Header:      "add an account as a group member",
			Usage:       "group member add --account USERNAME --group GROUP",
			Description: "add an account as a group member",
		},
		Args: map[string]commands.Argument{
			"account": {
				Required:    true,
				Description: "The username of the account",
			},
			"group": {
				Required:    true,
				Description: "The group to which attach of the account",
			},
		},
		New: func() commands.Command { return new(GroupAddMember) },
	})
}

// Checks checks whether or not the user can execute this method
func (c *GroupAddMember) Checks(ct *commands.Context) error {

	// Check if the user exists
	user, err := models.LoadUser(ct.FormattedArguments["account"])
	if err != nil {
		return fmt.Errorf("account %s doesn't exist", ct.FormattedArguments["account"])
	}
	if user.IsMemberOfGroup(ct.FormattedArguments["group"]) {
		return fmt.Errorf("account %s is already a group member", ct.FormattedArguments["account"])
	}

	return nil
}

// Execute executes the command
func (c *GroupAddMember) Execute(ct *commands.Context) (res commands.Result, err error) {

	res.Repl = models.ReplicationData{
		"group":   ct.FormattedArguments["group"],
		"account": ct.FormattedArguments["account"],
	}

	err = c.Replicate(res.Repl)

	return
}

func (c *GroupAddMember) PostExecute(repl models.ReplicationData) (err error) {
	return
}

func (c *GroupAddMember) Replicate(repl models.ReplicationData) (err error) {

	err = helpers.AddAccountInGroup(repl["group"], repl["account"], "m")
	if err != nil {
		return
	}

	fmt.Printf("Account %s was successfully added as a member of group %s\n", repl["account"], repl["group"])

	return
}
