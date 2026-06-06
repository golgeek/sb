package cmd

import (
	"fmt"

	"github.com/golgeek/sb/internal/commands"
	"github.com/golgeek/sb/internal/helpers"
	"github.com/golgeek/sb/internal/models"
)

// GroupDelMember describes the command
type GroupDelMember struct{}

func init() {
	commands.RegisterCommand("group member remove", func() (c commands.Command, r models.Right, helper helpers.Helper, args map[string]commands.Argument) {
		return new(GroupDelMember), models.GroupGateKeeper, helpers.Helper{
				Header:      "remove an account from the members of a group",
				Usage:       "group member remove --account USERNAME --group GROUP",
				Description: "remove an account from the members of a group",
				Aliases:     []string{"groupDelMember"},
			}, map[string]commands.Argument{
				"account": {
					Required:    true,
					Description: "The username of the account",
				},
				"group": {
					Required:    true,
					Description: "The group to which remove the account from",
				},
			}
	})
}

// Checks checks whether or not the user can execute this method
func (c *GroupDelMember) Checks(ct *commands.Context) error {

	// Check if the user exists
	user, err := models.LoadUser(ct.FormattedArguments["account"])
	if err != nil {
		return fmt.Errorf("account %s doesn't exist", ct.FormattedArguments["account"])
	}
	if !user.IsMemberOfGroup(ct.FormattedArguments["group"]) {
		return fmt.Errorf("account %s is already not a group member", ct.FormattedArguments["account"])
	}

	return nil
}

// Execute executes the command
func (c *GroupDelMember) Execute(ct *commands.Context) (repl models.ReplicationData, cmdError error, err error) {

	repl = models.ReplicationData{
		"group":   ct.FormattedArguments["group"],
		"account": ct.FormattedArguments["account"],
	}

	err = c.Replicate(repl)

	return
}

func (c *GroupDelMember) PostExecute(repl models.ReplicationData) (err error) {
	return
}

func (c *GroupDelMember) Replicate(repl models.ReplicationData) (err error) {

	err = helpers.RemoveAccountFromGroup(repl["group"], repl["account"], "m")
	if err != nil {
		return
	}

	fmt.Printf("Account %s was successfully removed from the members of group %s\n", repl["account"], repl["group"])

	return
}
