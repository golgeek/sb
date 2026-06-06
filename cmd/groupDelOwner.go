package cmd

import (
	"fmt"

	"github.com/golgeek/sb/internal/commands"
	"github.com/golgeek/sb/internal/helpers"
	"github.com/golgeek/sb/internal/models"
)

// GroupDelOwner describes the command
type GroupDelOwner struct{}

func init() {
	commands.RegisterCommand("group owner remove", func() (c commands.Command, r models.Right, helper helpers.Helper, args map[string]commands.Argument) {
		return new(GroupDelOwner), models.GroupOwner, helpers.Helper{
				Header:      "remove an account from the owners of a group",
				Usage:       "group owner remove --account USERNAME --group GROUP",
				Description: "remove an account from the owners of a group",
				Aliases:     []string{"groupDelOwner"},
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
func (c *GroupDelOwner) Checks(ct *commands.Context) error {

	// Check if the user exists
	user, err := models.LoadUser(ct.FormattedArguments["account"])
	if err != nil {
		return fmt.Errorf("account %s doesn't exist", ct.FormattedArguments["account"])
	}
	if !user.IsOwnerOfGroup(ct.FormattedArguments["group"]) {
		return fmt.Errorf("account %s is already not a group ownger", ct.FormattedArguments["account"])
	}

	return nil
}

// Execute executes the command
func (c *GroupDelOwner) Execute(ct *commands.Context) (repl models.ReplicationData, cmdError error, err error) {

	repl = models.ReplicationData{
		"group":   ct.FormattedArguments["group"],
		"account": ct.FormattedArguments["account"],
	}

	err = c.Replicate(repl)

	return
}

func (c *GroupDelOwner) PostExecute(repl models.ReplicationData) (err error) {
	return
}

func (c *GroupDelOwner) Replicate(repl models.ReplicationData) (err error) {

	err = helpers.RemoveAccountFromGroup(repl["group"], repl["account"], "o")
	if err != nil {
		return
	}

	fmt.Printf("Account %s was successfully removed from the owners of group %s\n", repl["account"], repl["group"])
	return
}
