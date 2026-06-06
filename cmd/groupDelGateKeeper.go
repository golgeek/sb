package cmd

import (
	"fmt"

	"github.com/golgeek/sb/internal/commands"
	"github.com/golgeek/sb/internal/helpers"
	"github.com/golgeek/sb/internal/models"
)

// GroupDelGateKeeper describes the command
type GroupDelGateKeeper struct{}

func init() {
	commands.RegisterCommand("group gate-keeper remove", func() (c commands.Command, r models.Right, helper helpers.Helper, args map[string]commands.Argument) {
		return new(GroupDelGateKeeper), models.GroupOwner, helpers.Helper{
				Header:      "remove an account from the gate keepers of a group",
				Usage:       "group gate-keeper remove --account USERNAME --group GROUP",
				Description: "remove an account from the gate keepers of a group",
				Aliases:     []string{"groupDelGateKeeper"},
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
func (c *GroupDelGateKeeper) Checks(ct *commands.Context) error {

	// Check if the user exists
	user, err := models.LoadUser(ct.FormattedArguments["account"])
	if err != nil {
		return fmt.Errorf("account %s doesn't exist", ct.FormattedArguments["account"])
	}
	if !user.IsACLKeeperOfGroup(ct.FormattedArguments["group"]) {
		return fmt.Errorf("account %s is already not a group ACL keeper", ct.FormattedArguments["account"])
	}

	return nil
}

// Execute executes the command
func (c *GroupDelGateKeeper) Execute(ct *commands.Context) (repl models.ReplicationData, cmdError error, err error) {

	repl = models.ReplicationData{
		"group":   ct.FormattedArguments["group"],
		"account": ct.FormattedArguments["account"],
	}

	err = c.Replicate(repl)

	return
}

func (c *GroupDelGateKeeper) PostExecute(repl models.ReplicationData) (err error) {
	return
}

func (c *GroupDelGateKeeper) Replicate(repl models.ReplicationData) (err error) {

	err = helpers.RemoveAccountFromGroup(repl["group"], repl["account"], "gk")
	if err != nil {
		return
	}

	fmt.Printf("Account %s was successfully removed from the ACL keepers of group %s\n", repl["account"], repl["group"])
	return
}
