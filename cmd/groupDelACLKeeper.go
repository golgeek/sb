package cmd

import (
	"fmt"

	"github.com/golgeek/sb/internal/commands"
	"github.com/golgeek/sb/internal/helpers"
	"github.com/golgeek/sb/internal/models"
)

// GroupDelACLKeeper describes the command
type GroupDelACLKeeper struct{}

func init() {
	commands.Register(commands.CommandSpec{
		Name:    "group acl-keeper remove",
		Aliases: []string{"groupDelACLKeeper"},
		Rights:  models.GroupOwner,
		Help: helpers.Helper{
			Header:      "remove an account from the ACL keepers of a group",
			Usage:       "group acl-keeper delete --account USERNAME --group GROUP",
			Description: "remove an account from the ACL keepers of a group",
		},
		Args: map[string]commands.Argument{
			"account": {
				Required:    true,
				Description: "The username of the account",
			},
			"group": {
				Required:    true,
				Description: "The group to which remove the account from",
			},
		},
		New: func() commands.Command { return new(GroupDelACLKeeper) },
	})
}

// Checks checks whether or not the user can execute this method
func (c *GroupDelACLKeeper) Checks(ct *commands.Context) error {

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
func (c *GroupDelACLKeeper) Execute(ct *commands.Context) (res commands.Result, err error) {

	res.Repl = models.ReplicationData{
		"group":   ct.FormattedArguments["group"],
		"account": ct.FormattedArguments["account"],
	}

	err = c.Replicate(res.Repl)

	return
}

func (c *GroupDelACLKeeper) PostExecute(repl models.ReplicationData) (err error) {
	return
}

func (c *GroupDelACLKeeper) Replicate(repl models.ReplicationData) (err error) {

	err = helpers.RemoveAccountFromGroup(repl["group"], repl["account"], "aclk")
	if err != nil {
		return
	}

	fmt.Printf("Account %s was successfully removed from the ACL keepers of group %s\n", repl["account"], repl["group"])

	return
}
