package cmd

import (
	"fmt"
	"strings"

	"github.com/golgeek/sb/internal/commands"
	"github.com/golgeek/sb/internal/helpers"
	"github.com/golgeek/sb/internal/models"
)

// GroupListAccesses describes the help command
type GroupListAccesses struct{}

func init() {
	commands.RegisterCommand("group accesses list", func() (c commands.Command, r models.Right, helper helpers.Helper, args map[string]commands.Argument) {
		return new(GroupListAccesses), models.GroupMember, helpers.Helper{
				Header:      "list the hosts accessible to a group",
				Usage:       "group accesses list --group 'GROUP-NAME'",
				Description: "list the hosts accessible to a group",
				Aliases:     []string{"groupListAccesses"},
			}, map[string]commands.Argument{
				"group": {
					Required:    true,
					Description: "The group name you want accesses from",
				},
			}
	})
}

// Checks checks whether or not the user can execute this method
func (c *GroupListAccesses) Checks(ct *commands.Context) error {
	return nil
}

// Execute executes the command
func (c *GroupListAccesses) Execute(ct *commands.Context) (repl models.ReplicationData, cmdError error, err error) {

	accesses, err := ct.Group.GetAccesses()
	if err != nil {
		return
	}

	allAccesses := make([]string, 0, len(accesses.Accesses))
	for _, host := range accesses.Accesses {
		allAccesses = append(allAccesses, host.String())
	}

	if len(allAccesses) > 0 {
		fmt.Printf(
			"Here is the list of accessible distant hosts to the group %s:\n%s\n",
			ct.Group.Name,
			strings.Join(allAccesses, "\n"),
		)
	} else {
		fmt.Printf("Group %s doesn't have any access to distant hosts yet\n", ct.Group.Name)
	}

	return
}

func (c *GroupListAccesses) PostExecute(repl models.ReplicationData) (err error) {
	return
}

func (c *GroupListAccesses) Replicate(repl models.ReplicationData) (err error) {
	return
}
