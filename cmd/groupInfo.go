package cmd

import (
	"fmt"
	"strings"

	"github.com/golgeek/sb/internal/commands"
	"github.com/golgeek/sb/internal/helpers"
	"github.com/golgeek/sb/internal/models"
)

// GroupInfo describes the help command
type GroupInfo struct{}

func init() {
	commands.Register(commands.CommandSpec{
		Name:    "group info",
		Aliases: []string{"groupInfo"},
		Rights:  models.Public,
		Help: helpers.Helper{
			Header:      "display the basic information of a group",
			Usage:       "group info --group 'GROUP-NAME'",
			Description: "display the basic information of a group",
		},
		Args: map[string]commands.Argument{
			"group": {
				Required:    true,
				Description: "The group name you want info from",
			},
		},
		New: func() commands.Command { return new(GroupInfo) },
	})
}

// Checks checks whether or not the user can execute this method
func (c *GroupInfo) Checks(ct *commands.Context) error {
	return nil
}

// Execute executes the command
func (c *GroupInfo) Execute(ct *commands.Context) (repl models.ReplicationData, cmdError error, err error) {

	fmt.Printf("Here are the info of group %s:\n", ct.Group.Name)

	toFetch := []string{"owner", "gate-keeper"}
	if ct.User.IsMemberOfGroup(ct.Group.Name) || ct.User.IsACLKeeperOfGroup(ct.Group.Name) {
		toFetch = append(toFetch, "acl-keeper", "member")
	}

	for _, memberType := range toFetch {
		list, err := ct.Group.GetMembers(memberType)
		if err != nil {
			fmt.Printf("    - List of group %ss: [error while listing, please report]\n", memberType)
		} else {
			fmt.Printf("    - List of group %ss: %s\n", memberType, strings.Join(list, ", "))
		}
	}

	if ct.User.IsMemberOfGroup(ct.Group.Name) || ct.User.IsACLKeeperOfGroup(ct.Group.Name) {
		strPubKeys, _, _ := ct.Group.DisplayPubKeys("egress")
		fmt.Printf("List of group's egress public SSH keys (sb -> distant host):\n%s\n", strPubKeys)
	} else {
		fmt.Println("You're not a member of this group: ask the owners or gate-keepers if you think you should be added.")
	}

	return
}

func (c *GroupInfo) PostExecute(repl models.ReplicationData) (err error) {
	return
}

func (c *GroupInfo) Replicate(repl models.ReplicationData) (err error) {
	return
}
