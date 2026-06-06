package cmd

import (
	"fmt"
	"strings"

	"github.com/golgeek/sb/internal/commands"
	"github.com/golgeek/sb/internal/helpers"
	"github.com/golgeek/sb/internal/models"
)

// SelfListAccesses describes the selfListAccesses command
type SelfListAccesses struct{}

func init() {
	commands.RegisterCommand("self accesses list", func() (c commands.Command, r models.Right, h helpers.Helper, args map[string]commands.Argument) {
		return new(SelfListAccesses), models.Public, helpers.Helper{
			Header:      "list the hosts accessible to this account",
			Usage:       "self accesses list",
			Description: "list the hosts accessible to this account",
			Aliases:     []string{"selfListAccesses"},
		}, map[string]commands.Argument{}
	})
}

// Checks checks whether or not the user can execute this method
func (c *SelfListAccesses) Checks(ct *commands.Context) error {
	// No specific rights needed but a sb account
	return nil
}

// Execute executes the command
func (c *SelfListAccesses) Execute(ct *commands.Context) (repl models.ReplicationData, cmdError error, err error) {

	accesses, err := ct.User.GetAccesses()
	if err != nil {
		return
	}

	allAccesses := make([]string, 0)
	for _, source := range accesses {
		for _, host := range source.Accesses {
			allAccesses = append(allAccesses, host.String())
		}
	}

	if len(allAccesses) > 0 {
		fmt.Printf(
			"Here is the list of your accessible distant hosts:\n%s\n",
			strings.Join(allAccesses, "\n"),
		)
	} else {
		fmt.Println("You currently don't have any access to distant hosts")
	}

	return
}

func (c *SelfListAccesses) PostExecute(repl models.ReplicationData) (err error) {
	return
}

func (c *SelfListAccesses) Replicate(repl models.ReplicationData) (err error) {
	return
}
