package cmd

import (
	"fmt"

	"github.com/golgeek/sb/internal/commands"
	"github.com/golgeek/sb/internal/helpers"
	"github.com/golgeek/sb/internal/models"
)

// SelfListEgressKeys describes the selfListEgressKeys command
type SelfListEgressKeys struct{}

func init() {
	commands.Register(commands.CommandSpec{
		Name:    "self egress-keys list",
		Aliases: []string{"selfListEgressKeys"},
		Rights:  models.Public,
		Help: helpers.Helper{
			Header:      "lists your egress public keys (sb -> distant host)",
			Usage:       "self egress-keys list",
			Description: "lists your egress public keys (sb -> distant host)",
		},
		Args: map[string]commands.Argument{},
		New:  func() commands.Command { return new(SelfListEgressKeys) },
	})
}

// Checks checks whether or not the user can execute this method
func (c *SelfListEgressKeys) Checks(ct *commands.Context) error {
	// No specific rights needed but a sb account
	return nil
}

// Execute executes the command
func (c *SelfListEgressKeys) Execute(ct *commands.Context) (repl models.ReplicationData, cmdError error, err error) {

	str, _, err := ct.User.DisplayPubKeys("egress")
	if err != nil {
		return
	}

	fmt.Printf("Here is the list of your egress public SSH keys (sb -> distant host):\n%s\n", str)

	return
}

func (c *SelfListEgressKeys) PostExecute(repl models.ReplicationData) (err error) {
	return
}

func (c *SelfListEgressKeys) Replicate(repl models.ReplicationData) (err error) {
	return
}
