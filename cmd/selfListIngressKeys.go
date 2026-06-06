package cmd

import (
	"fmt"

	"github.com/golgeek/sb/internal/commands"
	"github.com/golgeek/sb/internal/helpers"
	"github.com/golgeek/sb/internal/models"
)

// SelfListIngressKeys describes the selfListIngressKeys command
type SelfListIngressKeys struct{}

func init() {
	commands.RegisterCommand("self ingress-keys list", func() (c commands.Command, r models.Right, h helpers.Helper, args map[string]commands.Argument) {
		return new(SelfListIngressKeys), models.Public, helpers.Helper{
			Header:      "list your ingress public keys (you -> sb)",
			Usage:       "self ingress-keys list [--public-key 'ssh key text']",
			Description: "list your ingress public keys (you -> sb)",
			Aliases:     []string{"selfListIngressKeys"},
		}, map[string]commands.Argument{}
	})
}

// Checks checks whether or not the user can execute this method
func (c *SelfListIngressKeys) Checks(ct *commands.Context) error {
	// No specific rights needed but a sb account
	return nil
}

// Execute executes the command
func (c *SelfListIngressKeys) Execute(ct *commands.Context) (repl models.ReplicationData, cmdError error, err error) {

	str, _, err := ct.User.DisplayPubKeys("ingress")
	if err != nil {
		return
	}

	fmt.Printf("Here is the list of your current ingress public SSH keys (you -> sb):\n%s\n", str)

	return
}

func (c *SelfListIngressKeys) PostExecute(repl models.ReplicationData) (err error) {
	return
}

func (c *SelfListIngressKeys) Replicate(repl models.ReplicationData) (err error) {
	return
}
