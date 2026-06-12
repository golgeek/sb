package cmd

import (
	"os"

	"github.com/golgeek/sb/internal/commands"
	"github.com/golgeek/sb/internal/helpers"
	"github.com/golgeek/sb/internal/models"
)

// Help is the user-facing help command. Cobra owns the help content: Execute
// renders the generated tree's help text, so the listing can never drift from
// the registered commands. The command itself stays registered as a spec —
// rather than relying on cobra's auto-generated help command — for two
// reasons: "help" is part of the persisted replication name contract (peer
// outboxes may carry it as an action and must keep resolving it), and the
// front-end's first-word dispatch only routes registered command words into
// the tree.
type Help struct {
}

func init() {
	commands.Register(commands.CommandSpec{
		Name:   "help",
		Rights: models.Public,
		Help: helpers.Helper{
			Header:      "display this help",
			Usage:       "help [command words...]",
			Description: "display the bastion help, or a specific command's help when its name follows",
		},
		Args: map[string]commands.Argument{},
		New:  func() commands.Command { return new(Help) },
	})
}

// Checks checks whether or not the user can execute this method
func (c *Help) Checks(ct *commands.Context) error {
	// No specific rights needed but a sb account
	return nil
}

// Execute renders the cobra-generated help: the root help by default, or the
// help of the command named by the trailing words ("help self accesses
// list"). Unknown names fall back to the root help rather than failing — help
// must never refuse to help.
func (c *Help) Execute(ct *commands.Context) (repl models.ReplicationData, cmdError error, err error) {

	root := commands.BuildRootCommand(ct.Log, ct.User)
	root.SetOut(os.Stdout)

	target := root
	if len(ct.RawArguments) > 0 {
		if found, _, ferr := root.Find(ct.RawArguments); ferr == nil && found != nil {
			target = found
		}
	}

	err = target.Help()

	return
}

func (c *Help) PostExecute(repl models.ReplicationData) (err error) {
	return
}

func (c *Help) Replicate(repl models.ReplicationData) (err error) {
	return
}
