package cmd

import (
	"fmt"
	"strings"

	"github.com/golgeek/sb/internal/commands"
	"github.com/golgeek/sb/internal/helpers"
	"github.com/golgeek/sb/internal/models"
)

// SelfListSessions describes the selfListAccesses command
type SelfListSessions struct{}

func init() {
	commands.Register(commands.CommandSpec{
		Name:    "self sessions list",
		Aliases: []string{"selfListSessions"},
		Rights:  models.Public,
		Help: helpers.Helper{
			Header:      "list your last 20 SSH sessions",
			Usage:       "self sessions list",
			Description: "list your last 20 SSH sessions",
		},
		Args: map[string]commands.Argument{},
		New:  func() commands.Command { return new(SelfListSessions) },
	})
}

// Checks checks whether or not the user can execute this method
func (c *SelfListSessions) Checks(ct *commands.Context) error {
	// No specific rights needed but a sb account
	return nil
}

// Execute executes the command
func (c *SelfListSessions) Execute(ct *commands.Context) (res commands.Result, err error) {

	lastSessions, err := ct.User.GetLastSSHSessions(20)
	if err != nil {
		return
	}

	sessions := make([]string, 0, len(lastSessions))
	for id, session := range lastSessions {
		sessions = append(sessions, fmt.Sprintf("%02d: %s", id+1, session.String()))
	}

	if len(sessions) > 0 {
		fmt.Printf(
			"Here is the list of your last 20 SSH sessions:\n%s\n",
			strings.Join(sessions, "\n"),
		)
	} else {
		fmt.Println("You currently don't have any recorded SSH session")
	}

	return
}

func (c *SelfListSessions) PostExecute(repl models.ReplicationData) (err error) {
	return
}

func (c *SelfListSessions) Replicate(repl models.ReplicationData) (err error) {
	return
}
