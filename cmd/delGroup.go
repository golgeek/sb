package cmd

import (
	"fmt"
	"time"

	"github.com/golgeek/sb/internal/commands"
	"github.com/golgeek/sb/internal/helpers"
	"github.com/golgeek/sb/internal/models"
)

// DelGroup describes the command
type DelGroup struct{}

func init() {
	commands.Register(commands.CommandSpec{
		Name:    "group delete",
		Aliases: []string{"delGroup"},
		Rights:  models.SBOwner,
		Help: helpers.Helper{
			Header:      "delete a group from sb",
			Usage:       "group delete --group GROUP",
			Description: "delete a group from sb",
		},
		Args: map[string]commands.Argument{
			"group": {
				Required:    true,
				Description: "The name of the group",
			},
		},
		New: func() commands.Command { return new(DelGroup) },
	})
}

// Checks checks whether or not the user can execute this method
func (c *DelGroup) Checks(ct *commands.Context) error {

	// Check if the group exists
	groups, err := models.GetAllSBGroups()
	if err != nil {
		return err
	}
	if _, ok := groups[ct.FormattedArguments["group"]]; !ok {
		return fmt.Errorf("group %s doesn't exist", ct.FormattedArguments["group"])
	}

	return nil
}

// Execute executes the command
func (c *DelGroup) Execute(ct *commands.Context) (res commands.Result, err error) {

	res.Repl = models.ReplicationData{
		"group":          ct.FormattedArguments["group"],
		"archive-suffix": fmt.Sprintf("bak_%d", time.Now().Unix()),
	}

	err = c.Replicate(res.Repl)

	return
}

func (c *DelGroup) PostExecute(repl models.ReplicationData) (err error) {
	return
}

func (c *DelGroup) Replicate(repl models.ReplicationData) (err error) {

	err = helpers.DeleteGroup(repl["group"], repl["archive-suffix"])
	if err != nil {
		return
	}

	fmt.Printf("Group %s was successfully deleted\n", repl["group"])

	return
}
