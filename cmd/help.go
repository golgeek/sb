package cmd

import (
	"fmt"
	"strconv"

	"github.com/golgeek/sb/internal/commands"
	"github.com/golgeek/sb/internal/config"
	"github.com/golgeek/sb/internal/helpers"
	"github.com/golgeek/sb/internal/models"
)

// Help describes the help command
type Help struct {
}

func init() {
	commands.Register(commands.CommandSpec{
		Name:   "help",
		Rights: models.Public,
		Help: helpers.Helper{
			Header:      "display this help",
			Usage:       "help",
			Description: "display this help",
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

// Execute executes the command
func (c *Help) Execute(ct *commands.Context) (repl models.ReplicationData, cmdError error, err error) {

	specs := commands.Specs()

	maxLength := 0
	listable := make([]*commands.CommandSpec, 0, len(specs))

	for _, spec := range specs {

		// Trusted commands (interactive, ttyrec, daemon) are dispatched by
		// the front-end only and must never be advertised to users.
		if spec.Trusted {
			continue
		}

		if len(spec.Name) > maxLength {
			maxLength = len(spec.Name)
		}
		listable = append(listable, spec)
	}

	fmt.Printf("Usage: %s [OPTION | HOST | COMMAND]\n", config.GetSBName())
	fmt.Println()
	fmt.Printf("Available options:\n")
	fmt.Printf("  -i: launch sb in interactive mode\n")
	fmt.Println()
	fmt.Printf("Host supported formats:\n")
	fmt.Printf("  - full formats:\n")
	fmt.Printf("    - user@example.com:22\n")
	fmt.Printf("    - user@127.0.0.1:22\n")
	fmt.Printf("  - short formats*:\n")
	fmt.Printf("    - user@example.com : port will be retrieved from granted access\n")
	fmt.Printf("    - example.com:22   : user will be retrieved from granted access\n")
	fmt.Printf("    - example.com      : port and user will be retrieved from granted access\n")
	fmt.Printf("  - alias*:\n")
	fmt.Printf("    - user@alias:port  : host will be retrieved from granted access\n")
	fmt.Printf("    - user@alias       : host and port will be retrieved from granted access\n")
	fmt.Printf("    - alias:port       : host and user will be retrieved from granted access\n")
	fmt.Printf("    - alias            : host, user and port will be retrieved from granted access\n")
	fmt.Printf("* If multiple granted access match a short format or an alias,\n")
	fmt.Printf("user will be interactively prompted to choose the desired access\n")
	fmt.Println()
	fmt.Println("Available commands:")
	for _, spec := range listable {

		if spec.Rights >= models.Private {
			continue
		}

		if spec.Rights < models.SBOwner || ct.User.IsOwnerOfGroup("owners") {
			fmt.Printf("  - %-"+strconv.Itoa(maxLength)+"s : %s\n", spec.Name, spec.Help.Header)
		}
	}

	return
}

func (c *Help) PostExecute(repl models.ReplicationData) (err error) {
	return
}

func (c *Help) Replicate(repl models.ReplicationData) (err error) {
	return
}
