package cmd

import (
	"fmt"
	"os"
	"strconv"
	"syscall"

	"github.com/golgeek/sb/internal/commands"
	"github.com/golgeek/sb/internal/helpers"
	"github.com/golgeek/sb/internal/models"

	"github.com/golgeek/ttyrec2gif"
	"golang.org/x/term"
)

// SelfGetSessionAsGif describes the selfListAccesses command
type SelfGetSessionAsGif struct{}

func init() {
	commands.Register(commands.CommandSpec{
		Name:    "self session gif",
		Aliases: []string{"selfGetSessionAsGif"},
		Rights:  models.Public,
		Help: helpers.Helper{
			Header:      "get a recording of an SSH session as a gif",
			Usage:       "self session gif",
			Description: "get a recording of an SSH session as a gif",
		},
		Args: map[string]commands.Argument{
			"session-id": {
				Required:    true,
				Description: "The session recording ID to convert as a GIF",
			},
			"repeat": {
				Required:    false,
				Description: "Specify if animation is repeated",
				Type:        commands.BOOL,
			},
			"speed": {
				Required:     false,
				Description:  "Specify the play speed factor of the session (default is \"1.0\")",
				DefaultValue: "1.0",
			},
		},
		New: func() commands.Command { return new(SelfGetSessionAsGif) },
	})
}

// Checks checks whether or not the user can execute this method
func (c *SelfGetSessionAsGif) Checks(ct *commands.Context) error {

	_, err := strconv.ParseFloat(ct.FormattedArguments["speed"], 64)
	if err != nil {
		return fmt.Errorf("argument speed is not a valid float")
	}

	return ct.User.AuthorizeRecording(ct.FormattedArguments["session-id"])
}

// Execute executes the command
func (c *SelfGetSessionAsGif) Execute(ct *commands.Context) (res commands.Result, err error) {

	localFilepath, cleanup, err := prepareRecording(ct.User, ct.FormattedArguments["session-id"])
	if err != nil {
		return
	}
	defer cleanup()
	outputFile := localFilepath + ".gif"

	_, repeat := ct.FormattedArguments["repeat"]
	speed, err := strconv.ParseFloat(ct.FormattedArguments["speed"], 64)
	if err != nil {
		return
	}

	generator := ttyrec2gif.NewGifGenerator()
	generator.Speed = speed
	generator.NoLoop = !repeat
	err = generator.Generate(localFilepath, outputFile)
	if err != nil {
		err = fmt.Errorf("unable to generate GIF from TTYRec: %w", err)
		return
	}

	content, err := os.ReadFile(outputFile)
	if err != nil {
		return
	}

	// We set stdout in raw mode to avoid \r\n transformations by ssh -t on client side
	_, err = term.MakeRaw(syscall.Stdout)
	if err != nil {
		return
	}

	fmt.Printf("%s", string(content))

	return
}

func (c *SelfGetSessionAsGif) PostExecute(repl models.ReplicationData) (err error) {
	return
}

func (c *SelfGetSessionAsGif) Replicate(repl models.ReplicationData) (err error) {
	return
}
