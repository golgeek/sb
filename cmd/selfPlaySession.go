package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/golgeek/sb/internal/commands"
	"github.com/golgeek/sb/internal/helpers"
	"github.com/golgeek/sb/internal/models"
	"maze.io/x/ttyrec"
)

// SelfPlaySession describes the selfListAccesses command
type SelfPlaySession struct{}

func init() {
	commands.Register(commands.CommandSpec{
		Name:    "self session replay",
		Aliases: []string{"selfPlaySession"},
		Rights:  models.Public,
		Help: helpers.Helper{
			Header:      "watch a recording of an SSH session",
			Usage:       "self session replay",
			Description: "watch a recording of an SSH session",
		},
		Args: map[string]commands.Argument{
			"session-id": {
				Required:    true,
				Description: "The session recording ID to watch",
			},
		},
		New: func() commands.Command { return new(SelfPlaySession) },
	})
}

// Checks checks whether or not the user can execute this method
func (c *SelfPlaySession) Checks(ct *commands.Context) error {
	return ct.User.AuthorizeRecording(ct.FormattedArguments["session-id"])
}

// Execute executes the command
func (c *SelfPlaySession) Execute(ct *commands.Context) (res commands.Result, err error) {

	localFilepath, cleanup, err := prepareRecording(ct.User, ct.FormattedArguments["session-id"])
	if err != nil {
		return
	}
	defer cleanup()

	r, err := os.Open(localFilepath)
	if err != nil {
		err = fmt.Errorf("file not found: %w", err)
		return
	}

	defer r.Close()

	d := ttyrec.NewDecoder(r)
	frames, stop := d.DecodeStream()
	defer stop()

	var previous *ttyrec.Frame
	for frame := range frames {
		if _, errFrame := os.Stdout.Write(frame.Data); errFrame != nil {
			err = fmt.Errorf("error writing frame: %w", errFrame)
			return
		}
		if previous != nil {
			d := frame.Time.Sub(previous.Time)
			time.Sleep(time.Duration(float64(d)))
		}
		previous = frame
	}

	return
}

func (c *SelfPlaySession) PostExecute(repl models.ReplicationData) (err error) {
	return
}

func (c *SelfPlaySession) Replicate(repl models.ReplicationData) (err error) {
	return
}
