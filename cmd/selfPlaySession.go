package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/golgeek/sb/internal/commands"
	"github.com/golgeek/sb/internal/config"
	"github.com/golgeek/sb/internal/helpers"
	"github.com/golgeek/sb/internal/models"
	"github.com/golgeek/sb/internal/storage"
	"github.com/pkg/errors"
	"maze.io/x/ttyrec"
)

// SelfPlaySession describes the selfListAccesses command
type SelfPlaySession struct{}

func init() {
	commands.RegisterCommand("self session replay", func() (c commands.Command, r models.Right, h helpers.Helper, args map[string]commands.Argument) {
		return new(SelfPlaySession), models.Public, helpers.Helper{
				Header:      "watch a recording of an SSH session",
				Usage:       "self session replay",
				Description: "watch a recording of an SSH session",
				Aliases:     []string{"selfPlaySession"},
			}, map[string]commands.Argument{
				"session-id": {
					Required:    true,
					Description: "The session recording ID to watch",
				},
			}
	})
}

// Checks checks whether or not the user can execute this method
func (c *SelfPlaySession) Checks(ct *commands.Context) error {
	// No specific rights needed but a sb account
	return nil
}

// Execute executes the command
func (c *SelfPlaySession) Execute(ct *commands.Context) (repl models.ReplicationData, cmdError error, err error) {

	filename := fmt.Sprintf("%s.ttyrec", ct.FormattedArguments["session-id"])
	localFilepath := fmt.Sprintf("%s/%s", ct.User.GetTtyrecDirectory(), filename)

	// If TTYRecs offloading is enabled, we start by getting the ttyrec file from a storage
	ttyRecsOffloadingConfig := config.GetTTYRecsOffloadingConfig()
	if ttyRecsOffloadingConfig.Enabled {

		var rs storage.Storage
		rs, err = storage.GetStorage(ttyRecsOffloadingConfig)
		if err != nil {
			return
		}

		err = rs.GetFromStorage(fmt.Sprintf("%s.bin", filename), fmt.Sprintf("%s.bin", localFilepath))
		if err != nil {
			return
		}

		err = helpers.DecryptFile(fmt.Sprintf("%s.bin", localFilepath), localFilepath, config.GetEncryptionKey())
		if err != nil {
			return
		}

		err = os.Remove(fmt.Sprintf("%s.bin", localFilepath))
		if err != nil {
			return
		}
	}

	r, err := os.Open(localFilepath)
	if err != nil {
		err = errors.Wrap(err, "file not found")
		return
	}

	d := ttyrec.NewDecoder(r)
	frames, stop := d.DecodeStream()
	defer stop()

	var previous *ttyrec.Frame
	for frame := range frames {
		if _, errFrame := os.Stdout.Write(frame.Data); err != nil {
			err = errors.Wrap(errFrame, "error writing frame")
			return
		}
		if previous != nil {
			d := frame.Time.Sub(previous.Time)
			time.Sleep(time.Duration(float64(d)))
		}
		previous = frame
	}

	if ttyRecsOffloadingConfig.Enabled {
		err = os.Remove(localFilepath)
		if err != nil {
			return
		}
	}

	return
}

func (c *SelfPlaySession) PostExecute(repl models.ReplicationData) (err error) {
	return
}

func (c *SelfPlaySession) Replicate(repl models.ReplicationData) (err error) {
	return
}
