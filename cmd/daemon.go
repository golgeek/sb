package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/golgeek/sb/internal/commands"
	"github.com/golgeek/sb/internal/config"
	"github.com/golgeek/sb/internal/dedupcache"
	"github.com/golgeek/sb/internal/helpers"
	"github.com/golgeek/sb/internal/models"
	"github.com/golgeek/sb/internal/replicationqueue"
	"github.com/golgeek/sb/internal/types"
)

// CreateAccount describes the command
type Daemon struct {
	hostname   string
	replicated *dedupcache.Cache
}

func init() {
	commands.RegisterCommand("daemon", func() (c commands.Command, r models.Right, helper helpers.Helper, args map[string]commands.Argument) {
		return new(Daemon), models.Public, helpers.Helper{
			Header:      "daemon",
			Usage:       "daemon --subscriber",
			Description: "Launch the replication-daemon",
		}, map[string]commands.Argument{}
	})
}

// Checks checks whether or not the user can execute this method
func (c *Daemon) Checks(ct *commands.Context) error {

	return nil
}

// Execute executes the command
func (c *Daemon) Execute(ct *commands.Context) (repl models.ReplicationData, cmdError error, err error) {

	// IF replication is not enabled, nothing to do
	replicationQueueConfig := config.GetReplicationQueueConfig()
	ttyrecsOffloadingConfig := config.GetTTYRecsOffloadingConfig()

	// If both replication and ttyrecs offloading is disabled, nothing to do
	if !replicationQueueConfig.Enabled && !ttyrecsOffloadingConfig.Enabled {
		return repl, cmdError, types.ErrCommandDisabled
	}

	// We need to guess our own hostname
	c.hostname, err = helpers.GetHostname()
	if err != nil {
		return
	}

	fmt.Fprintf(os.Stdout, "Starting daemon for hostname: %s\n", c.hostname)

	// Init the replication queue backend
	rq, err := replicationqueue.GetReplicationQueue(replicationQueueConfig, c.hostname)
	if err != nil {
		return
	}

	// If replication is enabled, we start replicating other instances' actions
	if replicationQueueConfig.Enabled {
		c.replicated = dedupcache.New(5 * time.Minute)
		go func() {
			if err := c.consumeReplicationEvents(rq); err != nil {
				fmt.Fprintf(os.Stderr, "ERROR: replication consumer stopped: %s\n", err)
			}
		}()
	}

	// Handle post executions and potentially push events to other instances via the queue
	go func() {
		if err := c.publishReplicationEvents(rq, !replicationQueueConfig.Enabled); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: replication publisher stopped: %s\n", err)
		}
	}()

	// Let's just wait indefinitely
	select {}
}

func (c *Daemon) PostExecute(repl models.ReplicationData) (err error) {
	return
}

func (c *Daemon) Replicate(repl models.ReplicationData) (err error) {
	return
}

func (c *Daemon) consumeReplicationEvents(rq replicationqueue.ReplicationQueue) (err error) {

	return rq.ConsumeQueue(func(entry *models.Replication) (err error) {

		fmt.Printf("New replication entry received: [instance:%s|type:%s|ID:%s]\n", entry.Instance, entry.Action, entry.UniqID)
		if c.replicated.Seen(entry.UniqID) {
			fmt.Println("  -> this message was already replicated")
			return
		}

		// If I sent this entry myself, I don't care about it
		if entry.Instance == c.hostname {
			c.replicated.Mark(entry.UniqID)
			return
		}

		// Let's decipher the replication data
		replicationData, err := models.DecryptReplicationData(entry.Data)
		if err != nil {
			return
		}

		switch entry.Action {
		case "log", "new-log":

			var log models.Log
			err = json.Unmarshal([]byte(replicationData["log"]), &log)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ERROR: unable to json.Unmarshal log entry: %s", err)
				return
			}

			err = log.Replicate((entry.Action == "new-log"))
			if err != nil {
				fmt.Fprintf(os.Stderr, "ERROR: unable to save log entry: %s\n", err)
				return
			}

			c.replicated.Mark(entry.UniqID)

			return nil

		default:

			cmd, _, _, _, err := commands.GetCommand(entry.Action)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ERROR: unknown command to replicate: %s\n", err)
				return err
			}

			err = cmd.Replicate(replicationData)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ERROR: unable to replicate action: %s\n", err)
				return err
			}

			c.replicated.Mark(entry.UniqID)

			return nil

		}
	})

}

func (c *Daemon) publishReplicationEvents(rq replicationqueue.ReplicationQueue, onlyHandlePostExec bool) (err error) {

	dbHandler, err := models.GetReplicationGormDB(config.GetReplicationDatabasePath())
	if err != nil {
		return
	}

	for {
		entry, err := models.GetNextReplicationEntryToPush(dbHandler)
		if err != nil {
			time.Sleep(time.Second * 5)
			continue
		}

		fmt.Printf("New action entry to process: [instance:%s|type:%s|ID:%s]\n", entry.Instance, entry.Action, entry.UniqID)

		if entry.Action != "log" && entry.Action != "new-log" {
			fmt.Println("  -> executing PostExecution step...")

			// Starting with the PostExecute function
			err = c.handlePostExecution(entry)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ERROR: unable to handle PostExecution: %s\n", err)
				time.Sleep(time.Second * 5)
				continue
			}
		}

		if !onlyHandlePostExec {
			fmt.Println("  -> publishing to PubSub...")

			// Then publishing the entry
			err = rq.PushToQueue(&entry)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ERROR: unable to handle publish: %s\n", err)
				time.Sleep(time.Second * 5)
				continue
			}
		}

		fmt.Println("  -> deleting the entry...")

		// Finally, we delete the entry from our local database
		err = entry.Delete(dbHandler)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: unable to delete entry from database: %s", err)
			time.Sleep(time.Second * 5)
			continue
		}
	}

}

func (c *Daemon) handlePostExecution(entry models.Replication) (err error) {

	fmt.Println("    -> decrypting data...")

	// Let's decipher the replication data
	replicationData, err := models.DecryptReplicationData(entry.Data)
	if err != nil {
		return fmt.Errorf("unable to decrypt replication data for PostExecution")
	}

	fmt.Println("    -> getting the command to execute...")

	cmd, _, _, _, err := commands.GetCommand(entry.Action)
	if err != nil {
		return fmt.Errorf("unknown command to PostExecute: %s", err)
	}

	fmt.Println("    -> executing PostExecute() func...")

	err = cmd.PostExecute(replicationData)
	if err != nil {
		return fmt.Errorf("unable to excute the PostExecute action: %s", err)
	}

	fmt.Println("    -> all done!")

	return
}
