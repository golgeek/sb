package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/golgeek/sb/cmd"
	"github.com/golgeek/sb/internal/commands"
	"github.com/golgeek/sb/internal/config"
	"github.com/golgeek/sb/internal/helpers"
	"github.com/golgeek/sb/internal/models"
	"github.com/golgeek/sb/internal/types"
)

// Run gocyclo
//go:generate go run github.com/fzipp/gocyclo/cmd/gocyclo -ignore "vendor/" -over 30 .

func main() {

	// Get the system user calling
	currentUser, err := models.LoadCurrentUser()
	if err != nil {
		fmt.Printf("unable to get current user: %s\n", err)
		os.Exit(1)
	}

	// If replication is enabled
	if config.GetReplicationEnabled() {

		totpEnabled, secret, totpEmergency := currentUser.GetTOTP()

		// And user has TOTP enabled
		if totpEnabled {

			// Maybe the user used a recovery code, and we need to sync it to the other instances
			dbHandler, err := models.GetReplicationGormDB(config.GetReplicationDatabasePath())
			if err != nil {
				fmt.Printf("unable to init replication db handle: %s\n", err)
				return
			}
			sqlDB, err := dbHandler.DB()
			if err != nil {
				fmt.Printf("unable to init replication db handle: %s\n", err)
				return
			}

			replicationData := models.ReplicationData{
				"account":      currentUser.User.Username,
				"secret":       secret,
				"random-codes": strings.Join(totpEmergency, ";"),
			}
			repl, err := models.NewReplicationEntry("self totp emergency-codes generate", replicationData)
			if err != nil {
				fmt.Printf("unable to handle create replication entry: %s\n", err)
				return
			}
			err = repl.Save(dbHandler)
			if err != nil {
				sqlDB.Close()
				fmt.Printf("unable to save replication entry: %s\n", err)
				os.Exit(1)
			}

			sqlDB.Close()

		}

	}

	// Load commands (this is actually an empty func just used to iterate over all cmd/*.go init() funcs)
	cmd.LoadCommands()

	// Parse the command line
	client, clientArguments, sbArguments, arguments, err := helpers.ParseArguments(os.Args)
	if err != nil {
		fmt.Printf("unable to parse arguments: %s\n", err)
		os.Exit(1)
	}

	// Initialize a new log entry
	log := models.NewLog(currentUser.User.Username, []string{config.GetGlobalDatabasePath(), currentUser.GetLocalLogDatabasePath()}, os.Args)

	// We have two special cases: sb was called with -i option (we switch to interactive mode) or -d (we switch to daemon mode)
	if _, ok := sbArguments["interactive"]; ok {

		// We'll need to know if we're running mosh or ssh, here
		args := []string{
			"interactive",
			"--client", client,
			"--client-arguments", strings.Join(clientArguments, ","),
		}

		// We are on a trusted command, we give it all the remaining args
		err := commands.BuildAndExecuteSBCommand(log, currentUser, args...)

		TerminateSession(log, err)

	} else if _, ok := sbArguments["daemon"]; ok {

		// We'll need to know if we're running mosh or ssh, here
		args := []string{
			"daemon",
		}

		// We are on a trusted command, we give it all the remaining args
		err := commands.BuildAndExecuteSBCommand(log, currentUser, args...)

		TerminateSession(log, err)
	}

	// If we're not in interactive mode,
	// let's get the first argument to determine what to do (if none, we display help)
	if len(arguments) == 0 {
		arguments = []string{"help"}
	}

	cmd := arguments[0]
	if commands.IsAPublicCommand(cmd) {

		// We are on a trusted command, we give it all the remaining args
		err = commands.BuildAndExecuteSBCommand(log, currentUser, arguments...)

	} else {

		if !models.IsAValidSBAccessFromUserInput(cmd) {
			TerminateSession(log, types.ErrUnknownCommand)
		}

		// We'll need to know if we're running mosh or ssh, here
		args := []string{
			"--client", client,
			"--client-arguments", strings.Join(clientArguments, ","),
			"--access", arguments[0],
		}
		if len(arguments) > 1 {
			args = append(args, arguments[1:]...)
		}

		// We have an alias or a host, so we want to SSH connect to it while ttyrec-ing. Let's use our ttyrec command for that!
		arguments = append([]string{config.GetSSHCommand()}, args...)
		err = commands.BuildAndExecuteSBCommand(log, currentUser, arguments...)
	}

	TerminateSession(log, err)

}

// TerminateSession is a global accessible function that terminates the session while saving the log one last time
func TerminateSession(log *models.Log, err error) {
	log.SessionEndDate = time.Now()
	log.Save()

	var statusCode int
	switch {
	case err == nil:
		statusCode = 0
	case err == types.ErrCommandDisabled:
		statusCode = 126
		fmt.Printf("This command is disabled\n")
	case err == types.ErrMissingArguments:
		statusCode = 2
	default:
		statusCode = 1
		fmt.Printf("Error while executing command: %s\n", err)
	}

	os.Exit(statusCode)
}
