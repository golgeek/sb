package main

import (
	"errors"
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

	"github.com/spf13/cobra"
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

	// On replicated setups, snapshot the user's TOTP state into the
	// replication outbox so a recovery code consumed by PAM during this very
	// authentication gets invalidated on the peer instances too. Deliberately
	// best-effort: a failed sync warns loudly but never blocks the session —
	// it retries on the user's next invocation, and failing closed here would
	// lock every TOTP user out of the bastion on any outbox hiccup. (The
	// historical inline version aborted the whole invocation, partly with
	// exit code 0.)
	if config.GetReplicationEnabled() {
		if err := models.SyncTOTPState(currentUser, config.GetReplicationDatabasePath()); err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: unable to sync TOTP state to the replication outbox, peer instances may be stale: %s\n", err)
		}
	}

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

	first := arguments[0]
	if commands.IsCommandToken(first) {

		// The command line addresses the command system: translate a
		// camelCase alias (or a shell-quoted multi-word name) to canonical
		// words and let the generated cobra tree parse, authorize and execute
		// it. Building the tree also guarantees the cmd package's command
		// registrations ran.
		root := cmd.BuildRootCommand(log, currentUser)
		root.SetArgs(commands.CanonicalTokens(arguments))

		// TerminateSession prints the error exactly as before; cobra must
		// not double-print it, and an execution failure must not dump usage.
		// A flag parse error, however, IS a usage problem, so it carries the
		// failing command's usage text with it.
		root.SilenceErrors = true
		root.SilenceUsage = true
		root.SetFlagErrorFunc(func(c *cobra.Command, flagErr error) error {
			return fmt.Errorf("%w\n%s", flagErr, c.UsageString())
		})

		err = root.Execute()

		// A typo can land in another branch of the tree, where cobra's
		// in-parent suggester cannot see the real command ("group list" vs
		// "groups list"): enrich unknown-command errors with a fuzzy match
		// over the full flat name and alias set.
		err = commands.WithCommandSuggestion(err, arguments)

	} else {

		if !models.IsAValidSBAccessFromUserInput(first) {
			TerminateSession(log, commands.WithCommandSuggestion(types.ErrUnknownCommand, arguments))
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
		typed := arguments
		arguments = append([]string{config.GetSSHCommand()}, args...)
		err = commands.BuildAndExecuteSBCommand(log, currentUser, arguments...)

		// The target had a valid access shape but matched none of the user's
		// grants — it may well have been a mistyped command name instead
		// ("grup info"). Suggest one when something is close, keeping the
		// refusal itself untouched. A matching grant never reaches this
		// branch, so legitimate hosts are unaffected.
		var noAccess *commands.NoMatchingAccessError
		if errors.As(err, &noAccess) {
			if suggestion, ok := commands.SuggestCommandLine(typed); ok {
				err = fmt.Errorf("%s — did you mean the command %q?", err.Error(), suggestion)
			}
		}
	}

	TerminateSession(log, err)

}

// TerminateSession is a global accessible function that terminates the session while saving the log one last time
func TerminateSession(log *models.Log, err error) {
	log.SessionEndDate = time.Now()
	// Best-effort final audit write; report a failure rather than dropping it.
	if saveErr := log.Save(); saveErr != nil {
		fmt.Fprintf(os.Stderr, "WARNING: unable to persist audit log: %s\n", saveErr)
	}

	statusCode, message := sessionExitStatus(err)
	if message != "" {
		fmt.Println(message)
	}

	os.Exit(statusCode)
}

// sessionExitStatus maps the dispatch result to the bastion's process exit
// code and the message to print, kept separate from TerminateSession so the
// mapping is unit-testable (TerminateSession calls os.Exit).
//
// The sentinel checks use errors.Is — the dispatch layers may wrap a sentinel
// (e.g. with a "did you mean" suggestion), which the historical == comparison
// silently missed. A *commands.ExitError carries the distant command's real
// exit code: it becomes the bastion's own exit code (like plain ssh), so
// scripts driving `ssh bastion host -- cmd` observe the remote status rather
// than a flat 1. Non-positive codes (the exec convention for a signal death)
// map to the generic failure code 1, which a process exit code cannot
// express more faithfully.
func sessionExitStatus(err error) (statusCode int, message string) {

	var remoteExit *commands.ExitError

	switch {
	case err == nil:
		return 0, ""
	case errors.Is(err, types.ErrCommandDisabled):
		return 126, "This command is disabled"
	case errors.Is(err, types.ErrMissingArguments):
		return 2, ""
	case errors.As(err, &remoteExit):
		statusCode = remoteExit.Code
		if statusCode <= 0 {
			statusCode = 1
		}
		return statusCode, fmt.Sprintf("Error while executing command: %s", err)
	default:
		return 1, fmt.Sprintf("Error while executing command: %s", err)
	}
}
