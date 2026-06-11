package commands

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/golgeek/sb/internal/config"
	"github.com/golgeek/sb/internal/helpers"
	"github.com/golgeek/sb/internal/models"
	"github.com/golgeek/sb/internal/types"
)

// logAuditWarn reports a best-effort audit-log persistence failure to stderr
// without failing the command. The authorization decision has already been made
// by the time these writes happen, so a logging hiccup must not change the
// command's outcome — but it must not be silently swallowed either.
func logAuditWarn(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: unable to persist audit log: %s\n", err)
	}
}

// IsReplicableCommand reports whether a command's execution persists a
// replication outbox entry. Local-administration commands (setup, backup,
// restore) never replicate.
func IsReplicableCommand(command string) bool {
	if command == "setup" || command == "backup" || command == "restore" {
		return false
	}
	return true
}

// BuildAndExecuteSBCommand builds the command through the trusted flat
// dispatch path and executes it. It is used by the front-end for the trusted
// commands (interactive, ttyrec, daemon) whose arguments it assembles itself,
// and by the interactive REPL's executor. The user-facing CLI goes through
// the cobra tree instead (BuildRootCommand); both paths enforce the same
// centralized authorization gate.
func BuildAndExecuteSBCommand(log *models.Log, user *models.User, args ...string) (err error) {

	bc, ct, err := BuildSBCommand(log, user, args...)
	if err != nil {
		return
	}

	// If replication is enabled, let's start by getting a handler on the replication database,
	// as it's crucial we check we can get it to push the replication data after the action
	dbHandler, err := models.GetReplicationGormDB(config.GetReplicationDatabasePath())
	if err != nil {
		return
	}

	// Call the execute method
	replicationData, cmdErr, err := bc.Execute(ct)
	if err != nil {
		return
	}

	// If replication is enabled, let's save the data to the replication database
	// This process also handles the PostExecute() part of the command
	if (config.GetReplicationQueueConfig().Enabled || config.GetTTYRecsOffloadingConfig().Enabled) &&
		IsReplicableCommand(args[0]) {

		var repl *models.Replication

		repl, err = models.NewReplicationEntry(args[0], replicationData)
		if err != nil {
			return
		}

		err = repl.Save(dbHandler)
		if err != nil {
			return
		}

	}

	return cmdErr
}

// buildArgumentsList constructs a map[string]string from the arguments lists.
// It is the legacy argument parser, still used by the trusted flat dispatch
// path; the cobra adapter's formatArguments preserves its contractual
// semantics (see arguments_characterization_test.go for the distinction
// between contract and legacy quirks).
func buildArgumentsList(trustedArguments map[string]Argument, args []string) (arguments map[string]string, rest []string, err error) {

	arguments = make(map[string]string)
	flaggedArgs := make(map[string]interface{})

	// We initialize a flagset to handle the command arguments,
	// this will allow us to parse arguments easily and to get the remaining arguments
	flagset := flag.NewFlagSet("_", flag.ContinueOnError)

	// The flag package displays a nice message if an undeclared flag is found... but that's not what we want!
	// Let's redirect output to an abandoned buffer
	var buf bytes.Buffer
	flagset.SetOutput(&buf)

	// Build the flags from our command definition
	for name, ca := range trustedArguments {
		if ca.Type == BOOL {
			flaggedArgs[name] = flagset.Bool(name, false, ca.Description)
		} else {
			flaggedArgs[name] = flagset.String(name, ca.DefaultValue, ca.Description)
		}
	}

	// Parse the user arguments. As noted above, undeclared flags are tolerated by
	// design (their output is sent to an abandoned buffer), so the parse error is
	// intentionally ignored and the remaining args are recovered via Args below.
	_ = flagset.Parse(args)

	// Get the remaining arguments for future use
	rest = flagset.Args()

	encounteredErrors := make([]string, 0)
	for name, ca := range trustedArguments {

		value, present := flaggedArgs[name]

		if ca.Type == BOOL {
			if *value.(*bool) {
				arguments[name] = "true"
			}
			continue
		}

		val := value.(*string)

		// If the argument is required, but absent or empty, we add an error
		if ca.Required && (!present || *val == "") {
			encounteredErrors = append(encounteredErrors, fmt.Sprintf("please provide required argument --%s", name))
			continue
		}

		if !present {
			continue
		}

		// If the argument is present and we have a definition of allowed values, we check them against the user input
		if len(ca.AllowedValues) > 0 {
			valueOK := false
			for _, allowedValue := range ca.AllowedValues {
				if *val == allowedValue {
					valueOK = true
					break
				}
			}
			if !valueOK {
				encounteredErrors = append(encounteredErrors, fmt.Sprintf("argument --%s's value should be from the list: %s", name, strings.Join(ca.AllowedValues, ", ")))
				continue
			}
		}

		arguments[name] = *val
	}
	if len(encounteredErrors) > 0 {
		return arguments, rest, fmt.Errorf("%s", strings.Join(encounteredErrors, " ; "))
	}

	return
}

// BuildSBCommand resolves a command through the flat registry (canonical name
// or alias, trusted commands included), parses its arguments with the legacy
// parser, and runs the centralized authorization gate plus the command's own
// Checks. It returns the constructed command instance and its populated
// execution context.
func BuildSBCommand(log *models.Log, user *models.User, args ...string) (bc Command, ct *Context, err error) {

	ct = &Context{
		Log:  log,
		User: user,
	}

	// Resolve the command spec through the flat registry
	spec, err := GetSpec(args[0])
	if err != nil {
		return bc, ct, err
	}
	bc = spec.New()

	// Log the command we used, as typed (canonical name or alias)
	logAuditWarn(log.SetCommand(args[0]))

	// Let's start by displaying the helper if user asked for it
	if len(args) > 1 && (args[1] == "help" || args[1] == "?") {
		DisplayHelpers(spec.Help, spec.Args)
		return bc, ct, types.ErrMissingArguments
	}

	// Then, let's build the arguments list (and display the helper if there are missing values)
	ct.FormattedArguments, ct.RawArguments, err = buildArgumentsList(spec.Args, args[1:])
	if err != nil {
		DisplayHelpers(spec.Help, spec.Args)
		return bc, ct, err
	}

	// If a group argument was provided, we will pass the group to the build function
	var grp *models.Group
	if _, ok := ct.FormattedArguments["group"]; ok {
		grp, err = models.GetGroup(ct.FormattedArguments["group"])
		if err != nil {
			return
		}
		ct.Group = grp
	}

	// Now, let's check the rights! This is the single authorization gate on
	// the dispatch path; the decision logic lives in authorize (authorize.go)
	// so it can be unit tested hermetically.
	err = newAuthorizer().authorize(user, spec.Rights, ct)
	if err != nil {
		return
	}

	// Call the check method
	err = bc.Checks(ct)
	if err != nil {
		logAuditWarn(log.SetAllowed(false))
		return
	}

	logAuditWarn(log.SetAllowed(true))

	return
}

// DisplayHelpers displays the helper for a command
func DisplayHelpers(helpers helpers.Helper, arguments map[string]Argument) {
	fmt.Printf("Usage      : %s\n", helpers.Usage)
	fmt.Printf("Description: %s\n", helpers.Description)
	if len(arguments) > 0 {
		fmt.Println("Options    :")

		// We'll display arguments in alphabetical order, required first, then optional
		// This is not a good algorithm!
		order := make([]string, 0, len(arguments))
		maxLength := 0
		for argumentName, argument := range arguments {
			if len(argumentName) > maxLength {
				maxLength = len(argumentName)
			}

			prefix := "Z"
			if argument.Required {
				prefix = "A"
			}
			order = append(order, fmt.Sprintf("%s::%s", prefix, argumentName))
		}
		sort.Strings(order)

		for _, a := range order {
			argumentName := a
			splitted := strings.Split(a, "::")
			if len(splitted) > 1 {
				argumentName = splitted[1]
			}
			argument := arguments[argumentName]
			needed := "[OPTIONAL]"
			if argument.Required {
				needed = "[REQUIRED]"
			}
			fmt.Printf("    --%-"+strconv.Itoa(maxLength)+"s: %s %s\n", argumentName, needed, argument.Description)
		}
	}
}
