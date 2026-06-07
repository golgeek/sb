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

var (
	commands map[string]Factory
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

func RegisterCommand(name string, command Factory) {
	if commands == nil {
		commands = make(map[string]Factory)
	}
	commands[name] = command
}

func GetCommands() map[string]Factory {
	return commands
}

// IsAPublicCommand returns true if the argument passed is a public trusted command
func IsAPublicCommand(command string) bool {

	if command == "interactive" || command == "ttyrec" || command == "daemon" {
		return false
	}

	_, _, _, _, err := GetCommand(command)

	return err == nil
}

func IsReplicableCommand(command string) bool {
	if command == "setup" || command == "backup" || command == "restore" {
		return false
	}
	return true
}

// BuildAndExecuteSBCommand builds the command
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

// buildArgumentsList constructs a map[string]string from the arguments lists
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

func GetCommand(commandName string) (cmd Command, rights models.Right, helpers helpers.Helper, args map[string]Argument, err error) {

	if commandBuilder, ok := commands[commandName]; ok {
		cmd, rights, helpers, args = commandBuilder()
		return
	}

	for _, commandFactory := range commands {
		cmd, rights, helpers, args = commandFactory()
		for _, alias := range helpers.Aliases {
			if alias == commandName {
				return
			}
		}
	}

	err = types.ErrUnknownCommand
	return
}

// BuildSBCommand builds the command
func BuildSBCommand(log *models.Log, user *models.User, args ...string) (bc Command, ct *Context, err error) {

	ct = &Context{
		Log:  log,
		User: user,
	}

	// Get the command
	bc, commandRightsLevel, commandHlprs, cas, err := GetCommand(args[0])
	if err != nil {
		return bc, ct, err
	}

	// Log the command we used
	logAuditWarn(log.SetCommand(args[0]))

	// Let's start by displaying the helper if user asked for it
	if len(args) > 1 && (args[1] == "help" || args[1] == "?") {
		DisplayHelpers(commandHlprs, cas)
		return bc, ct, types.ErrMissingArguments
	}

	// Then, let's build the arguments list (and display the helper if there are missing values)
	ct.FormattedArguments, ct.RawArguments, err = buildArgumentsList(cas, args[1:])
	if err != nil {
		DisplayHelpers(commandHlprs, cas)
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

	// Now, let's check the rights!
	switch commandRightsLevel {
	case models.Public:
		// Nothing to do
	case models.Private:

		// Private commands must be run by root
		if ct.User.User.Username != "root" {
			err = fmt.Errorf("only root user can execute this command on sb")
			return
		}

	case models.HasAccess:
		host, ok := ct.FormattedArguments["access"]
		if ok && host != "" {
			ba, err := models.BuildSBAccessFromUserInput(host)
			if err != nil {
				return bc, ct, err
			}

			logAuditWarn(log.SetTargetAccess(ba))

			ai, err := user.HasAccess(ba)
			if err != nil {
				return bc, ct, err
			}
			if !ai.Authorized {
				logAuditWarn(log.SetAllowed(false))
				return bc, ct, fmt.Errorf("user can't access the host %s", ba.ShortString())
			}

			ct.AI = ai
			ct.BA = ba
		}
	case models.GroupMember:
		if !user.IsMemberOfGroup(grp.Name) {
			logAuditWarn(log.SetAllowed(false))
			return bc, ct, fmt.Errorf("user is not a member of the group")
		}
	case models.GroupACLKeeper:
		if !user.IsACLKeeperOfGroup(grp.Name) {
			logAuditWarn(log.SetAllowed(false))
			return bc, ct, fmt.Errorf("user is not an ACL keeper of the group")
		}
	case models.GroupGateKeeper:
		if !user.IsGateKeeperOfGroup(grp.Name) {
			logAuditWarn(log.SetAllowed(false))
			return bc, ct, fmt.Errorf("user is not a gate keeper of the group")
		}
	case models.GroupOwner:
		if !user.IsOwnerOfGroup(grp.Name) && !user.IsOwnerOfGroup("owners") {
			logAuditWarn(log.SetAllowed(false))
			return bc, ct, fmt.Errorf("user is not an owner of the group")
		}
	case models.SBOwner:
		if !user.IsOwnerOfGroup("owners") && user.User.Uid != "0" {
			logAuditWarn(log.SetAllowed(false))
			return bc, ct, fmt.Errorf("user is not a sb owner")
		}
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
