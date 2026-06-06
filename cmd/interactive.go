package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/golgeek/sb/internal/commands"
	"github.com/golgeek/sb/internal/config"
	"github.com/golgeek/sb/internal/helpers"
	"github.com/golgeek/sb/internal/models"
	"github.com/golgeek/sb/internal/types"

	prompt "github.com/c-bata/go-prompt"
)

// Interactive describes the interactive command
type Interactive struct {
	Context *commands.Context
}

func init() {
	commands.RegisterCommand("interactive", func() (c commands.Command, r models.Right, helper helpers.Helper, args map[string]commands.Argument) {
		return new(Interactive), models.Public, helpers.Helper{
				Header:      "launch sb in interactive mode",
				Usage:       "interactive",
				Description: "launch sb in interactive mode",
			}, map[string]commands.Argument{
				"client": {
					Required:    true,
					Description: "The client to use SSH or MOSH",
				},
				"client-arguments": {
					Required: false,
				},
			}
	})
}

// Checks checks whether or not the user can execute this method
func (c *Interactive) Checks(ct *commands.Context) error {
	// No specific rights needed but a sb account
	return nil
}

// Execute executes the command
func (c *Interactive) Execute(ct *commands.Context) (repl models.ReplicationData, cmdError error, err error) {

	c.Context = ct

	// Special case, we need to launch a mosh-server that will be calling ourselves
	if ct.FormattedArguments["client"] == "mosh" {

		fmt.Printf("Launched interactive command with mosh client...\n")

		moshCommand, errMosh := c.buildMOSHCommand(ct)
		if errMosh != nil {
			err = errMosh
			return
		}

		moshCommand = append(moshCommand, config.GetBinaryPath(), "-i")

		cmd := exec.Command(moshCommand[0], moshCommand[1:]...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		err = cmd.Start()
		if err != nil {
			return
		}

		err = cmd.Wait()
		if err != nil {
			var ok bool
			cmdError, ok = err.(*exec.ExitError)
			if !ok {
				return
			}
			err = nil
		}

		return

	}

	// Launch our prompt
	p := prompt.New(c.promptExecutor, c.promptCompleter,
		prompt.OptionTitle("sb prompt"),
		prompt.OptionPrefix(c.promptPrefix()),
		prompt.OptionPrefixTextColor(prompt.DarkBlue),
		prompt.OptionMaxSuggestion(20),
	)

	p.Run()

	return
}

func (c *Interactive) PostExecute(repl models.ReplicationData) (err error) {
	return
}

func (c *Interactive) Replicate(repl models.ReplicationData) (err error) {
	return
}

func (c *Interactive) buildMOSHCommand(ct *commands.Context) (cmd []string, err error) {

	moshPath, err := exec.LookPath("mosh-server")
	if err != nil {
		fmt.Printf("Unable to find ssh on system: %s\n", err)
		return
	}

	moshArguments := strings.Split(ct.FormattedArguments["client-arguments"], ",")
	moshArguments = append(moshArguments, "-p", config.GetMOSHPortsRange(), "--")

	cmd = []string{moshPath, "new"}
	cmd = append(cmd, moshArguments...)

	return
}

func (c *Interactive) promptPrefix() string {
	return fmt.Sprintf("%s@%s$ ", c.Context.User.User.Username, config.GetSBName())
}

func (c *Interactive) promptExecutor(command string) {

	// Check that user entered somthing
	if command == "" {
		return
	}

	// We read from input
	commandLine, err := helpers.ParseCommandLine(command)
	if err != nil {
		fmt.Printf("error: %s", err)
		return
	}

	commandLine = helpers.RegroupCommandArguments(commandLine)

	if commandLine[0] == "exit" {
		os.Exit(0)
	}

	if !commands.IsAPublicCommand(commandLine[0]) {
		fmt.Println("command not found")
		return
	}

	log := models.NewLog(c.Context.User.User.Username, []string{config.GetGlobalDatabasePath(), c.Context.User.GetLocalLogDatabasePath()}, commandLine)
	err = commands.BuildAndExecuteSBCommand(log, c.Context.User, commandLine...)
	if err != nil && err != types.ErrMissingArguments {
		fmt.Printf("Error while executing command: %s\n", err)
	}
	log.SessionEndDate = time.Now()
	log.Save()
}

func (c *Interactive) promptCompleter(d prompt.Document) (s []prompt.Suggest) {

	// No completion if no characters
	if d.TextBeforeCursor() == "" {
		return s
	}

	// Do we have a command typed ?
	// We check if line begins with a known command and a space
	for commandName, commandFactory := range commands.GetCommands() {
		if commands.IsAPublicCommand(commandName) && strings.HasPrefix(d.CurrentLine(), fmt.Sprintf("%s ", commandName)) {

			// We have a known command
			// We have to give the argument list to user
			_, _, _, args := commandFactory()

			for argName, arg := range args {
				if !strings.Contains(d.CurrentLine(), fmt.Sprintf("--%s", argName)) {
					argDesc := arg.Description
					argDesc = strings.ReplaceAll(argDesc, "\t", " ")
					argDesc = strings.ReplaceAll(argDesc, "\n", " ")
					s = append(s, prompt.Suggest{Text: fmt.Sprintf("--%s", argName), Description: argDesc})
				}
			}

			return prompt.FilterHasPrefix(s, d.GetWordBeforeCursor(), true)
		}
	}

	// Let's give the completion tu user
	for commandName, commandFactory := range commands.GetCommands() {
		if commands.IsAPublicCommand(commandName) && strings.HasPrefix(commandName, d.TextBeforeCursor()) {
			_, _, helper, _ := commandFactory()
			s = append(s, prompt.Suggest{Text: commandName, Description: helper.Description})
		}
	}

	sort.Slice(s, func(i, j int) bool {
		return s[i].Text < s[j].Text
	})

	return prompt.FilterHasPrefix(s, d.TextBeforeCursor(), true)
}
