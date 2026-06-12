package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/golgeek/sb/internal/commands"
	"github.com/golgeek/sb/internal/completer"
	"github.com/golgeek/sb/internal/config"
	"github.com/golgeek/sb/internal/helpers"
	"github.com/golgeek/sb/internal/models"
	"github.com/golgeek/sb/internal/types"

	prompt "github.com/elk-language/go-prompt"
	istrings "github.com/elk-language/go-prompt/strings"
)

// Interactive describes the interactive command
type Interactive struct {
	Context *commands.Context
}

func init() {
	commands.Register(commands.CommandSpec{
		Name:   "interactive",
		Rights: models.Public,
		Help: helpers.Helper{
			Header:      "launch sb in interactive mode",
			Usage:       "interactive",
			Description: "launch sb in interactive mode",
		},
		Args: map[string]commands.Argument{
			"client": {
				Required:    true,
				Description: "The client to use SSH or MOSH",
			},
			"client-arguments": {
				Required: false,
			},
		},
		Trusted: true,
		New:     func() commands.Command { return new(Interactive) },
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
	p := prompt.New(
		c.promptExecutor,
		prompt.WithCompleter(c.promptCompleter),
		prompt.WithTitle("sb prompt"),
		prompt.WithPrefix(c.promptPrefix()),
		prompt.WithPrefixTextColor(prompt.DarkBlue),
		prompt.WithMaxSuggestion(20),
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

	cmd = make([]string, 0, 2+len(moshArguments))
	cmd = append(cmd, moshPath, "new")
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
	if len(commandLine) == 0 {
		return
	}

	if commandLine[0] == "exit" {
		os.Exit(0)
	}

	log := models.NewLog(c.Context.User.User.Username, []string{config.GetGlobalDatabasePath(), c.Context.User.GetLocalLogDatabasePath()}, commandLine)

	// Execute through a FRESH cobra tree: cobra retains parsed-flag state
	// between Execute calls, and the REPL is the one place a single process
	// runs many commands, so a stale tree would leak flag values across
	// lines. The tree only contains non-trusted specs, so interactive,
	// ttyrec and daemon resolve to "unknown command" here exactly as before.
	root := commands.BuildRootCommand(log, c.Context.User)
	root.SetArgs(commands.CanonicalTokens(commandLine))

	// The REPL prints errors itself and must not exit on them; suppress
	// cobra's own error printing and the usage dump on execution failures.
	root.SilenceErrors = true
	root.SilenceUsage = true

	err = root.Execute()
	err = commands.WithCommandSuggestion(err, commandLine)
	if err != nil && err != types.ErrMissingArguments {
		fmt.Printf("Error while executing command: %s\n", err)
	}
	log.SessionEndDate = time.Now()
	// Best-effort final audit write; report a failure rather than dropping it.
	if err := log.Save(); err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: unable to persist audit log: %s\n", err)
	}
}

func (c *Interactive) promptCompleter(d prompt.Document) ([]prompt.Suggest, istrings.RuneNumber, istrings.RuneNumber) {

	// The completion logic itself lives in the library-agnostic completer
	// package; this method only adapts the prompt library's document to that
	// package's inputs and its suggestions back to the library's type.
	suggestions := completer.Suggest(
		publicCommands(),
		d.CurrentLine(),
		d.TextBeforeCursor(),
		d.GetWordBeforeCursor(),
	)

	s := make([]prompt.Suggest, 0, len(suggestions))
	for _, suggestion := range suggestions {
		s = append(s, prompt.Suggest{Text: suggestion.Text, Description: suggestion.Description})
	}

	// elk-language/go-prompt replaces the rune span [startChar, endChar) with
	// the accepted suggestion. Mirror the previous library's behavior by
	// replacing the word currently being typed immediately before the cursor.
	endChar := d.CurrentRuneIndex()
	startChar := endChar - istrings.RuneCountInString(d.GetWordBeforeCursor())

	return s, startChar, endChar
}

// publicCommands gathers the user-invocable commands from the registry into
// the library-agnostic representation the completer package expects. Trusted
// specs are excluded so the completer never advertises interactive, ttyrec or
// daemon.
func publicCommands() []completer.Command {

	var cmds []completer.Command

	for _, spec := range commands.Specs() {
		if spec.Trusted {
			continue
		}

		var commandArgs []completer.Arg
		for argName, arg := range spec.Args {
			commandArgs = append(commandArgs, completer.Arg{Name: argName, Description: arg.Description})
		}

		cmds = append(cmds, completer.Command{
			Name:        spec.Name,
			Description: spec.Help.Description,
			Args:        commandArgs,
		})
	}

	return cmds
}
