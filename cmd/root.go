package cmd

import (
	"github.com/golgeek/sb/internal/commands"
	"github.com/golgeek/sb/internal/models"

	"github.com/spf13/cobra"
)

// BuildRootCommand returns the user-facing cobra command tree generated from
// the command specs registered by this package's init functions. Calling it
// from main is also what guarantees those init functions ran — it replaces
// the old LoadCommands() empty function, whose only purpose was to trigger
// the package's import side effects.
//
// The returned tree carries parsed-flag state after an execution, so callers
// must build a fresh tree per execution.
func BuildRootCommand(log *models.Log, user *models.User) *cobra.Command {
	return commands.BuildRootCommand(log, user)
}
