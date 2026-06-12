package commands

import (
	"fmt"

	"github.com/golgeek/sb/internal/models"
)

// Command describes the required functions of a sb command interface.
//
// The lifecycle of a command on the CLI dispatch path is Checks → Execute;
// PostExecute and Replicate run later on the daemon's replication paths, fed
// with the ReplicationData that Execute produced (Result.Repl, persisted in
// the replication outbox).
type Command interface {
	Checks(ct *Context) error
	Execute(ct *Context) (Result, error)
	PostExecute(repl models.ReplicationData) error
	Replicate(repl models.ReplicationData) error
}

// Result is the outcome of a successful command execution.
//
// It separates the two things a command can produce besides an internal sb
// error: the data to persist in the replication outbox (Repl) and the exit
// status of a distant or wrapped process (RemoteExit). Execute therefore
// returns (Result, error) where the single error always means "sb itself
// failed"; a remote command failing is not an sb failure and travels in
// Result instead. This replaces the historical (ReplicationData, cmdError,
// err) triple whose two error returns were routinely confused.
type Result struct {
	// Repl is the data persisted in the replication outbox after a
	// successful execution and later fed to PostExecute/Replicate on the
	// daemon paths. Nil when the command has nothing to replicate.
	Repl models.ReplicationData

	// RemoteExit is non-nil only when the distant or wrapped process the
	// command drove (egress ssh for ttyrec/scp, mosh-server for interactive)
	// terminated unsuccessfully. The dispatch adapters propagate it as the
	// execution error so main can map it to the bastion's process exit code.
	RemoteExit *ExitError
}

// ExitError reports the unsuccessful termination of the distant or wrapped
// process a command drove. It is the typed form of the historical "cmdError"
// return: callers detect it with errors.As and map Code to the bastion's own
// process exit code, so a script driving `ssh bastion host -- cmd` observes
// the distant command's real exit status.
type ExitError struct {
	// Code is the process's exit code. It is -1 when the process was
	// terminated by a signal rather than exiting (the exec.ExitError
	// convention); consumers map non-positive codes to a generic failure.
	Code int

	// Err is the underlying cause — typically the *exec.ExitError from
	// Wait, possibly wrapped with command-specific context. It must be
	// non-nil; Error and Unwrap delegate to it.
	Err error
}

// Error returns the underlying cause's message, so user-visible output keeps
// the exact wording commands historically produced (e.g. "exit status 3" or
// "failed to execute command on distant host: exit status 3").
func (e *ExitError) Error() string {
	if e.Err == nil {
		// Defensive: a well-formed ExitError always carries its cause.
		return fmt.Sprintf("exit status %d", e.Code)
	}
	return e.Err.Error()
}

// Unwrap exposes the underlying cause to errors.Is/errors.As chains.
func (e *ExitError) Unwrap() error {
	return e.Err
}

type Context struct {
	User               *models.User
	Log                *models.Log
	Group              *models.Group
	AI                 *models.Info
	BA                 *models.Access
	FormattedArguments map[string]string
	RawArguments       []string
}

// Argument describes the basic properties of a sb command argument
type Argument struct {
	Required      bool
	Description   string
	AllowedValues []string
	DefaultValue  string
	Type          ArgumentType
}

// ArgumentType describes the type of the argument
type ArgumentType int32

const (
	STRING ArgumentType = iota
	BOOL
)
