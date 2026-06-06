package commands

import (
	"github.com/golgeek/sb/internal/helpers"
	"github.com/golgeek/sb/internal/models"
)

// Command descibes the required functions of a sb command interface
type Command interface {
	Checks(ct *Context) error
	Execute(ct *Context) (models.ReplicationData, error, error)
	PostExecute(repl models.ReplicationData) error
	Replicate(repl models.ReplicationData) error
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

// Factory describes the command factory that registers the commands
type Factory func() (c Command, r models.Right, h helpers.Helper, args map[string]Argument)

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
