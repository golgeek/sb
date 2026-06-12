package commands

import (
	"fmt"
	"strings"

	"github.com/golgeek/sb/internal/config"
	"github.com/golgeek/sb/internal/models"

	"github.com/spf13/cobra"
	"gorm.io/gorm"
)

// execDeps bundles the effectful dependencies of the cobra execution adapter
// so tests can substitute hermetic fakes (no DNS, no databases, no config
// reads). Production wiring is provided by defaultExecDeps; tests override
// individual fields through the with* build options.
type execDeps struct {
	// authorize enforces the command's rights level. Production: the
	// authorizer from authorize.go, which performs the audit writes and
	// populates ct.AI/ct.BA on the HasAccess path.
	authorize func(user *models.User, rights models.Right, ct *Context) error

	// resolveGroup resolves the --group argument into a models.Group.
	// Production: models.GetGroup, which reads /etc/group.
	resolveGroup func(name string) (*models.Group, error)

	// openReplicationDB returns a handle on the replication outbox database.
	// It is called before Execute even when replication is disabled,
	// preserving the long-standing contract that an action is not performed
	// if its outbox entry could not be persisted afterwards.
	openReplicationDB func() (*gorm.DB, error)

	// replicationOn reports whether an outbox entry must be persisted after a
	// successful Execute. Production: replication queue or TTYRec offloading
	// enabled in the configuration.
	replicationOn func() bool
}

// defaultExecDeps returns the production dependency wiring.
func defaultExecDeps() *execDeps {
	return &execDeps{
		authorize: func(user *models.User, rights models.Right, ct *Context) error {
			return newAuthorizer().authorize(user, rights, ct)
		},
		resolveGroup: models.GetGroup,
		openReplicationDB: func() (*gorm.DB, error) {
			return models.GetReplicationGormDB(config.GetReplicationDatabasePath())
		},
		replicationOn: func() bool {
			return config.GetReplicationQueueConfig().Enabled || config.GetTTYRecsOffloadingConfig().Enabled
		},
	}
}

// BuildOption customizes the execution adapter's dependencies. Options are
// unexported because they exist for in-package tests; production callers use
// BuildRootCommand as-is.
type BuildOption func(*execDeps)

// withAuthorizeFunc substitutes the authorization gate. Tests use it to
// observe and control authorization decisions hermetically.
func withAuthorizeFunc(f func(user *models.User, rights models.Right, ct *Context) error) BuildOption {
	return func(d *execDeps) { d.authorize = f }
}

// withGroupResolver substitutes --group resolution. Tests use it to avoid
// reading the system group database.
func withGroupResolver(f func(name string) (*models.Group, error)) BuildOption {
	return func(d *execDeps) { d.resolveGroup = f }
}

// withReplicationDBOpener substitutes the replication outbox handle. Tests
// use it to point at an in-memory database or to simulate an unavailable one.
func withReplicationDBOpener(f func() (*gorm.DB, error)) BuildOption {
	return func(d *execDeps) { d.openReplicationDB = f }
}

// withReplicationOn substitutes the "must persist an outbox entry" decision.
func withReplicationOn(f func() bool) BuildOption {
	return func(d *execDeps) { d.replicationOn = f }
}

// BuildRootCommand generates the user-facing cobra command tree from the
// registry's specs. The tree is a *view*: it owns parsing, help, and
// suggestions, while name resolution for programmatic dispatch (replication
// apply, the REPL completer, the front-end command check) stays on the flat
// registry index and never goes through cobra.
//
// Every non-trusted spec contributes one leaf; multi-word canonical names
// create intermediate parent commands on demand ("self totp emergency-codes
// generate" becomes self → totp → emergency-codes → generate). Trusted specs
// (interactive, ttyrec, daemon) are deliberately absent so they cannot be
// invoked, completed, or suggested through any user-facing path.
//
// The returned tree carries parsed-flag state after an Execute, so callers
// must build a fresh tree per execution (the REPL builds one per input line).
// log and user are attached to every leaf's execution context.
func (r *Registry) BuildRootCommand(log *models.Log, user *models.User, opts ...BuildOption) *cobra.Command {

	deps := defaultExecDeps()
	for _, opt := range opts {
		opt(deps)
	}

	root := &cobra.Command{
		Use:   fmt.Sprintf("%s [OPTION | HOST | COMMAND]", config.GetSBName()),
		Short: fmt.Sprintf("%s SSH bastion", config.GetSBName()),
		// The long help carries the bastion-specific entrypoint
		// documentation that no generated command listing can express: the
		// -i front-end option and the accepted host/alias target formats.
		Long: fmt.Sprintf(`%s SSH bastion.

Available options:
  -i: launch %s in interactive mode

Host supported formats:
  - full formats:
    - user@example.com:22
    - user@127.0.0.1:22
  - short formats*:
    - user@example.com : port will be retrieved from granted access
    - example.com:22   : user will be retrieved from granted access
    - example.com      : port and user will be retrieved from granted access
  - alias*:
    - user@alias:port  : host will be retrieved from granted access
    - user@alias       : host and port will be retrieved from granted access
    - alias:port       : host and user will be retrieved from granted access
    - alias            : host, user and port will be retrieved from granted access
* If multiple granted access match a short format or an alias,
user will be interactively prompted to choose the desired access`,
			config.GetSBName(), config.GetSBName()),
		// The bastion's forced-command entrypoint is not a shell environment
		// where generated shell-completion scripts make sense; keeping the
		// auto-generated "completion" command out also keeps the user-facing
		// surface identical to the flat registry's contents.
		CompletionOptions: cobra.CompletionOptions{DisableDefaultCmd: true},
	}

	for _, spec := range r.ordered {
		if spec.Trusted {
			continue
		}

		words := strings.Fields(spec.Name)
		parent := root
		for _, word := range words[:len(words)-1] {
			parent = findOrCreateChild(parent, word)
		}
		parent.AddCommand(newLeafCommand(spec, log, user, deps))
	}

	return root
}

// BuildRootCommand generates the cobra tree from the process-wide registry
// (see Registry.BuildRootCommand).
func BuildRootCommand(log *models.Log, user *models.User, opts ...BuildOption) *cobra.Command {
	return defaultRegistry.BuildRootCommand(log, user, opts...)
}

// findOrCreateChild returns parent's direct child command named word,
// creating an intermediate group command when none exists yet. Intermediate
// commands have no RunE: invoking them shows their subtree help, which is the
// desired behavior for a bare "sb self" or "sb group".
func findOrCreateChild(parent *cobra.Command, word string) *cobra.Command {
	for _, child := range parent.Commands() {
		if child.Name() == word {
			return child
		}
	}
	child := &cobra.Command{
		Use:   word,
		Short: fmt.Sprintf("%s commands", word),
	}
	parent.AddCommand(child)
	return child
}

// newLeafCommand builds the executable cobra command for a spec and wires the
// adapter between cobra's single-error RunE world and the sb Command
// interface (Checks + Execute returning a Result and an internal error).
//
// The execution pipeline mirrors the historical BuildSBCommand /
// BuildAndExecuteSBCommand pair exactly:
//
//	PersistentPreRunE: audit the command name, materialize the argument maps,
//	                   resolve --group, authorize, run Checks, audit outcome.
//	RunE:              acquire the replication outbox handle, Execute, persist
//	                   the outbox entry, surface the remote/internal error.
//
// One deliberate difference from the historical flow: the outbox entry's
// action is the canonical spec.Name, where the old dispatcher persisted
// args[0] as typed (possibly a camelCase alias). Peers resolve canonical
// names and aliases alike through the flat registry, so both forms stay
// compatible; persisting the canonical form normalizes new entries.
func newLeafCommand(spec *CommandSpec, log *models.Log, user *models.User, deps *execDeps) *cobra.Command {

	// ct and inst are shared between the pre-run hook and RunE of this single
	// leaf. A tree is built per execution, so they carry no cross-run state;
	// inst is the same Command instance across Checks and Execute because
	// commands are allowed to carry state from one phase to the other.
	ct := &Context{Log: log, User: user}
	var inst Command

	leaf := &cobra.Command{
		Use:   strings.Fields(spec.Name)[len(strings.Fields(spec.Name))-1],
		Short: spec.Help.Header,
		Long:  spec.Help.Description,
		// Positional arguments are legal on every command: anything after the
		// first positional token is handed to the command as RawArguments
		// (the historical Go-flag semantics, preserved by SetInterspersed
		// below).
		Args: cobra.ArbitraryArgs,
	}

	// Stop flag parsing at the first positional token, exactly like the
	// historical stdlib flag parser: everything from that token on lands in
	// args (and therefore in ct.RawArguments) untouched, which is the
	// passthrough contract commands rely on. Without this, pflag would parse
	// flag-looking tokens out of the trailing blob.
	leaf.Flags().SetInterspersed(false)

	// Declare the spec's flags. Unknown flags are a hard parse error under
	// pflag — a deliberate improvement over the historical parser, which
	// silently dropped the offending token (and could lose user input).
	for name, arg := range spec.Args {
		if arg.Type == BOOL {
			leaf.Flags().Bool(name, false, arg.Description)
		} else {
			leaf.Flags().String(name, arg.DefaultValue, arg.Description)
		}
	}

	leaf.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {

		// Audit which command runs under its canonical name (the historical
		// dispatcher logged the name as typed; canonical is normalized).
		logAuditWarn(log.SetCommand(spec.Name))

		formatted, err := formatArguments(spec.Args, cmd)
		if err != nil {
			return err
		}
		ct.FormattedArguments = formatted
		ct.RawArguments = args

		// Resolve the --group argument when one was provided. Group-scoped
		// commands declare it Required, so an empty value cannot reach this
		// point on those; for everything else an absent group stays nil and
		// authorize fails closed if the rights level needs one.
		if groupName, ok := formatted["group"]; ok && groupName != "" {
			grp, err := deps.resolveGroup(groupName)
			if err != nil {
				return err
			}
			ct.Group = grp
		}

		// The single authorization gate of the CLI path. The replication
		// apply path never runs this hook: it calls spec.New().Replicate
		// directly off the flat registry with already-authorized peer data.
		if err := deps.authorize(user, spec.Rights, ct); err != nil {
			return err
		}

		inst = spec.New()
		if err := inst.Checks(ct); err != nil {
			logAuditWarn(log.SetAllowed(false))
			return err
		}
		logAuditWarn(log.SetAllowed(true))

		return nil
	}

	leaf.RunE = func(cmd *cobra.Command, args []string) error {

		// Acquire the replication outbox handle before executing, even when
		// replication is disabled: an action whose outbox entry cannot be
		// persisted must not be performed at all.
		dbHandler, err := deps.openReplicationDB()
		if err != nil {
			return err
		}

		res, err := inst.Execute(ct)
		if err != nil {
			return err
		}

		if deps.replicationOn() && IsReplicableCommand(spec.Name) {
			repl, err := models.NewReplicationEntry(spec.Name, res.Repl)
			if err != nil {
				return err
			}
			if err := repl.Save(dbHandler); err != nil {
				return err
			}
		}

		// A remote exit is the distant command's failure, not an sb failure;
		// it propagates as a typed *ExitError so the top-level caller can map
		// it to the process exit code with errors.As. The nil check matters:
		// returning a nil *ExitError directly would yield a non-nil error
		// interface value.
		if res.RemoteExit != nil {
			return res.RemoteExit
		}
		return nil
	}

	return leaf
}

// formatArguments materializes ct.FormattedArguments from the parsed pflag
// values, preserving the historical buildArgumentsList semantics exactly:
//
//   - every declared string flag is present in the result, holding its
//     default value when the user did not pass it (commands test presence
//     with the two-value map read, so this shape is a behavioral contract);
//   - a BOOL flag is present (as "true") only when set;
//   - a Required string flag must end up non-empty;
//   - a flag with AllowedValues must hold one of them;
//   - all validation failures are joined into a single error with the
//     historical message wording, so user-visible errors do not change.
func formatArguments(specArgs map[string]Argument, cmd *cobra.Command) (map[string]string, error) {

	arguments := make(map[string]string)
	encounteredErrors := make([]string, 0)

	for name, arg := range specArgs {

		if arg.Type == BOOL {
			set, err := cmd.Flags().GetBool(name)
			if err != nil {
				return nil, err
			}
			if set {
				arguments[name] = "true"
			}
			continue
		}

		value, err := cmd.Flags().GetString(name)
		if err != nil {
			return nil, err
		}

		if arg.Required && value == "" {
			encounteredErrors = append(encounteredErrors, fmt.Sprintf("please provide required argument --%s", name))
			continue
		}

		if len(arg.AllowedValues) > 0 {
			valueOK := false
			for _, allowedValue := range arg.AllowedValues {
				if value == allowedValue {
					valueOK = true
					break
				}
			}
			if !valueOK {
				encounteredErrors = append(encounteredErrors, fmt.Sprintf("argument --%s's value should be from the list: %s", name, strings.Join(arg.AllowedValues, ", ")))
				continue
			}
		}

		arguments[name] = value
	}

	if len(encounteredErrors) > 0 {
		return arguments, fmt.Errorf("%s", strings.Join(encounteredErrors, " ; "))
	}

	return arguments, nil
}
