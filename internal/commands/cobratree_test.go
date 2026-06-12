package commands

import (
	"bytes"
	"errors"
	"fmt"
	osuser "os/user"
	"testing"

	"github.com/golgeek/sb/internal/models"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// fakeCommand is a scriptable Command implementation recording how the
// adapter drives it.
type fakeCommand struct {
	checksErr error
	execRes   Result // Result returned by Execute (replication data + remote exit)
	execErr   error  // internal sb error returned by Execute

	checksCalled bool
	execCalled   bool
	gotCt        *Context
}

func (f *fakeCommand) Checks(ct *Context) error {
	f.checksCalled = true
	f.gotCt = ct
	return f.checksErr
}

func (f *fakeCommand) Execute(ct *Context) (Result, error) {
	f.execCalled = true
	f.gotCt = ct
	return f.execRes, f.execErr
}

func (f *fakeCommand) PostExecute(repl models.ReplicationData) error { return nil }
func (f *fakeCommand) Replicate(repl models.ReplicationData) error   { return nil }

// hermeticDeps returns build options that disconnect the adapter from config,
// DNS and databases: authorization always passes, no group resolution, no
// replication persistence, and a nil (but successfully "opened") outbox
// handle. Individual tests override what they observe.
func hermeticDeps() []BuildOption {
	return []BuildOption{
		withAuthorizeFunc(func(user *models.User, rights models.Right, ct *Context) error { return nil }),
		withGroupResolver(func(name string) (*models.Group, error) {
			return nil, fmt.Errorf("unexpected group resolution for %q", name)
		}),
		withReplicationDBOpener(func() (*gorm.DB, error) { return nil, nil }),
		withReplicationOn(func() bool { return false }),
	}
}

// testRootUser returns a minimal user for adapter tests.
func testRootUser() *models.User {
	return &models.User{User: &osuser.User{Username: "alice", Uid: "1000"}}
}

// execute builds the tree from the registry and runs it on the given tokens,
// capturing cobra's output instead of spamming the test log.
func execute(r *Registry, tokens []string, opts ...BuildOption) (*models.Log, error) {
	log := &models.Log{Allowed: true}
	root := r.BuildRootCommand(log, testRootUser(), opts...)
	root.SilenceUsage = true
	root.SilenceErrors = true
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(tokens)
	return log, root.Execute()
}

// findCommand walks the cobra tree along the given words and returns the
// command found at the end, or nil.
func findCommand(root *cobra.Command, words ...string) *cobra.Command {
	current := root
	for _, w := range words {
		var next *cobra.Command
		for _, child := range current.Commands() {
			if child.Name() == w {
				next = child
				break
			}
		}
		if next == nil {
			return nil
		}
		current = next
	}
	return current
}

// TestBuildRootCommandTreeShape asserts the spec→tree generation: multi-word
// names create intermediate parents on demand, intermediate nodes are shared
// between commands with a common prefix, and trusted specs never appear.
func TestBuildRootCommandTreeShape(t *testing.T) {

	r := NewRegistry()
	r.MustRegister(specStub("self totp emergency-codes generate", nil, false))
	r.MustRegister(specStub("self totp enable", nil, false))
	r.MustRegister(specStub("self accesses list", nil, false))
	r.MustRegister(specStub("info", nil, false))
	r.MustRegister(specStub("ttyrec", nil, true))
	r.MustRegister(specStub("daemon", nil, true))
	r.MustRegister(specStub("interactive", nil, true))

	root := r.BuildRootCommand(&models.Log{}, testRootUser(), hermeticDeps()...)

	require.NotNil(t, findCommand(root, "self", "totp", "emergency-codes", "generate"), "deep leaf exists")
	require.NotNil(t, findCommand(root, "self", "totp", "enable"), "sibling leaf exists")
	require.NotNil(t, findCommand(root, "self", "accesses", "list"))
	require.NotNil(t, findCommand(root, "info"), "single-word leaf attaches to the root")

	// Intermediate nodes must be shared, not duplicated: "self" appears once.
	var selfCount int
	for _, child := range root.Commands() {
		if child.Name() == "self" {
			selfCount++
		}
	}
	require.Equal(t, 1, selfCount, "shared prefix words create exactly one intermediate command")

	// §1.7: trusted specs are excluded from the tree (and hence from help,
	// completion and suggestions); they stay reachable only via the flat map.
	require.Nil(t, findCommand(root, "ttyrec"), "trusted ttyrec must not be in the tree")
	require.Nil(t, findCommand(root, "daemon"), "trusted daemon must not be in the tree")
	require.Nil(t, findCommand(root, "interactive"), "trusted interactive must not be in the tree")
}

// TestAdapterArgumentHandling asserts the adapter materializes
// ct.FormattedArguments / ct.RawArguments with the historical semantics.
func TestAdapterArgumentHandling(t *testing.T) {

	newRegistry := func(fake *fakeCommand) *Registry {
		r := NewRegistry()
		spec := specStub("thing do", nil, false)
		spec.Args = map[string]Argument{
			"host":  {Required: true, Description: "target host"},
			"port":  {DefaultValue: "22", Description: "target port"},
			"algo":  {AllowedValues: []string{"rsa", "ed25519"}, DefaultValue: "rsa"},
			"force": {Type: BOOL, Description: "force"},
		}
		spec.New = func() Command { return fake }
		r.MustRegister(spec)
		return r
	}

	t.Run("declared strings always present, bool only when set", func(t *testing.T) {
		fake := &fakeCommand{}
		_, err := execute(newRegistry(fake), []string{"thing", "do", "--host", "h1"}, hermeticDeps()...)
		require.NoError(t, err)
		require.True(t, fake.execCalled)
		require.Equal(t, map[string]string{
			"host": "h1",
			"port": "22", // default materializes even when not passed
			"algo": "rsa",
		}, fake.gotCt.FormattedArguments)
		_, boolPresent := fake.gotCt.FormattedArguments["force"]
		require.False(t, boolPresent, "unset BOOL must be absent from the map")
	})

	t.Run("bool present as true when set", func(t *testing.T) {
		fake := &fakeCommand{}
		_, err := execute(newRegistry(fake), []string{"thing", "do", "--host", "h1", "--force"}, hermeticDeps()...)
		require.NoError(t, err)
		require.Equal(t, "true", fake.gotCt.FormattedArguments["force"])
	})

	t.Run("missing required argument fails with the historical message", func(t *testing.T) {
		fake := &fakeCommand{}
		_, err := execute(newRegistry(fake), []string{"thing", "do"}, hermeticDeps()...)
		require.EqualError(t, err, "please provide required argument --host")
		require.False(t, fake.checksCalled, "Checks must not run on invalid arguments")
		require.False(t, fake.execCalled, "Execute must not run on invalid arguments")
	})

	t.Run("value outside AllowedValues fails with the historical message", func(t *testing.T) {
		fake := &fakeCommand{}
		_, err := execute(newRegistry(fake), []string{"thing", "do", "--host", "h1", "--algo", "dsa"}, hermeticDeps()...)
		require.EqualError(t, err, "argument --algo's value should be from the list: rsa, ed25519")
		require.False(t, fake.execCalled)
	})

	t.Run("trailing blob after first positional reaches RawArguments untouched", func(t *testing.T) {
		// SetInterspersed(false) preserves the historical Go-flag semantics:
		// parsing stops at the first positional token, so flag-looking tokens
		// in a trailing remote-command blob are forwarded, not parsed.
		fake := &fakeCommand{}
		_, err := execute(newRegistry(fake), []string{"thing", "do", "--host", "h1", "uptime", "-a", "--weird"}, hermeticDeps()...)
		require.NoError(t, err)
		require.Equal(t, []string{"uptime", "-a", "--weird"}, fake.gotCt.RawArguments)
	})

	t.Run("explicit -- terminator reaches RawArguments untouched", func(t *testing.T) {
		fake := &fakeCommand{}
		_, err := execute(newRegistry(fake), []string{"thing", "do", "--host", "h1", "--", "uptime", "-a"}, hermeticDeps()...)
		require.NoError(t, err)
		require.Equal(t, []string{"uptime", "-a"}, fake.gotCt.RawArguments)
	})

	t.Run("unknown flag before any positional is a hard error", func(t *testing.T) {
		// Deliberate difference from the historical parser, which silently
		// dropped the unknown token (losing user input): pflag refuses it.
		fake := &fakeCommand{}
		_, err := execute(newRegistry(fake), []string{"thing", "do", "--host", "h1", "--bogus"}, hermeticDeps()...)
		require.ErrorContains(t, err, "unknown flag: --bogus")
		require.False(t, fake.execCalled)
	})
}

// TestAdapterPipeline asserts the ordering and error-propagation contract of
// the PersistentPreRunE/RunE pair: authorization gates Checks, Checks gates
// Execute, the outbox handle is acquired before Execute, and the internal
// error and the Result's remote exit keep their distinct roles.
func TestAdapterPipeline(t *testing.T) {

	registryWith := func(fake *fakeCommand, rights models.Right) *Registry {
		r := NewRegistry()
		spec := specStub("thing do", nil, false)
		spec.Rights = rights
		spec.New = func() Command { return fake }
		r.MustRegister(spec)
		return r
	}

	t.Run("authorize receives the spec's rights level and gates execution", func(t *testing.T) {
		fake := &fakeCommand{}
		var gotRights models.Right
		opts := append(hermeticDeps(), withAuthorizeFunc(func(user *models.User, rights models.Right, ct *Context) error {
			gotRights = rights
			return fmt.Errorf("computer says no")
		}))
		_, err := execute(registryWith(fake, models.SBOwner), []string{"thing", "do"}, opts...)
		require.EqualError(t, err, "computer says no")
		require.Equal(t, models.SBOwner, gotRights)
		require.False(t, fake.checksCalled, "a refusal must stop the pipeline before Checks")
		require.False(t, fake.execCalled, "a refusal must stop the pipeline before Execute")
	})

	t.Run("Checks failure marks the audit log refused and stops Execute", func(t *testing.T) {
		fake := &fakeCommand{checksErr: fmt.Errorf("bad input")}
		log, err := execute(registryWith(fake, models.Public), []string{"thing", "do"}, hermeticDeps()...)
		require.EqualError(t, err, "bad input")
		require.False(t, fake.execCalled)
		require.False(t, log.Allowed, "failed Checks must flip the audit log to not-allowed")
	})

	t.Run("successful run marks the audit log allowed and records the canonical name", func(t *testing.T) {
		fake := &fakeCommand{}
		log, err := execute(registryWith(fake, models.Public), []string{"thing", "do"}, hermeticDeps()...)
		require.NoError(t, err)
		require.True(t, log.Allowed)
		require.Equal(t, "thing do", log.Command, "the audit log records the canonical name")
	})

	t.Run("unavailable outbox handle prevents execution", func(t *testing.T) {
		fake := &fakeCommand{}
		opts := append(hermeticDeps(), withReplicationDBOpener(func() (*gorm.DB, error) {
			return nil, fmt.Errorf("outbox unavailable")
		}))
		_, err := execute(registryWith(fake, models.Public), []string{"thing", "do"}, opts...)
		require.EqualError(t, err, "outbox unavailable")
		require.False(t, fake.execCalled, "an action whose outbox entry cannot be persisted must not run")
	})

	t.Run("internal error wins over the remote exit", func(t *testing.T) {
		fake := &fakeCommand{
			execErr: fmt.Errorf("internal"),
			execRes: Result{RemoteExit: &ExitError{Code: 1, Err: fmt.Errorf("remote exit 1")}},
		}
		_, err := execute(registryWith(fake, models.Public), []string{"thing", "do"}, hermeticDeps()...)
		require.EqualError(t, err, "internal")
		var exitErr *ExitError
		require.False(t, errors.As(err, &exitErr), "an internal failure must not surface as a remote exit")
	})

	t.Run("remote exit propagates as a typed *ExitError when there is no internal error", func(t *testing.T) {
		fake := &fakeCommand{
			execRes: Result{RemoteExit: &ExitError{Code: 3, Err: fmt.Errorf("remote exit 3")}},
		}
		_, err := execute(registryWith(fake, models.Public), []string{"thing", "do"}, hermeticDeps()...)
		require.EqualError(t, err, "remote exit 3")
		// The typed exit must survive the adapter so the top-level caller can
		// recover the distant command's exit code with errors.As.
		var exitErr *ExitError
		require.ErrorAs(t, err, &exitErr)
		require.Equal(t, 3, exitErr.Code)
	})

	t.Run("a successful execution returns a nil error, not a typed nil", func(t *testing.T) {
		// The adapter must not return Result.RemoteExit unconditionally: a nil
		// *ExitError stored in the error interface would be non-nil and turn
		// every success into a failure.
		fake := &fakeCommand{}
		_, err := execute(registryWith(fake, models.Public), []string{"thing", "do"}, hermeticDeps()...)
		require.NoError(t, err)
	})

	t.Run("group argument resolves before authorization", func(t *testing.T) {
		fake := &fakeCommand{}
		r := NewRegistry()
		spec := specStub("thing do", nil, false)
		spec.Rights = models.GroupOwner
		spec.Args = map[string]Argument{"group": {Required: true}}
		spec.New = func() Command { return fake }
		r.MustRegister(spec)

		team := &models.Group{Name: "team"}
		var authorizedGroup *models.Group
		opts := []BuildOption{
			withGroupResolver(func(name string) (*models.Group, error) {
				require.Equal(t, "team", name)
				return team, nil
			}),
			withAuthorizeFunc(func(user *models.User, rights models.Right, ct *Context) error {
				authorizedGroup = ct.Group
				return nil
			}),
			withReplicationDBOpener(func() (*gorm.DB, error) { return nil, nil }),
			withReplicationOn(func() bool { return false }),
		}
		_, err := execute(r, []string{"thing", "do", "--group", "team"}, opts...)
		require.NoError(t, err)
		require.Same(t, team, authorizedGroup, "authorize must see the resolved group on the context")
	})
}

// TestAdapterReplicationOutbox asserts a successful execution persists an
// outbox entry carrying the canonical command name — the §1.1 normalization:
// the historical dispatcher persisted args[0] as typed (possibly an alias),
// the adapter always persists the canonical name.
func TestAdapterReplicationOutbox(t *testing.T) {

	db, err := models.GetReplicationGormDB(":memory:")
	require.NoError(t, err)

	fake := &fakeCommand{execRes: Result{Repl: models.ReplicationData{"account": "alice"}}}
	r := NewRegistry()
	spec := specStub("thing do", []string{"thingDo"}, false)
	spec.New = func() Command { return fake }
	r.MustRegister(spec)

	opts := []BuildOption{
		withAuthorizeFunc(func(user *models.User, rights models.Right, ct *Context) error { return nil }),
		withReplicationDBOpener(func() (*gorm.DB, error) { return db, nil }),
		withReplicationOn(func() bool { return true }),
	}
	_, err = execute(r, []string{"thing", "do"}, opts...)
	require.NoError(t, err)

	var entries []models.Replication
	require.NoError(t, db.Find(&entries).Error)
	require.Len(t, entries, 1, "exactly one outbox entry must be persisted")
	require.Equal(t, "thing do", entries[0].Action, "the outbox action is the canonical name")

	// The persisted payload is encrypted for transport; decrypting it brings
	// back the replication data the command returned.
	data, err := models.DecryptReplicationData(entries[0].Data)
	require.NoError(t, err)
	require.Equal(t, "alice", data["account"])
}

// TestAdapterReplicationSkipsNonReplicable asserts the setup/backup/restore
// carve-out carries over to the adapter.
func TestAdapterReplicationSkipsNonReplicable(t *testing.T) {

	db, err := models.GetReplicationGormDB(":memory:")
	require.NoError(t, err)

	fake := &fakeCommand{}
	r := NewRegistry()
	spec := specStub("backup", nil, false)
	spec.New = func() Command { return fake }
	r.MustRegister(spec)

	opts := []BuildOption{
		withAuthorizeFunc(func(user *models.User, rights models.Right, ct *Context) error { return nil }),
		withReplicationDBOpener(func() (*gorm.DB, error) { return db, nil }),
		withReplicationOn(func() bool { return true }),
	}
	_, err = execute(r, []string{"backup"}, opts...)
	require.NoError(t, err)

	var count int64
	require.NoError(t, db.Model(&models.Replication{}).Count(&count).Error)
	require.Zero(t, count, "backup must never write a replication outbox entry")
}

// TestTrustedCommandsUnreachableThroughTree asserts executing a trusted
// command name through the tree fails as an unknown command — the guarantee
// the interactive REPL relies on, since its executor feeds user lines
// straight into a fresh tree.
func TestTrustedCommandsUnreachableThroughTree(t *testing.T) {

	r := NewRegistry()
	r.MustRegister(specStub("info", nil, false))
	r.MustRegister(specStub("ttyrec", nil, true))
	r.MustRegister(specStub("daemon", nil, true))
	r.MustRegister(specStub("interactive", nil, true))

	for _, trusted := range []string{"ttyrec", "daemon", "interactive"} {
		_, err := execute(r, []string{trusted, "--client", "ssh"}, hermeticDeps()...)
		require.Error(t, err, "trusted command %q must not execute through the tree", trusted)
		require.Contains(t, err.Error(), "unknown command", "trusted %q must look like an unknown command", trusted)
	}
}

// TestIntermediateCommandShowsHelp asserts invoking a bare intermediate word
// (e.g. "sb self") displays its subtree help instead of failing.
func TestIntermediateCommandShowsHelp(t *testing.T) {

	r := NewRegistry()
	r.MustRegister(specStub("self accesses list", nil, false))

	log := &models.Log{}
	root := r.BuildRootCommand(log, testRootUser(), hermeticDeps()...)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"self"})
	require.NoError(t, root.Execute())
	require.Contains(t, out.String(), "accesses", "subtree help lists the child commands")
}
