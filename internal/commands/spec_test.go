package commands

import (
	"testing"

	"github.com/golgeek/sb/internal/helpers"
	"github.com/golgeek/sb/internal/models"
	"github.com/golgeek/sb/internal/types"

	"github.com/stretchr/testify/require"
)

// specStub returns a minimal valid spec for registry tests.
func specStub(name string, aliases []string, trusted bool) CommandSpec {
	return CommandSpec{
		Name:    name,
		Aliases: aliases,
		Rights:  models.Public,
		Help:    helpers.Helper{Header: name},
		Trusted: trusted,
		New:     func() Command { return &fakeCommand{} },
	}
}

// TestRegistryRegisterValidation covers the fail-closed registration rules:
// every malformed or ambiguous spec must be refused so the first-word
// dispatch always has exactly one meaning per token.
func TestRegistryRegisterValidation(t *testing.T) {

	t.Run("empty name refused", func(t *testing.T) {
		r := NewRegistry()
		require.ErrorContains(t, r.Register(specStub("", nil, false)), "empty name")
	})

	t.Run("nil constructor refused", func(t *testing.T) {
		r := NewRegistry()
		spec := specStub("x", nil, false)
		spec.New = nil
		require.ErrorContains(t, r.Register(spec), "nil constructor")
	})

	t.Run("duplicate canonical name refused", func(t *testing.T) {
		r := NewRegistry()
		require.NoError(t, r.Register(specStub("self accesses list", nil, false)))
		require.ErrorContains(t, r.Register(specStub("self accesses list", nil, false)), "already registered")
	})

	t.Run("duplicate alias refused", func(t *testing.T) {
		r := NewRegistry()
		require.NoError(t, r.Register(specStub("self accesses list", []string{"selfListAccesses"}, false)))
		require.ErrorContains(t, r.Register(specStub("other", []string{"selfListAccesses"}, false)), "already registered")
	})

	t.Run("multi-word alias refused", func(t *testing.T) {
		r := NewRegistry()
		require.ErrorContains(t, r.Register(specStub("x", []string{"two words"}, false)), "must be a single word")
	})

	t.Run("alias colliding with another command's first word refused", func(t *testing.T) {
		r := NewRegistry()
		require.NoError(t, r.Register(specStub("group info", nil, false)))
		require.ErrorContains(t, r.Register(specStub("x", []string{"group"}, false)), "collides with the first word")
	})

	t.Run("first word colliding with an existing alias refused", func(t *testing.T) {
		r := NewRegistry()
		require.NoError(t, r.Register(specStub("self accesses list", []string{"shortcut"}, false)))
		require.ErrorContains(t, r.Register(specStub("shortcut things do", nil, false)), "already an alias")
	})

	t.Run("MustRegister panics on error", func(t *testing.T) {
		r := NewRegistry()
		require.Panics(t, func() { r.MustRegister(specStub("", nil, false)) })
	})
}

// TestRegistryGet covers the flat-index resolution contract: canonical names
// and aliases both resolve (this is what the replication-apply path depends
// on), unknown names return types.ErrUnknownCommand.
func TestRegistryGet(t *testing.T) {

	r := NewRegistry()
	require.NoError(t, r.Register(specStub("self totp emergency-codes generate", []string{"selfGenerateTOTPCodes"}, false)))

	byName, err := r.Get("self totp emergency-codes generate")
	require.NoError(t, err)
	byAlias, err2 := r.Get("selfGenerateTOTPCodes")
	require.NoError(t, err2)
	require.Same(t, byName, byAlias, "canonical name and alias must resolve to the same spec")

	_, err = r.Get("nope")
	require.ErrorIs(t, err, types.ErrUnknownCommand)
}

// TestRegistrySpecsSorted asserts Specs() returns a deterministic, sorted
// view regardless of registration order, so every generated view (tree, help,
// completion) is stable.
func TestRegistrySpecsSorted(t *testing.T) {

	r := NewRegistry()
	require.NoError(t, r.Register(specStub("zeta", nil, false)))
	require.NoError(t, r.Register(specStub("alpha", nil, false)))
	require.NoError(t, r.Register(specStub("mike", nil, false)))

	names := make([]string, 0, len(r.Specs()))
	for _, s := range r.Specs() {
		names = append(names, s.Name)
	}
	require.Equal(t, []string{"alpha", "mike", "zeta"}, names)
}

// TestRegistryIsCommandToken covers the front-end dispatch predicate: first
// words of canonical names and aliases address the command system; trusted
// command names must fall through (a user-supplied "daemon" or "ttyrec" must
// be treated as a host, never as the command).
func TestRegistryIsCommandToken(t *testing.T) {

	r := NewRegistry()
	require.NoError(t, r.Register(specStub("self accesses list", []string{"selfListAccesses"}, false)))
	require.NoError(t, r.Register(specStub("ttyrec", nil, true)))
	require.NoError(t, r.Register(specStub("daemon", nil, true)))

	require.True(t, r.IsCommandToken("self"), "first word of a canonical name")
	require.True(t, r.IsCommandToken("selfListAccesses"), "alias")
	require.False(t, r.IsCommandToken("accesses"), "non-first word does not dispatch")
	require.False(t, r.IsCommandToken("ttyrec"), "trusted name must fall through to the access path")
	require.False(t, r.IsCommandToken("daemon"), "trusted name must fall through to the access path")
	require.False(t, r.IsCommandToken("unknown"))
}

// TestRegistryCanonicalTokens covers alias-to-canonical rewriting of a
// tokenized command line before it is handed to cobra.
func TestRegistryCanonicalTokens(t *testing.T) {

	r := NewRegistry()
	require.NoError(t, r.Register(specStub("self totp emergency-codes generate", []string{"selfGenerateTOTPCodes"}, false)))
	require.NoError(t, r.Register(specStub("info", nil, false)))
	require.NoError(t, r.Register(specStub("ttyrec", nil, true)))

	require.Equal(t,
		[]string{"self", "totp", "emergency-codes", "generate", "--foo", "x"},
		r.CanonicalTokens([]string{"selfGenerateTOTPCodes", "--foo", "x"}),
		"alias expands to the canonical words")

	require.Equal(t,
		[]string{"info"},
		r.CanonicalTokens([]string{"info"}),
		"single-word canonical name is unchanged")

	require.Equal(t,
		[]string{"self", "totp", "emergency-codes", "generate"},
		r.CanonicalTokens([]string{"self totp emergency-codes generate"}),
		"a joined canonical name (the historical regrouped form) splits into words")

	require.Equal(t,
		[]string{"ttyrec", "--access", "host"},
		r.CanonicalTokens([]string{"ttyrec", "--access", "host"}),
		"trusted names are never rewritten for the user-facing tree")

	require.Equal(t,
		[]string{"user@host", "uptime"},
		r.CanonicalTokens([]string{"user@host", "uptime"}),
		"non-command tokens are unchanged")

	require.Empty(t, r.CanonicalTokens(nil))
}
