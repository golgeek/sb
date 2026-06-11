package helpers

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// These tests pin the current front-end tokenization behavior around
// RegroupCommandArguments, which joins all leading non-flag tokens into one
// space-separated token so the flat command registry can look up multi-word
// command names as a single string ("self accesses list").
//
// The cobra port removes the regrouping from ParseArguments and the REPL
// (dispatch switches to a first-word lookup and cobra walks the words), so
// the cases below marked [changes with cobra] are expected to change, in the
// stated way. They are pinned here first so the port is measured against
// reality rather than assumption.

// TestRegroupCommandArguments pins the joining behavior in isolation.
func TestRegroupCommandArguments(t *testing.T) {

	t.Run("leading words join into one token", func(t *testing.T) {
		require.Equal(t,
			[]string{"self accesses list"},
			RegroupCommandArguments([]string{"self", "accesses", "list"}))
	})

	t.Run("joining stops at the first dash token", func(t *testing.T) {
		require.Equal(t,
			[]string{"self ingress-key add", "--public-key", "KEY"},
			RegroupCommandArguments([]string{"self", "ingress-key", "add", "--public-key", "KEY"}))
	})

	t.Run("access token glues to a trailing remote command", func(t *testing.T) {
		// [changes with cobra] The join is name-agnostic, so an access plus a
		// remote command becomes one invalid token: "user@host uptime" is not
		// a registered command nor a valid access, and dispatch fails with
		// "unknown command" today. After the port, "user@host" dispatches to
		// the access path and "uptime" is forwarded to the distant host.
		require.Equal(t,
			[]string{"user@host uptime"},
			RegroupCommandArguments([]string{"user@host", "uptime"}))
	})

	t.Run("explicit -- protects a trailing remote command", func(t *testing.T) {
		// The reliable passthrough form today: the "--" token starts with a
		// dash, so the join stops before it and the access token stays
		// intact. This end-to-end behavior must keep working after the port.
		require.Equal(t,
			[]string{"user@host", "--", "uptime", "-a"},
			RegroupCommandArguments([]string{"user@host", "--", "uptime", "-a"}))
	})

	t.Run("single token and empty input pass through", func(t *testing.T) {
		require.Equal(t, []string{"info"}, RegroupCommandArguments([]string{"info"}))
		require.Empty(t, RegroupCommandArguments([]string{}))
	})
}

// TestParseArgumentsRegroupingEndToEnd pins the regrouping as observed
// through ParseArguments, i.e. what main.go actually receives for the
// SSH-forced command lines users type.
func TestParseArgumentsRegroupingEndToEnd(t *testing.T) {

	t.Run("multi-word command arrives as one joined token", func(t *testing.T) {
		// [changes with cobra] After the port the tokens stay split
		// (["self", "accesses", "list"]) and cobra walks them.
		_, _, _, args, err := ParseArguments([]string{"sb", "-c", "self accesses list"})
		require.NoError(t, err)
		require.Equal(t, []string{"self accesses list"}, args)
	})

	t.Run("access with remote command arrives glued", func(t *testing.T) {
		// [changes with cobra] Today this single mangled token makes
		// "ssh bastion 'user@host uptime'" fail as an unknown command; after
		// the port it works (access + forwarded remote command).
		_, _, _, args, err := ParseArguments([]string{"sb", "-c", "user@host uptime"})
		require.NoError(t, err)
		require.Equal(t, []string{"user@host uptime"}, args)
	})

	t.Run("access with -- protected remote command arrives split", func(t *testing.T) {
		// Works today and must keep working identically after the port.
		_, _, _, args, err := ParseArguments([]string{"sb", "-c", "user@host -- uptime -a"})
		require.NoError(t, err)
		require.Equal(t, []string{"user@host", "--", "uptime", "-a"}, args)
	})

	t.Run("command flags survive after the joined name", func(t *testing.T) {
		_, _, _, args, err := ParseArguments([]string{"sb", "-c", "group info --group team"})
		require.NoError(t, err)
		require.Equal(t, []string{"group info", "--group", "team"}, args)
	})
}
