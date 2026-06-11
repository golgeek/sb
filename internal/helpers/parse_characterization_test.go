package helpers

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// These tests pin the tokenization behavior around RegroupCommandArguments,
// which joins all leading non-flag tokens into one space-separated token so
// the flat command registry can look up multi-word command names as a single
// string ("self accesses list").
//
// The front-end (ParseArguments) no longer regroups: dispatch is first-word
// based and cobra walks the words. The interactive REPL still calls
// RegroupCommandArguments, so the joining behavior itself stays pinned here
// until the REPL executor moves to the cobra tree as well.

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
		// The join is name-agnostic, so an access plus a remote command
		// becomes one invalid token. This is why the front-end stopped
		// regrouping ("sb user@host uptime" now works); the REPL has no
		// access path, so the quirk is harmless there.
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

// TestParseArgumentsTokenization pins what main.go receives for the
// SSH-forced command lines users type, now that ParseArguments no longer
// regroups leading tokens (dispatch is first-word based and cobra walks the
// words). Each case notes the historical behavior it replaces.
func TestParseArgumentsTokenization(t *testing.T) {

	t.Run("multi-word command arrives split", func(t *testing.T) {
		// Historical behavior: one joined token ("self accesses list") so the
		// flat registry could look it up as a single key.
		_, _, _, args, err := ParseArguments([]string{"sb", "-c", "self accesses list"})
		require.NoError(t, err)
		require.Equal(t, []string{"self", "accesses", "list"}, args)
	})

	t.Run("access with remote command arrives split", func(t *testing.T) {
		// Historical behavior: the regrouping glued these into the single
		// invalid token "user@host uptime", so
		// "ssh bastion 'user@host uptime'" failed as an unknown command.
		// Split tokens make it work: "user@host" dispatches to the access
		// path and "uptime" is forwarded to the distant host.
		_, _, _, args, err := ParseArguments([]string{"sb", "-c", "user@host uptime"})
		require.NoError(t, err)
		require.Equal(t, []string{"user@host", "uptime"}, args)
	})

	t.Run("access with -- protected remote command is unchanged", func(t *testing.T) {
		// The documented passthrough form worked before and must keep
		// working identically.
		_, _, _, args, err := ParseArguments([]string{"sb", "-c", "user@host -- uptime -a"})
		require.NoError(t, err)
		require.Equal(t, []string{"user@host", "--", "uptime", "-a"}, args)
	})

	t.Run("command flags follow the split words", func(t *testing.T) {
		// Historical behavior: ["group info", "--group", "team"].
		_, _, _, args, err := ParseArguments([]string{"sb", "-c", "group info --group team"})
		require.NoError(t, err)
		require.Equal(t, []string{"group", "info", "--group", "team"}, args)
	})
}
