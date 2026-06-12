package helpers

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestParseArgumentsTokenization pins what main.go receives for the
// SSH-forced command lines users type. Historically, ParseArguments ended
// with RegroupCommandArguments, which joined all leading non-flag tokens into
// one space-separated token so the flat command registry could look up
// multi-word command names as a single string ("self accesses list") — at
// the cost of also gluing an access to its trailing remote command into one
// invalid token. Dispatch is first-word based now and cobra walks the words,
// so tokens stay split; each case notes the historical behavior it replaces.
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
