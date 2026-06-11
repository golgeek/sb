package commands

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// These tests pin the exact behavior of buildArgumentsList, the historical
// argument parser. It remains in production for the trusted dispatch path
// (interactive/ttyrec/daemon are built by the front-end through
// BuildSBCommand), and the cobra adapter's formatArguments must preserve the
// semantics marked [contract] below. The behaviors marked [legacy quirk] are
// deliberately NOT carried over to the cobra path; each notes the replacement
// behavior.

// argsFixture declares a representative argument set: required string,
// optional string with default, constrained string, and a bool.
func argsFixture() map[string]Argument {
	return map[string]Argument{
		"access": {Required: true, Description: "the host"},
		"port":   {DefaultValue: "22", Description: "the port"},
		"algo":   {AllowedValues: []string{"rsa", "ed25519"}, DefaultValue: "rsa"},
		"force":  {Type: BOOL, Description: "force"},
	}
}

// TestBuildArgumentsListContract pins the semantics shared by the legacy
// parser and the cobra adapter.
func TestBuildArgumentsListContract(t *testing.T) {

	t.Run("declared strings always present, bool absent unless set", func(t *testing.T) {
		// [contract] Every declared string flag materializes in the map (with
		// its default when not passed); commands probe with the two-value map
		// read, so presence is part of the behavioral contract. BOOLs are
		// present only when set.
		arguments, rest, err := buildArgumentsList(argsFixture(), []string{"--access", "h1"})
		require.NoError(t, err)
		require.Equal(t, map[string]string{"access": "h1", "port": "22", "algo": "rsa"}, arguments)
		require.Empty(t, rest)

		arguments, _, err = buildArgumentsList(argsFixture(), []string{"--access", "h1", "--force"})
		require.NoError(t, err)
		require.Equal(t, "true", arguments["force"])
	})

	t.Run("missing required argument message", func(t *testing.T) {
		// [contract] Exact user-visible message.
		_, _, err := buildArgumentsList(argsFixture(), []string{})
		require.EqualError(t, err, "please provide required argument --access")
	})

	t.Run("allowed-values message", func(t *testing.T) {
		// [contract] Exact user-visible message.
		_, _, err := buildArgumentsList(argsFixture(), []string{"--access", "h1", "--algo", "dsa"})
		require.EqualError(t, err, "argument --algo's value should be from the list: rsa, ed25519")
	})

	t.Run("parsing stops at the first positional token", func(t *testing.T) {
		// [contract] Everything from the first positional on lands in rest
		// (ct.RawArguments) untouched — the passthrough contract ttyrec
		// relies on to forward a remote command to the egress ssh.
		arguments, rest, err := buildArgumentsList(argsFixture(), []string{"--access", "h1", "uptime", "-a"})
		require.NoError(t, err)
		require.Equal(t, "h1", arguments["access"])
		require.Equal(t, []string{"uptime", "-a"}, rest)
	})

	t.Run("explicit -- terminator forwards the remainder", func(t *testing.T) {
		// [contract] The documented reliable passthrough form:
		// ssh bastion "user@host -- uptime -a".
		_, rest, err := buildArgumentsList(argsFixture(), []string{"--access", "h1", "--", "uptime", "-a"})
		require.NoError(t, err)
		require.Equal(t, []string{"uptime", "-a"}, rest)
	})
}

// TestBuildArgumentsListLegacyQuirks pins behaviors of the legacy parser that
// the cobra path deliberately does NOT reproduce.
func TestBuildArgumentsListLegacyQuirks(t *testing.T) {

	t.Run("unknown flag is silently consumed and dropped", func(t *testing.T) {
		// [legacy quirk] An undeclared flag aborts the stdlib flag parse; the
		// offending token is consumed and *lost*, and the remainder becomes
		// rest. This is how "sb user@host -la" silently loses "-la" today.
		// Cobra path replacement: an unknown flag before the first positional
		// is a hard "unknown flag" error — loud instead of lossy.
		arguments, rest, err := buildArgumentsList(argsFixture(), []string{"--access", "h1", "-la"})
		require.NoError(t, err, "the parse error is swallowed by design")
		require.Equal(t, "h1", arguments["access"])
		require.Empty(t, rest, "-la is consumed and dropped, not forwarded")
	})

	t.Run("unknown flag mid-line drops itself but keeps the remainder", func(t *testing.T) {
		// [legacy quirk] The parse aborts at the unknown token; everything
		// after it is recovered as rest. Note "--access h1" after the unknown
		// flag is NOT parsed as a flag anymore — it lands in rest.
		arguments, rest, err := buildArgumentsList(argsFixture(), []string{"--bogus", "--access", "h1"})
		require.EqualError(t, err, "please provide required argument --access",
			"the required check fires because --access was never parsed")
		require.Empty(t, arguments["access"])
		require.Equal(t, []string{"--access", "h1"}, rest)
	})
}
