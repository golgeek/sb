package commands

import (
	"testing"

	"github.com/golgeek/sb/internal/helpers"
	"github.com/golgeek/sb/internal/models"
	"github.com/stretchr/testify/require"
)

func TestSessionTransportFieldsCannotBeOverridden(t *testing.T) {
	// Stub only the command and its rights to avoid DNS/OS access. Exercise the
	// real front-end parser, flat argument parser, and session-context construction.
	previous := defaultRegistry
	defaultRegistry = NewRegistry()
	t.Cleanup(func() { defaultRegistry = previous })
	for _, name := range []string{"ttyrec", "interactive"} {
		defaultRegistry.MustRegister(CommandSpec{
			Name: name, Trusted: true, Rights: models.Public,
			Args: map[string]Argument{"access": {}},
			New:  func() Command { return &fakeCommand{} },
		})
	}
	for _, client := range []string{"ssh", "mosh"} {
		for _, separator := range []string{"", "-- "} {
			input := "user@host " + separator + "--client mosh --client-arguments --,/bin/sh --access other@host"
			if client == "mosh" {
				input = "mosh-server new -c 256 -l LANG=en_US.UTF-8,--,/bin/sh -- " + input
			}
			parsedClient, clientArgs, _, args, err := helpers.ParseArguments([]string{"sb", "-c", input})
			require.NoError(t, err)
			_, ct, err := BuildSessionCommand(&models.Log{}, testUser("alice", "1000", nil), "ttyrec", parsedClient, clientArgs, args[0], args[1:])
			require.NoError(t, err)
			require.Equal(t, client, ct.Client)
			require.Equal(t, clientArgs, ct.ClientArguments)
			require.Equal(t, "user@host", ct.FormattedArguments["access"])
			require.NotContains(t, ct.FormattedArguments, "client")
			require.Equal(t, []string{"--client", "mosh", "--client-arguments", "--,/bin/sh", "--access", "other@host"}, ct.RawArguments)
		}
	}
	client, clientArgs, flags, _, err := helpers.ParseArguments([]string{"sb", "-c", "mosh-server new -c 256 -l LANG=en_US.UTF-8,--,/bin/sh -- -i"})
	require.NoError(t, err)
	require.True(t, flags["interactive"])
	_, ct, err := BuildSessionCommand(&models.Log{}, testUser("alice", "1000", nil), "interactive", client, clientArgs, "", nil)
	require.NoError(t, err)
	require.Equal(t, clientArgs, ct.ClientArguments)
	clientArgs[0] = "--"
	require.Equal(t, "-c", ct.ClientArguments[0], "context owns its argument slice")
}

func TestSessionRejectsInvalidDispatch(t *testing.T) {
	for _, tc := range []struct {
		command, client string
		args            []string
	}{
		{"daemon", "ssh", nil}, {"interactive", "shell", nil},
		{"interactive", "ssh", []string{"-c", "8"}},
		{"interactive", "mosh", []string{"--", "/bin/sh"}},
	} {
		_, _, err := BuildSessionCommand(nil, nil, tc.command, tc.client, tc.args, "", nil)
		require.Error(t, err)
	}
}
