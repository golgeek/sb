package cmd

import (
	"os"
	osuser "os/user"
	"path/filepath"
	"testing"

	"github.com/golgeek/sb/internal/commands"
	"github.com/golgeek/sb/internal/helpers"
	"github.com/golgeek/sb/internal/models"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestIngressCommandOptions(t *testing.T) {
	const line = `from="10.0.0.0/8,!10.1.0.0/16",restrict,command="echo hello, world" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFxu5J1fpfRBHe/2JKreeDGgJlMZji3n97fYm3KJt8Yv test key`
	args, err := helpers.ParseCommandLine("self ingress-key add --public-key '" + line + "'")
	require.NoError(t, err)
	require.Equal(t, []string{"self", "ingress-key", "add", "--public-key", line}, args)

	// Use a nonexistent identity so Execute produces the real replication
	// payload but stops at account lookup, without changing any OS account.
	username := "sbtest" + uuid.NewString()[:8]
	_, err = osuser.Lookup(username)
	var unknown osuser.UnknownUserError
	require.ErrorAs(t, err, &unknown)
	user := &models.User{User: &osuser.User{Username: username, HomeDir: t.TempDir()}}
	path := filepath.Join(t.TempDir(), "authorized_keys")
	require.NoError(t, os.WriteFile(path, nil, 0600))
	require.NoError(t, user.OverrideAuthorizedKeysFilePath(path))
	ct := &commands.Context{User: user, FormattedArguments: map[string]string{"public-key": args[4], "username": username}}
	create := &CreateAccount{}
	require.NoError(t, create.Checks(ct))
	require.Equal(t, line, create.PK.String(), "account creation must retain restrictions")
	result, err := (&SelfAddIngressKey{}).Execute(ct)
	require.ErrorAs(t, err, &unknown)
	require.Equal(t, line, result.Repl["public-key"], "key-add replication must retain restrictions")
}
