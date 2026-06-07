package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/golgeek/sb/internal/helpers"

	"github.com/stretchr/testify/require"
)

// TestSetSSHDOptions verifies the hardened sshd options the setup writes,
// notably that root login is set to prohibit-password (not the previous "yes")
// and password authentication is disabled. It runs against a temporary config
// file so it never touches the host's real /etc/ssh/sshd_config.
func TestSetSSHDOptions(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sshd_config")

	initial := "# test sshd config\n" +
		"PermitRootLogin yes\n" +
		"PasswordAuthentication yes\n" +
		"ChallengeResponseAuthentication no\n"
	require.NoError(t, os.WriteFile(cfgPath, []byte(initial), 0644))

	// Point the setup at the temporary file and restore the default afterwards.
	original := DefaultSSHDConfigFile
	DefaultSSHDConfigFile = cfgPath
	t.Cleanup(func() { DefaultSSHDConfigFile = original })

	c := new(Setup)
	require.NoError(t, c._SetSSHDOptions())

	p, err := helpers.ParseSSHDConfigFile(cfgPath)
	require.NoError(t, err)

	require.Equal(t, "prohibit-password", p.GetParam("PermitRootLogin"), "root login must be prohibit-password, not yes")
	require.Equal(t, "no", p.GetParam("PasswordAuthentication"))
	require.Equal(t, "yes", p.GetParam("ChallengeResponseAuthentication"))
	require.Equal(t, "yes", p.GetParam("KbdInteractiveAuthentication"))
	require.Equal(t, "publickey,keyboard-interactive", p.GetParam("AuthenticationMethods"))
}

// TestValidateSSHDConfigWithSuccess asserts the config validator invokes
// `sshd -t -f <path>` and returns no error when sshd accepts the file.
func TestValidateSSHDConfigWithSuccess(t *testing.T) {
	var gotName string
	var gotArgs []string

	err := validateSSHDConfigWith("/etc/ssh/sshd_config", func(name string, args ...string) ([]byte, error) {
		gotName = name
		gotArgs = args
		return nil, nil
	})

	require.NoError(t, err)
	require.Equal(t, "sshd", gotName)
	require.Equal(t, []string{"-t", "-f", "/etc/ssh/sshd_config"}, gotArgs)
}

// TestValidateSSHDConfigWithFailure asserts that when sshd rejects the config,
// the validator returns an error carrying sshd's output — the signal the setup
// uses to abort the restart and restore the backup rather than lock the host.
func TestValidateSSHDConfigWithFailure(t *testing.T) {
	err := validateSSHDConfigWith("/tmp/broken", func(name string, args ...string) ([]byte, error) {
		return []byte("/tmp/broken: line 5: Bad configuration option"), errors.New("exit status 255")
	})

	require.Error(t, err)
	require.Contains(t, err.Error(), "sshd configuration test failed")
	require.Contains(t, err.Error(), "Bad configuration option", "sshd's output should be surfaced to the operator")
}
