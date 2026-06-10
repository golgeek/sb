package config

import (
	"bytes"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func TestInitialize(t *testing.T) {
	require.Equal(t, "sb", GetSBName(), "The default value of sb name is wrong")
	require.Equal(t, "sb.domain.tld", GetSBHostname(), "The default value of sb hostname is wrong")
	require.Equal(t, "40000:49999", GetMOSHPortsRange(), "The default value of the mosh ports rangeis wrong")
	require.Equal(t, []string{"USER"}, GetEnvironmentVarsToForward(), "The default SSH environmen variables to forward is wrong")
	require.Equal(t, "ttyrec", GetSSHCommand(), "The default value of sb hostname is wrong")
	require.Equal(t, "/opt/sb/sb", GetBinaryPath(), "The default value of the binary path is wrong")
}

// setKeyConfig overrides the three viper keys ValidateSecretsEncryption reads
// and registers a cleanup that restores them to the package defaults. It avoids
// viper.Reset on purpose: Reset would also wipe the defaults installed by the
// package init(), which the other tests in this file rely on.
func setKeyConfig(t *testing.T, key string, replicationEnabled, offloadingEnabled bool) {
	t.Helper()
	t.Cleanup(func() {
		viper.Set("general.encryption-key", DefaultEncryptionKey)
		viper.Set("replication.enabled", false)
		viper.Set("ttyrecsoffloading.enabled", false)
	})
	viper.Set("general.encryption-key", key)
	viper.Set("replication.enabled", replicationEnabled)
	viper.Set("ttyrecsoffloading.enabled", offloadingEnabled)
}

// TestEncryptionKeyIsInsecure verifies the empty/default detection that the
// startup guard relies on: only an empty key or the shipped placeholder is
// considered insecure, any other value is treated as operator-chosen.
func TestEncryptionKeyIsInsecure(t *testing.T) {
	cases := []struct {
		name string
		key  string
		want bool
	}{
		{name: "empty key is insecure", key: "", want: true},
		{name: "shipped default is insecure", key: DefaultEncryptionKey, want: true},
		{name: "custom key is secure", key: "demo-only-not-secret-change-me!!", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setKeyConfig(t, tc.key, false, false)
			require.Equal(t, tc.want, EncryptionKeyIsInsecure())
		})
	}
}

// TestEncryptionKeyHasValidLength verifies the AES-length check shared by the
// startup guard and the replication transport: only 16, 24 and 32-byte keys are
// usable, and notably the historical hand-written check this replaces was wrong
// at both ends (it accepted 8 bytes and rejected 24).
func TestEncryptionKeyHasValidLength(t *testing.T) {
	cases := []struct {
		name string
		key  string
		want bool
	}{
		{name: "16 bytes (AES-128) is valid", key: "0123456789abcdef", want: true},
		{name: "24 bytes (AES-192) is valid", key: "0123456789abcdef01234567", want: true},
		{name: "32 bytes (AES-256) is valid", key: "0123456789abcdef0123456789abcdef", want: true},
		{name: "empty is invalid", key: "", want: false},
		{name: "8 bytes is invalid", key: "shortkey", want: false},
		{name: "20 bytes is invalid", key: "0123456789abcdef0123", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, EncryptionKeyHasValidLength(tc.key))
		})
	}
}

// TestValidateSecretsEncryption covers the matrix that decides whether the
// daemon is allowed to start: the guard must fail closed when a feature that
// ships secrets is enabled while the key is either insecure (empty/default) or
// not a valid AES length, and stay silent in every other combination.
func TestValidateSecretsEncryption(t *testing.T) {
	const customKey = "demo-only-not-secret-change-me!!" // 32 bytes
	const customKey24 = "0123456789abcdef01234567"       // 24 bytes (AES-192)
	const shortKey = "shortkey"                          // 8 bytes: non-default but unusable

	cases := []struct {
		name               string
		key                string
		replicationEnabled bool
		offloadingEnabled  bool
		wantErr            bool
	}{
		{name: "replication on with default key fails", key: DefaultEncryptionKey, replicationEnabled: true, wantErr: true},
		{name: "offloading on with default key fails", key: DefaultEncryptionKey, offloadingEnabled: true, wantErr: true},
		{name: "replication on with empty key fails", key: "", replicationEnabled: true, wantErr: true},
		{name: "replication on with short non-default key fails", key: shortKey, replicationEnabled: true, wantErr: true},
		{name: "offloading on with short non-default key fails", key: shortKey, offloadingEnabled: true, wantErr: true},
		{name: "replication on with 24-byte key passes", key: customKey24, replicationEnabled: true, wantErr: false},
		{name: "both on with custom key passes", key: customKey, replicationEnabled: true, offloadingEnabled: true, wantErr: false},
		{name: "both off with default key passes", key: DefaultEncryptionKey, wantErr: false},
		{name: "both off with short key passes", key: shortKey, wantErr: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setKeyConfig(t, tc.key, tc.replicationEnabled, tc.offloadingEnabled)
			err := ValidateSecretsEncryption()
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestGetEgressStrictHostKeyChecking verifies the accessor never returns an
// empty policy (which would make ssh abort with "no argument after keyword
// stricthostkeychecking"). A configured value is returned verbatim, while an
// empty/unset value — the situation for deployments whose config file predates
// this key, since viper defaults do not apply when a config file is present —
// falls back to the safe default.
func TestGetEgressStrictHostKeyChecking(t *testing.T) {
	t.Cleanup(func() { viper.Set("general.egress_strict_host_key_checking", defaultEgressStrictHostKeyChecking) })

	t.Run("configured value is returned", func(t *testing.T) {
		viper.Set("general.egress_strict_host_key_checking", "yes")
		require.Equal(t, "yes", GetEgressStrictHostKeyChecking())
	})

	t.Run("empty value falls back to the default", func(t *testing.T) {
		viper.Set("general.egress_strict_host_key_checking", "")
		require.Equal(t, defaultEgressStrictHostKeyChecking, GetEgressStrictHostKeyChecking())
		require.NotEmpty(t, GetEgressStrictHostKeyChecking())
	})
}

// TestSetDefaultsAppliedAlongsidePartialConfig is the regression test for the
// bug this change fixes: defaults must apply even when a config file is present
// but only sets some keys. It drives a fresh viper instance (so it never touches
// the process-wide one) exactly as init() does — register the defaults, then
// read a config — and asserts that a key set in the file wins while an omitted
// key still resolves to its default. Before the fix the defaults were only
// registered when no config file existed, so the omitted key would have
// resolved to "".
func TestSetDefaultsAppliedAlongsidePartialConfig(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")

	setDefaults(v)

	// A config file that sets only general.name and leaves everything else out.
	partialConfig := []byte("general:\n  name: custom-bastion\n")
	require.NoError(t, v.ReadConfig(bytes.NewReader(partialConfig)))

	// The key present in the file overrides its default...
	require.Equal(t, "custom-bastion", v.GetString("general.name"))

	// ...while keys omitted from the file still resolve to their defaults rather
	// than the empty string. commands.ssh_command in particular must stay
	// "ttyrec": main.go uses it to dispatch host connections.
	require.Equal(t, "ttyrec", v.GetString("commands.ssh_command"))
	require.Equal(t, "/opt/sb/sb", v.GetString("general.binary_path"))
	require.Equal(t, "22", v.GetString("general.ssh_port"))
	require.Equal(t, "sb", v.GetString("general.sb_user"))
}
