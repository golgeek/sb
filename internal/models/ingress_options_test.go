package models

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	osuser "os/user"
	"path/filepath"
	"testing"

	"github.com/golgeek/sb/internal/helpers"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestIngressOptionsStorageAndReplication(t *testing.T) {
	const restricted = `from="10.0.0.0/8,!10.2.0.0/16",restrict,port-forwarding,permitopen="database.internal:5432",command="echo \"hello, world\"" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFxu5J1fpfRBHe/2JKreeDGgJlMZji3n97fYm3KJt8Yv alice key`
	pk, err := helpers.CheckStringPK(restricted, nil)
	require.NoError(t, err)

	// Exercise the same encrypted payload used by account creation and key
	// addition, then the receiver's real authorized_keys writer and listing.
	payload, err := EncryptReplicationDataForTransport(ReplicationData{"account": "alice", "public-key": pk.String()})
	require.NoError(t, err)
	data, err := DecryptReplicationData(payload)
	require.NoError(t, err)
	require.Equal(t, restricted, data["public-key"])

	path := filepath.Join(t.TempDir(), "authorized_keys")
	require.NoError(t, os.WriteFile(path, nil, 0600))
	user := &User{User: &osuser.User{Username: "alice", HomeDir: t.TempDir()}}
	require.NoError(t, user.OverrideAuthorizedKeysFilePath(path))
	require.NoError(t, user.AddIngressKey(data["public-key"]))
	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, restricted+"\n", string(contents))
	display, keys, err := user.DisplayPubKeys("ingress")
	require.NoError(t, err)
	require.Contains(t, display, restricted)
	require.Len(t, keys, 1)
	require.Equal(t, pk.Options, keys[0].Options)
	require.Equal(t, restricted, keys[0].String())

	// Removing an unrelated key must retain the restricted line unchanged.
	public, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sshKey, err := ssh.NewPublicKey(public)
	require.NoError(t, err)
	other := helpers.PublicKey{PublicKey: sshKey}
	require.NoError(t, user.AddIngressKey(other.String()))
	require.NoError(t, user.DeletePubKey("ingress", other))
	contents, err = os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, restricted+"\n", string(contents))

	// Revocation remains based on key material, not options or comments.
	require.NoError(t, user.DeletePubKey("ingress", helpers.PublicKey{PublicKey: pk.PublicKey}))
	_, keys, err = user.DisplayPubKeys("ingress")
	require.NoError(t, err)
	require.Empty(t, keys)
}
