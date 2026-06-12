package models

import (
	"os"
	osuser "os/user"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// totpSyncUser builds a hermetic user whose home is a throwaway directory,
// optionally seeded with a ~/.google_authenticator file.
func totpSyncUser(t *testing.T, totpFileContent string) *User {
	t.Helper()
	home := t.TempDir()
	if totpFileContent != "" {
		require.NoError(t,
			os.WriteFile(filepath.Join(home, ".google_authenticator"), []byte(totpFileContent), 0600),
			"failed to write the TOTP fixture")
	}
	return &User{User: &osuser.User{Username: "alice", HomeDir: home}}
}

// TestSyncTOTPState pins the outbox snapshot the front-end queues on every
// invocation of a TOTP-enabled user: the persisted action string is part of
// the replication name contract, and the payload must round-trip into the
// exact state the peer's Replicate handler will write.
func TestSyncTOTPState(t *testing.T) {

	t.Run("TOTP-enabled user queues a snapshot of the current state", func(t *testing.T) {
		user := totpSyncUser(t, "SECRETBASE32\n\" RATE_LIMIT 3 30\n11111111\n22222222\n")
		dbPath := filepath.Join(t.TempDir(), "replication.db")

		require.NoError(t, SyncTOTPState(user, dbPath))

		db, err := GetReplicationGormDB(dbPath)
		require.NoError(t, err)
		var entries []Replication
		require.NoError(t, db.Find(&entries).Error)
		require.Len(t, entries, 1, "exactly one outbox entry must be queued")
		require.Equal(t, "self totp emergency-codes generate", entries[0].Action,
			"the action string is a persisted replication contract")

		data, err := DecryptReplicationData(entries[0].Data)
		require.NoError(t, err)
		require.Equal(t, "alice", data["account"])
		require.Equal(t, "SECRETBASE32", data["secret"])
		require.Equal(t, "11111111;22222222", data["random-codes"])
	})

	t.Run("user without TOTP is a successful no-op", func(t *testing.T) {
		user := totpSyncUser(t, "")
		dbPath := filepath.Join(t.TempDir(), "replication.db")

		require.NoError(t, SyncTOTPState(user, dbPath))

		_, err := os.Stat(dbPath)
		require.True(t, os.IsNotExist(err), "the outbox must not even be opened when there is nothing to sync")
	})

	t.Run("malformed TOTP file is an error and queues nothing", func(t *testing.T) {
		// An empty file means "TOTP half-configured": GetTOTP refuses to
		// treat it as either enabled or disabled, and the sync must surface
		// that rather than publish a bogus snapshot to peers.
		user := totpSyncUser(t, "\n\n")
		dbPath := filepath.Join(t.TempDir(), "replication.db")

		err := SyncTOTPState(user, dbPath)
		require.ErrorContains(t, err, "unable to read TOTP state")

		_, statErr := os.Stat(dbPath)
		require.True(t, os.IsNotExist(statErr), "no outbox entry may be queued from an unreadable state")
	})

	t.Run("unavailable outbox database is an error", func(t *testing.T) {
		user := totpSyncUser(t, "SECRETBASE32\n11111111\n")

		// A directory is never a valid SQLite file, so opening it fails the
		// same way a corrupt or locked outbox would.
		err := SyncTOTPState(user, t.TempDir())
		require.ErrorContains(t, err, "unable to open the replication outbox")
	})
}
