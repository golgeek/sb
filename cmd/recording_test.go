package cmd

import (
	"errors"
	"os"
	osuser "os/user"
	"path/filepath"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/golgeek/sb/internal/commands"
	"github.com/golgeek/sb/internal/helpers"
	"github.com/golgeek/sb/internal/models"
	"github.com/golgeek/sb/internal/storage"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func recordingUser(t *testing.T, logs ...models.Log) *models.User {
	t.Helper()
	user := &models.User{User: &osuser.User{Username: "alice", HomeDir: t.TempDir()}}
	db, err := gorm.Open(sqlite.Open(user.GetLocalLogDatabasePath()), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	require.NoError(t, db.AutoMigrate(&models.Log{}))
	for _, log := range logs {
		require.NoError(t, db.Create(&log).Error)
	}
	require.NoError(t, os.Mkdir(user.GetTtyrecDirectory(), 0700))
	return user
}

func allowedRecording() models.Log {
	return models.Log{UniqID: uuid.NewString(), LocalUsername: "alice", Command: "ttyrec", Allowed: true}
}

func TestRecordingAuthorization(t *testing.T) {
	for _, kind := range []string{"own", "other user", "denied", "other command", "unknown", "traversal", "absolute", "noncanonical"} {
		t.Run(kind, func(t *testing.T) {
			log := allowedRecording()
			id := log.UniqID
			switch kind {
			case "other user":
				log.LocalUsername = "bob"
			case "denied":
				log.Allowed = false
			case "other command":
				log.Command = "interactive"
			case "unknown":
				id = uuid.NewString()
			case "traversal":
				id = "../" + id
			case "absolute":
				id = "/tmp/" + id
			case "noncanonical":
				id = "urn:uuid:" + id
			}
			user := recordingUser(t, log)
			ct := &commands.Context{User: user, FormattedArguments: map[string]string{"session-id": id, "speed": "1.0"}}
			for _, command := range []commands.Command{&SelfPlaySession{}, &SelfGetSessionAsGif{}} {
				if kind == "own" {
					require.NoError(t, command.Checks(ct))
				} else {
					require.Error(t, command.Checks(ct))
					_, err := command.Execute(ct)
					require.Error(t, err)
				}
			}
			if kind != "own" {
				_, _, err := prepareRecordingWithStorage(user, id, func() (storage.Storage, error) {
					t.Fatal("unauthorized request reached storage")
					return nil, nil
				}, "key")
				require.Error(t, err)
			}
		})
	}
}

func TestRecordingMissingAuditDoesNotCreateDatabase(t *testing.T) {
	user := &models.User{User: &osuser.User{Username: "alice", HomeDir: t.TempDir()}}
	require.Error(t, user.AuthorizeRecording(uuid.NewString()))
	_, err := os.Stat(user.GetLocalLogDatabasePath())
	require.True(t, os.IsNotExist(err))
}

func TestLocalRecordingIsCopiedPrivately(t *testing.T) {
	log := allowedRecording()
	user := recordingUser(t, log)
	source := filepath.Join(user.GetTtyrecDirectory(), log.UniqID+".ttyrec")
	require.NoError(t, os.WriteFile(source, []byte("recording"), 0600))
	path, cleanup, err := prepareRecordingWithStorage(user, log.UniqID, func() (storage.Storage, error) { return nil, nil }, "")
	require.NoError(t, err)
	t.Cleanup(cleanup)
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "recording", string(content))
	info, err := os.Stat(filepath.Dir(path))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0700), info.Mode().Perm())
	info, err = os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())
	cleanup()
	_, err = os.Stat(path)
	require.True(t, os.IsNotExist(err))
	content, err = os.ReadFile(source)
	require.NoError(t, err)
	require.Equal(t, "recording", string(content))
}

func TestLocalRecordingRejectsEscapingSymlink(t *testing.T) {
	log := allowedRecording()
	user := recordingUser(t, log)
	outside := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(outside, []byte("secret"), 0600))
	require.NoError(t, os.Symlink(outside, filepath.Join(user.GetTtyrecDirectory(), log.UniqID+".ttyrec")))
	path, _, err := prepareRecordingWithStorage(user, log.UniqID, func() (storage.Storage, error) { return nil, nil }, "")
	require.Error(t, err)
	_, err = os.Stat(filepath.Dir(path))
	require.True(t, os.IsNotExist(err))
}

type recordingStorage struct {
	get func(string, string) error
}

func (s recordingStorage) GetFromStorage(key, path string) error { return s.get(key, path) }
func (s recordingStorage) PushToStorage(string, string) error    { return errors.New("unexpected upload") }

func TestOffloadedRecordingCleanup(t *testing.T) {
	for _, mode := range []string{"success", "download failure", "decrypt failure"} {
		t.Run(mode, func(t *testing.T) {
			log := allowedRecording()
			user := recordingUser(t, log)
			plain := filepath.Join(t.TempDir(), "plain")
			require.NoError(t, os.WriteFile(plain, []byte("recording"), 0600))
			var staging string
			remote := recordingStorage{get: func(key, path string) error {
				require.Equal(t, log.UniqID+".ttyrec.bin", key)
				staging = filepath.Dir(path)
				if mode == "success" {
					return helpers.EncryptFile(plain, path, "test-key")
				}
				if mode == "download failure" {
					require.NoError(t, os.WriteFile(path, []byte("incomplete ciphertext"), 0600))
					return errors.New("download failed")
				}
				require.NoError(t, helpers.EncryptFile(plain, path, "test-key"))
				ciphertext, err := os.ReadFile(path)
				require.NoError(t, err)
				ciphertext[len(ciphertext)-1] ^= 1
				require.NoError(t, os.WriteFile(path, ciphertext, 0600))
				return nil
			}}
			path, cleanup, err := prepareRecordingWithStorage(user, log.UniqID, func() (storage.Storage, error) { return remote, nil }, "test-key")
			if mode == "success" {
				require.NoError(t, err)
				t.Cleanup(cleanup)
				content, err := os.ReadFile(path)
				require.NoError(t, err)
				require.Equal(t, "recording", string(content))
				cleanup()
			} else {
				require.Error(t, err)
			}
			require.NotEmpty(t, staging)
			_, err = os.Stat(staging)
			require.True(t, os.IsNotExist(err))
			entries, err := os.ReadDir(user.GetTtyrecDirectory())
			require.NoError(t, err)
			require.Empty(t, entries)
		})
	}
}
