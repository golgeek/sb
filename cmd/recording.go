package cmd

import (
	"io"
	"os"
	"path/filepath"

	"github.com/golgeek/sb/internal/config"
	"github.com/golgeek/sb/internal/helpers"
	"github.com/golgeek/sb/internal/models"
	"github.com/golgeek/sb/internal/storage"
)

func prepareRecording(user *models.User, sessionID string) (string, func(), error) {
	return prepareRecordingWithStorage(user, sessionID, func() (storage.Storage, error) {
		cfg := config.GetTTYRecsOffloadingConfig()
		if !cfg.Enabled {
			return nil, nil
		}
		return storage.GetStorage(cfg)
	}, config.GetEncryptionKey())
}

// Authorization precedes all storage access. Both local and offloaded recordings
// are staged privately so conversion never overwrites or deletes original files.
func prepareRecordingWithStorage(user *models.User, sessionID string, remote func() (storage.Storage, error), key string) (path string, cleanup func(), err error) {
	if err = user.AuthorizeRecording(sessionID); err != nil {
		return
	}
	rs, err := remote()
	if err != nil {
		return
	}
	dir, err := os.MkdirTemp("", "sb-recording-")
	if err != nil {
		return
	}
	cleanup = func() { _ = os.RemoveAll(dir) }
	defer func() {
		if err != nil {
			cleanup()
		}
	}()
	path = filepath.Join(dir, "recording.ttyrec")
	filename := sessionID + ".ttyrec"
	if rs != nil {
		encrypted := filepath.Join(dir, "recording.bin")
		if err = rs.GetFromStorage(filename+".bin", encrypted); err != nil {
			return
		}
		err = helpers.DecryptFile(encrypted, path, key)
		return
	}
	err = copyLocalRecording(user.GetTtyrecDirectory(), filename, path)
	return
}

func copyLocalRecording(directory, filename, destination string) error {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer root.Close()
	src, err := root.Open(filename)
	if err != nil {
		return err
	}
	defer src.Close()
	dst, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = io.Copy(dst, src)
	closeErr := dst.Close()
	if err != nil {
		return err
	}
	return closeErr
}
