package models

import (
	"fmt"
	"net/url"

	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// AuthorizeRecording requires an allowed recorded session belonging to this user.
// The per-user audit database is read-only here: missing audit data denies replay,
// but does not change the best-effort recording policy for new connections.
func (bu *User) AuthorizeRecording(sessionID string) error {
	id, err := uuid.Parse(sessionID)
	if err != nil || id.String() != sessionID {
		return fmt.Errorf("invalid session ID: expected a canonical UUID")
	}
	dsn := url.URL{Scheme: "file", Path: bu.GetLocalLogDatabasePath(), RawQuery: "mode=ro"}
	db, err := gorm.Open(sqlite.Open(dsn.String()), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		return fmt.Errorf("unable to verify recording ownership: %w", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("unable to verify recording ownership: %w", err)
	}
	defer sqlDB.Close()

	var count int64
	err = db.Model(&Log{}).Where("uniq_id = ? AND local_username = ? AND command = ? AND allowed = ?",
		sessionID, bu.User.Username, "ttyrec", true).Count(&count).Error
	if err != nil {
		return fmt.Errorf("unable to verify recording ownership: %w", err)
	}
	if count != 1 {
		return fmt.Errorf("recording not available for this user")
	}
	return nil
}
