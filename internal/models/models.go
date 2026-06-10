package models

import (
	"fmt"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// GetAccessGormDB returns a DB handler
func GetAccessGormDB(database string) (db *gorm.DB, err error) {

	// We open the DB
	db, err = gorm.Open(sqlite.Open(database), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		err = fmt.Errorf("failed to connect database %s", database)
		return
	}

	// Migrate the schema (this will create table or alter table if needed).
	// Migration is a write, and not every legitimate caller may write this
	// database: a group's accesses database is writable by its ACL keepers
	// only, while plain members open it read-only (listing the group's
	// accesses, resolving a group-granted host connection). For such readers
	// the migration fails with a read-only error even though the schema is
	// already in place. Only tolerate that failure when the table verifiably
	// exists: the database was then provisioned by a writable caller, and a
	// genuinely incompatible schema still surfaces as a loud query error. An
	// unprovisioned database (no table) keeps failing here, read-only or not.
	if err = db.AutoMigrate(&Access{}); err != nil {
		if db.Migrator().HasTable(&Access{}) {
			err = nil
		} else {
			err = fmt.Errorf("failed to migrate access schema for %s: %w", database, err)
			return
		}
	}

	return
}

// GetReplicationGormDB returns a DB handler
func GetReplicationGormDB(database string) (db *gorm.DB, err error) {

	// We open the DB
	db, err = gorm.Open(sqlite.Open(database), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		err = fmt.Errorf("failed to connect to replication database %s", database)
		return
	}

	// Migrate the schema (this will create table or alter table if needed)
	if err = db.AutoMigrate(&Replication{}); err != nil {
		err = fmt.Errorf("failed to migrate replication schema for %s: %w", database, err)
		return
	}

	return
}
