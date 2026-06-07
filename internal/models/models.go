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

	// Migrate the schema (this will create table or alter table if needed)
	if err = db.AutoMigrate(&Access{}); err != nil {
		err = fmt.Errorf("failed to migrate access schema for %s: %w", database, err)
		return
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
