package models

import (
	"os"
	"path/filepath"
	"testing"
)

// TestGetAccessGormDBReadOnly covers opening an accesses database without
// write permission, the situation of every plain group member reading the
// group's accesses (the file is writable by the group's ACL keepers only):
// a provisioned database must open and serve reads, while an unprovisioned
// one must keep failing — its schema cannot be created without writing.
func TestGetAccessGormDBReadOnly(t *testing.T) {

	t.Run("provisioned database opens and reads without write permission", func(t *testing.T) {
		dbPath := filepath.Join(t.TempDir(), "accesses.db")

		// Provision the database as a writable caller (the ACL-keeper role
		// in production): schema migrated and one access stored.
		db, err := GetAccessGormDB(dbPath)
		if err != nil {
			t.Fatalf("provisioning open failed: %v", err)
		}
		if err := db.Create(&Access{Host: "examplevm", User: "root", Port: 22}).Error; err != nil {
			t.Fatalf("provisioning insert failed: %v", err)
		}
		sqlDB, err := db.DB()
		if err != nil {
			t.Fatalf("unable to get SQL handle: %v", err)
		}
		if err := sqlDB.Close(); err != nil {
			t.Fatalf("unable to close provisioning handle: %v", err)
		}

		// Drop write permission, as seen by a plain group member.
		if err := os.Chmod(dbPath, 0o444); err != nil {
			t.Fatalf("unable to chmod database read-only: %v", err)
		}

		// Re-open read-only: the migration write fails, but the schema is in
		// place, so the open must succeed and reads must work.
		roDB, err := GetAccessGormDB(dbPath)
		if err != nil {
			t.Fatalf("read-only open of a provisioned database failed: %v", err)
		}
		accesses, err := GetAllAccesses(roDB)
		if err != nil {
			t.Fatalf("read-only query failed: %v", err)
		}
		if len(accesses) != 1 || accesses[0].Host != "examplevm" {
			t.Fatalf("read-only query returned %v, want the provisioned access", accesses)
		}
	})

	t.Run("unprovisioned read-only database still fails", func(t *testing.T) {
		dbPath := filepath.Join(t.TempDir(), "accesses.db")

		// An empty file with no schema, not writable: the table cannot be
		// created, so opening must fail rather than hand out a handle that
		// breaks on first use.
		if err := os.WriteFile(dbPath, nil, 0o444); err != nil {
			t.Fatalf("unable to create empty database file: %v", err)
		}

		if _, err := GetAccessGormDB(dbPath); err == nil {
			t.Fatalf("open of an unprovisioned read-only database succeeded, want error")
		}
	})
}
