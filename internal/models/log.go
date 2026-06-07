package models

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/golgeek/sb/internal/config"
	"github.com/golgeek/sb/internal/helpers"

	"github.com/glebarez/sqlite" // Blank import
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Log describes the basic properties of a log
type Log struct {
	UniqID           string    `gorm:"PRIMARY_KEY"`       // PK: uniq log ID (corresponding to the ttyrec filename)
	LocalUsername    string    `gorm:"type:varchar(50)"`  // The local user iniating the SSH session
	Arguments        string    `gorm:"type:text"`         // The arguments passed to SSH
	SessionStartDate time.Time `gorm:"type:datetime"`     // Session start time
	SessionEndDate   time.Time `gorm:"type:datetime"`     // Session end time
	IPFrom           string    `gorm:"type:varchar(45)"`  // The IP the connection is issued from
	PortFrom         string    `gorm:"type:varchar(5)"`   // The port the connection is issued from
	HostFrom         string    `gorm:"type:varchar(100)"` // The host the connection is issued from
	BastionIP        string    `gorm:"type:varchar(45)"`  // A bit about myself: my IP
	BastionPort      string    `gorm:"type:varchar(5)"`   // A bit about myself: my port
	BastionHost      string    `gorm:"type:varchar(100)"` // A bit about myself: my host

	Command string `gorm:"type:text"` // The command that was executed by this piece of software
	Comment string `gorm:"type:text"` // A comment, because why not?

	HostTo string `gorm:"type:varchar(100)"` // The host the user wanted to connect to
	PortTo string `gorm:"type:varchar(5)"`   // The port the user wanted to connect to
	UserTo string `gorm:"type:varchar(100)"` // The user to connect to the distant host

	Allowed bool `gorm:"type:varchar(1)"` // Did we allow the connection?

	// Ignored helpers: not saved to database
	Databases []string `gorm:"-"`
}

// NewLog initiates a new log entry
func NewLog(username string, databases []string, arguments []string) (log *Log) {

	// Initialize new log
	log = new(Log)

	// Data passed by the constructor
	log.LocalUsername = username
	log.Arguments = strings.Join(arguments, " ")

	// Data I gather myself
	log.SessionStartDate = time.Now()
	log.UniqID = uuid.New().String()

	// If I've been executed by SSH, I should get this env var
	sshConnectionEnv := strings.Split(os.Getenv("SSH_CONNECTION"), " ")
	if len(sshConnectionEnv) >= 4 {
		log.HostFrom = sshConnectionEnv[0]
		log.PortFrom = sshConnectionEnv[1]
		log.BastionIP = sshConnectionEnv[2]
		log.BastionPort = sshConnectionEnv[3]
	}

	log.Databases = databases

	// Best-effort audit write: NewLog has no error return, so surface a failure to
	// stderr rather than dropping the new log entry silently.
	if err := log.insert(true); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: unable to persist new log entry: %s\n", err)
	}

	if config.GetReplicationEnabled() {
		err := log.PushReplication(true)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: unable to push log replication: %s\n", err)
		}
	}

	return
}

// GetLastSSHSessions returns the last SSH sessions
func GetLastSSHSessions(database string, limit int) (sessions []*helpers.SSHSession, err error) {

	var logs []*Log

	db, err := gorm.Open(sqlite.Open(database), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		panic("failed to connect database")
	}

	sqlDB, err := db.DB()
	if err != nil {
		panic("failed to get SQL DB handler")
	}
	defer sqlDB.Close()

	// Migrate the schema (this will create table or alter table if needed)
	if err = db.AutoMigrate(&Log{}); err != nil {
		return
	}

	// Select
	err = db.Where("command = ?", "ttyrec").Order("session_start_date desc").Limit(limit).Find(&logs).Error
	if err != nil {
		return
	}

	sessions = make([]*helpers.SSHSession, 0, len(logs))
	for _, log := range logs {
		sessions = append(sessions, &helpers.SSHSession{
			UniqID:    log.UniqID,
			StartDate: log.SessionStartDate,
			EndDate:   log.SessionEndDate,
			UserFrom:  log.LocalUsername,
			IPFrom:    log.IPFrom,
			PortFrom:  log.PortFrom,
			HostFrom:  log.HostFrom,
			HostTo:    log.HostTo,
			PortTo:    log.PortTo,
			UserTo:    log.UserTo,
			Allowed:   log.Allowed,
		})
	}

	return
}

// Save saves a log in a global access database
func (l *Log) Replicate(new bool) (err error) {
	return l.insert(new)
}

// Save saves a log in a global access database
func (l *Log) Save() (err error) {

	err = l.insert(false)
	if err != nil {
		return
	}

	if config.GetReplicationEnabled() {
		return l.PushReplication(false)
	}
	return
}

// SetAllowed sets whether or not the command was allowed by sb in the log and saves it
func (l *Log) SetAllowed(allowed bool) error {
	l.Allowed = allowed
	return l.Save()
}

func (l *Log) PushReplication(new bool) (err error) {

	action := "log"
	if new {
		action = "new-log"
	}

	logJSON, err := json.Marshal(l)
	if err != nil {
		return
	}

	repl, err := NewReplicationEntry(action, ReplicationData{
		"log": string(logJSON),
	})
	if err != nil {
		return
	}

	dbHandler, err := GetReplicationGormDB(config.GetReplicationDatabasePath())
	if err != nil {
		return
	}

	return repl.Save(dbHandler)
}

// SetCommand sets the command that was executed by sb in the log and saves it
func (l *Log) SetCommand(command string) error {
	l.Command = command
	return l.Save()
}

// SetTargetAccess sets the target access information in the log and saves it
func (l *Log) SetTargetAccess(ba *Access) error {
	l.HostTo = ba.Host
	l.PortTo = strconv.Itoa(ba.Port)
	l.UserTo = ba.User
	return l.Save()
}

// insert saves the object in database (insert or update depending on the passed boolean)
func (l *Log) insert(insert bool) (err error) {

	// We usually work on the local user database and a global database
	for _, dbPath := range l.Databases {

		_, errStat := os.Stat(dbPath)
		if errStat != nil {
			if os.IsNotExist(errStat) {
				errMkdir := os.MkdirAll(filepath.Dir(dbPath), 0755)
				if errMkdir != nil {
					return fmt.Errorf("unable to create logs database path %s: %w", dbPath, errMkdir)
				}
			} else {
				return fmt.Errorf("unable to stat logs database path %s: %w", dbPath, errStat)
			}
		}

		// We open the DB
		db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
			Logger: logger.Default.LogMode(logger.Silent),
		})
		if err != nil {
			panic(fmt.Sprintf("failed to connect database %s", dbPath))
		}

		sqlDB, err := db.DB()
		if err != nil {
			panic("failed to get SQL DB handler")
		}
		defer sqlDB.Close()

		// Migrate the schema (this will create table or alter table if needed)
		if err = db.AutoMigrate(&Log{}); err != nil {
			return fmt.Errorf("unable to migrate logs schema in %s: %w", dbPath, err)
		}

		// We insert our log
		if insert {
			err = db.Create(l).Error
		} else {
			err = db.Save(l).Error
		}
		if err != nil {
			return fmt.Errorf("unable to save entry to database: %w", err)
		}

	}

	return
}
