package models

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/golgeek/sb/internal/helpers"

	"github.com/stretchr/testify/require"
)

func TestNewLog(t *testing.T) {

	// Build a valid path for tests
	_, filename, _, _ := runtime.Caller(0)
	logsDatabase := fmt.Sprintf("%s/test_assets/log/logs.db", filepath.Dir(filename))

	os.Setenv("SSH_CONNECTION", "test 21519 sb.domain.tld 22")

	log := NewLog("test", []string{logsDatabase}, []string{"test"})
	require.IsType(t, &Log{}, log, "NewLog should return a Log{} object")

	require.NoError(t, log.SetAllowed(true))
	require.Equal(t, true, log.Allowed, "Allowed should be set to true after the SetAllowed() call")

	require.NoError(t, log.SetCommand("selfAddAccess"))
	require.Equal(t, "selfAddAccess", log.Command, "Command should be set to selfAddAccess after the SetCommand() call")

	ba, _ := BuildSBAccess("test.com", "root", "22022", "", false)
	require.NoError(t, log.SetTargetAccess(ba))
	require.Equal(t, "test.com", log.HostTo, "HostTo should be set to test.com after the SetTargetAccess() call")
	require.Equal(t, "22022", log.PortTo, "PortTo should be set to 22022 after the SetTargetAccess() call")
	require.Equal(t, "root", log.UserTo, "UserTo should be set to root after the SetTargetAccess() call")

	os.Remove(logsDatabase)
}

func TestLogLastSSHSessions(t *testing.T) {

	// Build a valid path for tests
	_, filename, _, _ := runtime.Caller(0)
	logsDatabase := fmt.Sprintf("%s/test_assets/log/sshsessions_test.db", filepath.Dir(filename))

	expectedSessions := []*helpers.SSHSession{
		{
			UniqID:    "27183a68-bf9e-4810-9250-f1308d428aeb",
			StartDate: time.Date(2020, 05, 07, 12, 52, 22, 519483, time.UTC),
			EndDate:   time.Date(2020, 05, 07, 13, 07, 22, 0, time.UTC),
			UserFrom:  "test",
			IPFrom:    "",
			PortFrom:  "22222",
			HostFrom:  "127.0.0.1",
			HostTo:    "meow.com",
			PortTo:    "555",
			UserTo:    "root",
			Allowed:   true,
		},
		{
			UniqID:    "c628b55c-0baf-45a8-84ce-a3ba5ddf11ee",
			StartDate: time.Date(2020, 05, 07, 12, 52, 02, 158443, time.UTC),
			EndDate:   time.Date(2020, 05, 07, 13, 07, 22, 0, time.UTC),
			UserFrom:  "test",
			IPFrom:    "",
			PortFrom:  "22222",
			HostFrom:  "127.0.0.1",
			HostTo:    "meow.com",
			PortTo:    "22022",
			UserTo:    "root",
			Allowed:   true,
		},
		{
			UniqID:    "95c6e39c-e510-4182-a623-eec2837a97a2",
			StartDate: time.Date(2020, 05, 07, 12, 51, 35, 163687, time.UTC),
			EndDate:   time.Date(2020, 05, 07, 13, 07, 22, 0, time.UTC),
			UserFrom:  "test",
			IPFrom:    "",
			PortFrom:  "22222",
			HostFrom:  "127.0.0.1",
			HostTo:    "meow.com",
			PortTo:    "22022",
			UserTo:    "test",
			Allowed:   false,
		},
	}

	sessions, err := GetLastSSHSessions(logsDatabase, 3)
	require.NoError(t, err, "An unexpected error occurred while calling GetLastSSHSessions")
	for i, session := range sessions {
		require.Equal(t, expectedSessions[i].UniqID, session.UniqID, "The session UniqID returned by GetLastSSHSessions do not match what we expected")
	}

}
