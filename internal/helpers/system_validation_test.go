package helpers

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSystemHelpersRejectMaliciousNames verifies that every privileged helper
// that shells out to adduser/usermod/addgroup/deluser/groupmod fails closed when
// handed a flag-like name, BEFORE it can exec anything. These tests are hermetic
// precisely because validation short-circuits the function: a name like "-x"
// never reaches runCommand, so no sudo is invoked. The accepting path (a valid
// name) is covered by TestValidateSystemName; here we only assert the rejection
// reaches each entry point.
func TestSystemHelpersRejectMaliciousNames(t *testing.T) {
	const malicious = "-x" // would be parsed as a flag by the underlying tools

	tests := []struct {
		name string
		call func() error
	}{
		{
			name: "AddUser rejects flag-like username",
			call: func() error { return AddUser("/home/x", malicious, "/usr/local/bin/sb") },
		},
		{
			name: "AddGroup rejects flag-like group name",
			call: func() error { return AddGroup(malicious, "owner") },
		},
		{
			name: "AddGroup rejects flag-like owner account",
			call: func() error { return AddGroup("team", malicious) },
		},
		{
			name: "AddAccountInGroup rejects flag-like group name",
			call: func() error { return AddAccountInGroup(malicious, "alice", "m") },
		},
		{
			name: "AddAccountInGroup rejects flag-like account",
			call: func() error { return AddAccountInGroup("team", malicious, "m") },
		},
		{
			name: "RemoveAccountFromGroup rejects flag-like group name",
			call: func() error { return RemoveAccountFromGroup(malicious, "alice", "m") },
		},
		{
			name: "RemoveAccountFromGroup rejects flag-like account",
			call: func() error { return RemoveAccountFromGroup("team", malicious, "m") },
		},
		{
			name: "DeleteAccount rejects flag-like username",
			call: func() error { return DeleteAccount(malicious, "bak_1") },
		},
		{
			name: "DeleteGroup rejects flag-like group name",
			call: func() error { return DeleteGroup(malicious, "bak_1") },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.call()
			require.Error(t, err, "a flag-like name must be rejected before exec")
			require.Contains(t, err.Error(), "invalid name", "the error should come from name validation, not from a downstream exec")
		})
	}
}
