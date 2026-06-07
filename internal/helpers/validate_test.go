package helpers

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestValidateSystemName covers the security-critical name validation that
// guards every privileged adduser/usermod/addgroup/deluser/groupmod call. The
// table groups the cases by intent so a regression is easy to localise: legit
// names must pass, and every injection / namespace-collision shape must fail
// closed.
func TestValidateSystemName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		// Valid names: a leading lowercase letter then the allowed body.
		{name: "simple", input: "alice", wantErr: false},
		{name: "with digits", input: "alice2", wantErr: false},
		{name: "with underscore", input: "build_bot", wantErr: false},
		{name: "with internal hyphen", input: "ci-runner", wantErr: false},
		{name: "single letter", input: "a", wantErr: false},
		{name: "max length 31", input: "a" + strings.Repeat("b", 30), wantErr: false},

		// Argument injection: a name that adduser/usermod would read as a flag.
		{name: "leading hyphen", input: "-x", wantErr: true},
		{name: "long option", input: "--shell", wantErr: true},
		{name: "lone hyphen", input: "-", wantErr: true},

		// Characters that would split group lists or sudoers paths.
		{name: "comma", input: "a,b", wantErr: true},
		{name: "slash", input: "a/b", wantErr: true},
		{name: "dot", input: "a.b", wantErr: true},
		{name: "colon", input: "a:b", wantErr: true},
		{name: "space", input: "a b", wantErr: true},
		{name: "newline", input: "a\nb", wantErr: true},

		// Shape violations.
		{name: "empty", input: "", wantErr: true},
		{name: "leading digit", input: "2cool", wantErr: true},
		{name: "leading underscore", input: "_svc", wantErr: true},
		{name: "uppercase", input: "Alice", wantErr: true},
		{name: "too long 32", input: "a" + strings.Repeat("b", 31), wantErr: true},

		// Reserved names and the reserved group namespace.
		{name: "root", input: "root", wantErr: true},
		{name: "bg prefix", input: "bg_team", wantErr: true},
		{name: "bg prefix exact", input: "bg_", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSystemName(tt.input)
			if tt.wantErr {
				require.Error(t, err, "input %q should be rejected", tt.input)
			} else {
				require.NoError(t, err, "input %q should be accepted", tt.input)
			}
		})
	}
}

// TestValidateSystemNames asserts the multi-name wrapper rejects as soon as any
// one name is invalid and accepts only when all names are valid.
func TestValidateSystemNames(t *testing.T) {
	require.NoError(t, ValidateSystemNames("alice", "team", "ci-runner"))
	require.Error(t, ValidateSystemNames("alice", "-x"), "a single bad name must fail the batch")
	require.Error(t, ValidateSystemNames("-x", "alice"), "order must not matter")
	require.NoError(t, ValidateSystemNames(), "an empty batch with no names is a vacuous no-op")
}
