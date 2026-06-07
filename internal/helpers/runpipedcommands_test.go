package helpers

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRunPipedCommands exercises the piped-command runner with small, universally
// available commands (echo/cat/true/false) so the test stays hermetic. It checks
// both that healthy pipelines succeed and that a failure at every stage — an
// empty argument list, a command that cannot start, the first command failing,
// and a downstream command exiting non-zero — is surfaced as an error rather than
// swallowed.
func TestRunPipedCommands(t *testing.T) {
	tests := []struct {
		name     string
		commands [][]string
		wantErr  bool
	}{
		{
			name:     "single successful command",
			commands: [][]string{{"true"}},
			wantErr:  false,
		},
		{
			name:     "two-stage pipeline succeeds",
			commands: [][]string{{"echo", "hello"}, {"cat"}},
			wantErr:  false,
		},
		{
			name:     "three-stage pipeline succeeds",
			commands: [][]string{{"echo", "hello"}, {"cat"}, {"cat"}},
			wantErr:  false,
		},
		{
			name:     "no commands is an error",
			commands: nil,
			wantErr:  true,
		},
		{
			name:     "single command that fails",
			commands: [][]string{{"false"}},
			wantErr:  true,
		},
		{
			name:     "downstream command exits non-zero",
			commands: [][]string{{"echo", "hello"}, {"false"}},
			wantErr:  true,
		},
		{
			name:     "downstream command cannot start",
			commands: [][]string{{"echo", "hello"}, {"/nonexistent/command/xyz"}},
			wantErr:  true,
		},
		{
			name:     "first command cannot run",
			commands: [][]string{{"/nonexistent/command/xyz"}},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := runPipedCommands(tt.commands...)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
