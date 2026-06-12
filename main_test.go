package main

import (
	"fmt"
	"testing"

	"github.com/golgeek/sb/internal/commands"
	"github.com/golgeek/sb/internal/types"

	"github.com/stretchr/testify/require"
)

// TestSessionExitStatus pins the dispatch-result → process-exit-code mapping:
// sentinels keep their historical codes (and now match through wrapping), a
// remote command's exit code propagates as the bastion's own exit code, and
// everything else stays a generic failure.
func TestSessionExitStatus(t *testing.T) {

	tests := []struct {
		name        string
		err         error
		wantCode    int
		wantMessage string
	}{
		{
			name:     "success",
			err:      nil,
			wantCode: 0,
		},
		{
			name:        "disabled command",
			err:         types.ErrCommandDisabled,
			wantCode:    126,
			wantMessage: "This command is disabled",
		},
		{
			name: "wrapped disabled command still matches",
			// The historical == comparison missed a wrapped sentinel; the
			// errors.Is mapping must not.
			err:         fmt.Errorf("dispatch: %w", types.ErrCommandDisabled),
			wantCode:    126,
			wantMessage: "This command is disabled",
		},
		{
			name:     "missing arguments",
			err:      types.ErrMissingArguments,
			wantCode: 2,
		},
		{
			name:     "wrapped missing arguments still matches",
			err:      fmt.Errorf("dispatch: %w", types.ErrMissingArguments),
			wantCode: 2,
		},
		{
			name: "remote exit code propagates",
			err: &commands.ExitError{
				Code: 3,
				Err:  fmt.Errorf("failed to execute command on distant host: exit status 3"),
			},
			wantCode:    3,
			wantMessage: "Error while executing command: failed to execute command on distant host: exit status 3",
		},
		{
			name: "wrapped remote exit still propagates",
			err: fmt.Errorf("session: %w", &commands.ExitError{
				Code: 5,
				Err:  fmt.Errorf("exit status 5"),
			}),
			wantCode:    5,
			wantMessage: "Error while executing command: session: exit status 5",
		},
		{
			name: "signal death maps to the generic failure code",
			// exec reports -1 when the process was killed by a signal; a
			// process exit code cannot express that, so it maps to 1.
			err:         &commands.ExitError{Code: -1, Err: fmt.Errorf("signal: killed")},
			wantCode:    1,
			wantMessage: "Error while executing command: signal: killed",
		},
		{
			name:        "internal error stays a generic failure",
			err:         fmt.Errorf("unable to open database"),
			wantCode:    1,
			wantMessage: "Error while executing command: unable to open database",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, message := sessionExitStatus(tt.err)
			require.Equal(t, tt.wantCode, code)
			require.Equal(t, tt.wantMessage, message)
		})
	}
}
