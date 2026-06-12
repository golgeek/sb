package commands

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestExitErrorMessage asserts ExitError preserves the user-visible wording
// of the historical untyped errors: the message is the underlying cause's
// message, with a defensive fallback when the cause is missing.
func TestExitErrorMessage(t *testing.T) {

	t.Run("message delegates to the underlying cause", func(t *testing.T) {
		e := &ExitError{Code: 3, Err: fmt.Errorf("exit status 3")}
		require.EqualError(t, e, "exit status 3")
	})

	t.Run("wrapped cause keeps the command-specific context", func(t *testing.T) {
		// ttyrec wraps the egress ssh failure with its historical message;
		// the typed error must surface it unchanged.
		cause := fmt.Errorf("failed to execute command on distant host: %w", fmt.Errorf("exit status 3"))
		e := &ExitError{Code: 3, Err: cause}
		require.EqualError(t, e, "failed to execute command on distant host: exit status 3")
	})

	t.Run("missing cause falls back to the exit code", func(t *testing.T) {
		e := &ExitError{Code: 7}
		require.EqualError(t, e, "exit status 7")
	})
}

// TestExitErrorUnwrap asserts the typed error participates in errors.Is /
// errors.As chains: callers find the *ExitError through any wrapping, and the
// underlying cause stays reachable through the ExitError itself.
func TestExitErrorUnwrap(t *testing.T) {

	cause := fmt.Errorf("exit status 3")
	var err error = &ExitError{Code: 3, Err: cause}

	require.ErrorIs(t, err, cause, "the underlying cause must stay reachable via Unwrap")

	// Wrapping the typed error (as a dispatch layer might) must not hide it.
	wrapped := fmt.Errorf("session ended: %w", err)
	var exitErr *ExitError
	require.True(t, errors.As(wrapped, &exitErr))
	require.Equal(t, 3, exitErr.Code)
}
