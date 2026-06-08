package cmd

import (
	"testing"

	"github.com/golgeek/sb/internal/commands"
	"github.com/golgeek/sb/internal/models"

	"github.com/stretchr/testify/require"
)

// TestScpChecks covers the dual-mode validation boundary: SFTP mode is accepted
// when scp-cmd carries the fixed "sftp" subsystem sentinel (nothing further to
// inspect), while legacy mode still requires a scp-cmd shaped like the internal
// scp sub-protocol. The get-script / help path (no access resolved) is always
// allowed.
func TestScpChecks(t *testing.T) {
	c := new(Scp)
	withAccess := &models.Info{}

	cases := []struct {
		name    string
		ctx     *commands.Context
		wantErr bool
	}{
		{
			name:    "no access resolved is allowed",
			ctx:     &commands.Context{AI: nil, FormattedArguments: map[string]string{}},
			wantErr: false,
		},
		{
			name:    "sftp mode via scp-cmd token passes",
			ctx:     &commands.Context{AI: withAccess, FormattedArguments: map[string]string{"scp-cmd": "sftp"}},
			wantErr: false,
		},
		{
			name:    "legacy mode with valid scp-cmd passes",
			ctx:     &commands.Context{AI: withAccess, FormattedArguments: map[string]string{"scp-cmd": "scp -t /tmp/x"}},
			wantErr: false,
		},
		{
			name:    "legacy mode missing scp-cmd fails",
			ctx:     &commands.Context{AI: withAccess, FormattedArguments: map[string]string{}},
			wantErr: true,
		},
		{
			name:    "legacy mode with malformed scp-cmd fails",
			ctx:     &commands.Context{AI: withAccess, FormattedArguments: map[string]string{"scp-cmd": "rm -rf /"}},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := c.Checks(tc.ctx)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestScpAppendTransferTail asserts the mode-specific tail: SFTP requests the
// sftp subsystem (ssh -s ... host sftp) and ignores any scp-cmd, while legacy
// runs the verbatim scp sub-protocol command after the host.
func TestScpAppendTransferTail(t *testing.T) {
	c := new(Scp)
	base := []string{"/usr/bin/ssh", "-x"}

	t.Run("sftp mode requests the subsystem", func(t *testing.T) {
		got := c.appendTransferTail(base, "prod-web", true, "ignored")
		require.Equal(t, []string{"/usr/bin/ssh", "-x", "-s", "--", "prod-web", "sftp"}, got)
	})

	t.Run("legacy mode runs the scp command", func(t *testing.T) {
		got := c.appendTransferTail(base, "prod-web", false, "scp -t /tmp/x")
		require.Equal(t, []string{"/usr/bin/ssh", "-x", "--", "prod-web", "scp -t /tmp/x"}, got)
	})
}
