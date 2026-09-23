package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/golgeek/sb/internal/commands"
	"github.com/golgeek/sb/internal/config"
	"github.com/stretchr/testify/require"
)

func TestSessionMOSHPrefixes(t *testing.T) {
	dir := t.TempDir()
	executable, err := os.Executable()
	require.NoError(t, err)
	require.NoError(t, os.Symlink(executable, filepath.Join(dir, "mosh-server")))
	t.Setenv("PATH", dir)
	args := []string{"-c", "256", "-l", "LANG=en_US.UTF-8,--,/bin/sh"}
	want := append([]string{filepath.Join(dir, "mosh-server"), "new"}, args...)
	want = append(want, "-p", config.GetMOSHPortsRange(), "--")
	interactive, err := (&Interactive{}).buildMOSHCommand(&commands.Context{ClientArguments: args})
	require.NoError(t, err)
	require.Equal(t, want, interactive)
	ttyrec, err := (&Ttyrec{}).buildMOSHCommand(args)
	require.NoError(t, err)
	require.Equal(t, want, ttyrec)
	_, err = (&Interactive{}).buildMOSHCommand(&commands.Context{ClientArguments: []string{"--", "/bin/sh"}})
	require.Error(t, err)
	_, err = (&Ttyrec{}).buildMOSHCommand([]string{"-c", "8,--,/bin/sh"})
	require.Error(t, err)
}
