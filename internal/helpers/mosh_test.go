package helpers

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMOSHRejectsUntrustedOptions(t *testing.T) {
	for _, options := range []string{
		"-c 8,--,/usr/bin/id", "-i 127.0.0.1,--,/bin/sh",
		"-l PATH=/tmp", "-l LD_PRELOAD=/tmp/lib.so", "-c --",
		"-c invalid", "-c -1", "-i not-an-address", "-l invalid",
		"-unknown ignored", "-c",
	} {
		t.Run(options, func(t *testing.T) {
			_, _, _, _, err := ParseArguments([]string{"sb", "-c", "mosh-server new " + options + " -- -i"})
			require.Error(t, err)
		})
	}
	for _, args := range [][]string{{"--", "/bin/sh"}, {"-p", "22"}, {"-l"}, {"-l", "LANG=x\nPATH=/tmp"}} {
		require.Error(t, ValidateMOSHArguments(args))
	}
}

func TestMOSHCommandPreservesArgumentBoundaries(t *testing.T) {
	// Only command construction is tested: this executable is never launched.
	dir := t.TempDir()
	executable, err := os.Executable()
	require.NoError(t, err)
	require.NoError(t, os.Symlink(executable, filepath.Join(dir, "mosh-server")))
	t.Setenv("PATH", dir)
	_, args, _, _, err := ParseArguments([]string{"sb", "-c", "mosh-server new -s -i ::1 -c 256 -l LANG=en_US.UTF-8,--,/bin/sh -- -i"})
	require.NoError(t, err)
	got, err := BuildMOSHCommand(args, "40000:49999")
	require.NoError(t, err)
	require.Equal(t, []string{filepath.Join(dir, "mosh-server"), "new", "-s", "-i", "::1", "-c", "256", "-l", "LANG=en_US.UTF-8,--,/bin/sh", "-p", "40000:49999", "--"}, got)
	for _, ports := range []string{"", "--", "0", "65536", "49999:40000", "1:2:3"} {
		_, err := BuildMOSHCommand(args, ports)
		require.Error(t, err)
	}
}

func TestParseEmptyForcedCommand(t *testing.T) {
	_, _, _, args, err := ParseArguments([]string{"sb", "-c", ""})
	require.NoError(t, err)
	require.Empty(t, args)
}

func FuzzParseArguments(f *testing.F) {
	for _, input := range []string{"", "mosh-server", "mosh-server new -c 8,--,/usr/bin/id -- -i", "user@host -- uptime", "mosh-server new -l LANG=en_US.UTF-8 -- -i"} {
		f.Add(input)
	}
	f.Fuzz(func(t *testing.T, input string) {
		client, args, _, _, err := ParseArguments([]string{"sb", "-c", input})
		if err == nil && client == "mosh" {
			require.NoError(t, ValidateMOSHArguments(args))
		}
	})
}
