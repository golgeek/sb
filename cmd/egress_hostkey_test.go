package cmd

import (
	"os/exec"
	"testing"

	"github.com/golgeek/sb/internal/models"

	"github.com/stretchr/testify/require"
)

// TestScpBuildEgressBaseCommand asserts the SCP egress prefix pins host-key
// verification explicitly: it must carry the user's managed known_hosts file
// and the requested StrictHostKeyChecking policy, alongside the existing
// hardening options, port, login user and each private key. It deliberately
// stops before the "-- host <command>" tail so both legacy and SFTP modes can
// reuse it.
func TestScpBuildEgressBaseCommand(t *testing.T) {
	c := new(Scp)
	access := &models.Access{Host: "prod-web", User: "deploy", Port: 2222}

	cmd := c.buildEgressBaseCommand(
		"/usr/bin/ssh", access,
		[]string{"/home/alice/.ssh/id_a", "/home/alice/.ssh/id_b"},
		"/home/alice/.ssh/known_hosts", "accept-new",
	)

	require.Equal(t, "/usr/bin/ssh", cmd[0])
	require.Contains(t, cmd, "-oUserKnownHostsFile=/home/alice/.ssh/known_hosts")
	require.Contains(t, cmd, "-oStrictHostKeyChecking=accept-new")
	require.Contains(t, cmd, "-oForwardAgent=no")
	require.Subset(t, cmd, []string{"-p", "2222"})
	require.Subset(t, cmd, []string{"-l", "deploy"})
	require.Subset(t, cmd, []string{"-i", "/home/alice/.ssh/id_a"})
	require.Subset(t, cmd, []string{"-i", "/home/alice/.ssh/id_b"})

	// The transparent transfer tail is the caller's responsibility, so the host
	// must not yet be present in the base command.
	require.NotContains(t, cmd, "prod-web")
}

// TestTtyrecBuildSSHCommand asserts the interactive egress command pins host-key
// verification while keeping agent forwarding enabled for onward auth.
func TestTtyrecBuildSSHCommand(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh not available on this system")
	}

	c := new(Ttyrec)
	access := &models.Access{Host: "prod-db", User: "root", Port: 22}

	cmd, err := c.buildSSHCommand(
		access,
		[]string{"/home/bob/.ssh/id_x"},
		nil,
		"/home/bob/.ssh/known_hosts", "yes",
	)
	require.NoError(t, err)

	require.Contains(t, cmd, "-oUserKnownHostsFile=/home/bob/.ssh/known_hosts")
	require.Contains(t, cmd, "-oStrictHostKeyChecking=yes")
	require.Contains(t, cmd, "-A")
	require.Subset(t, cmd, []string{"-i", "/home/bob/.ssh/id_x"})
}
