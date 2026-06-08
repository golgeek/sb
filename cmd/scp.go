package cmd

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"syscall"

	"github.com/golgeek/sb/internal/commands"
	"github.com/golgeek/sb/internal/config"
	"github.com/golgeek/sb/internal/helpers"
	"github.com/golgeek/sb/internal/models"

	"golang.org/x/term"
)

// Scp describes the help command
type Scp struct{}

func init() {
	commands.RegisterCommand("scp", func() (c commands.Command, r models.Right, helper helpers.Helper, args map[string]commands.Argument) {
		return new(Scp), models.HasAccess, helpers.Helper{
				Header: "transfer a file from or to a distant host through sb",
				Usage:  "proxy [--get-script | --access HOST --scp-cmd CMD]",
				Description: fmt.Sprintf(`This command allows the transfer of a file from or to a distant host through sb.
             This requires the execution of script in complement of your usual scp command.
             To get this running, execute the following commands:
                 %s scp --get-script > ~/.%sscp && chmod +x ~/.%sscp
                 alias %sscp='scp -O -S ~/.%sscp '
			 And voila, you're all set: just run the command '%sscp' as you would run 'scp'!`,
					config.GetSBName(), config.GetSBName(), config.GetSBName(), config.GetSBName(), config.GetSBName(), config.GetSBName()),
			}, map[string]commands.Argument{
				"access": {
					Required:    false,
					Description: "The IP, host or alias of the distant host",
				},
				"scp-cmd": {
					Required:    false,
					Description: "The actual SCP command",
				},
				"get-script": {
					Required:    false,
					Description: "Get the SCP script",
					Type:        commands.BOOL,
				},
			}
	})
}

// Checks checks whether or not the user can execute this method
func (c *Scp) Checks(ct *commands.Context) error {

	scpValidRegexp := regexp.MustCompile(`^scp (-r )?(-f|-t) .*`)

	// In case an access was provided and verified
	if ct.AI != nil {

		// And we check we have a scp-cmd
		if ct.FormattedArguments["scp-cmd"] == "" {
			return fmt.Errorf("argument scp-cmd should be provided")
		}

		if !scpValidRegexp.MatchString(ct.FormattedArguments["scp-cmd"]) {
			return fmt.Errorf("argument scp-cmd should be a scp internal formated command")
		}

	}
	return nil
}

// Execute executes the command
func (c *Scp) Execute(ct *commands.Context) (repl models.ReplicationData, cmdError error, err error) {

	// We have three cases:
	//   - user calls scp with no arguments, we need to display the help
	//   - user calls scp --get-script, we will return the script that makes it work
	//   - user calls scp --host host --scp-cmd, we execute the scp cmd

	_, ok := ct.FormattedArguments["get-script"]

	// case with no arguments at all
	if !ok && ct.AI == nil {
		// Let's just print the help
		_, _, commandHlprs, cas, errCmd := commands.GetCommand("scp")
		if err != nil {
			return repl, cmdError, errCmd
		}
		commands.DisplayHelpers(commandHlprs, cas)
		return
	}

	// Case with --get-script
	if ok {
		// We set stdout in raw mode to avoid \r\n transformations by ssh -t on client side
		_, err = term.MakeRaw(syscall.Stdout)
		if err != nil {
			return
		}

		fmt.Printf("%s", helpers.GetScpScript(ct.User.User.Username, config.GetSBHostname(), config.GetSSHPort()))
		return
	}

	// We should have everything to scp something to somewhere
	// If we're here, rights are already checked
	access, err := c.getUniqueAccessFromAvailableAccesses(ct.AI.Accesses, ct.BA.Host)
	if err != nil {
		fmt.Printf("Error: %s", err)
		return
	}
	// Best-effort audit write; log a failure rather than aborting the transfer.
	if err := ct.Log.SetTargetAccess(access); err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: unable to persist target access in audit log: %s\n", err)
	}

	// Get ssh command path on the system
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		fmt.Printf("Unable to find ssh on system: %s\n", err)
		return
	}

	// Build the egress command prefix (ssh options + port/user/keys, with
	// host-key verification pinned), then append the transparent transfer tail.
	command := c.buildEgressBaseCommand(sshPath, access, ct.AI.KeyFilepathes, ct.User.GetKnownHostsFilepath(), config.GetEgressStrictHostKeyChecking())
	command = append(command,
		"--",
		access.Host,
		ct.FormattedArguments["scp-cmd"],
	)

	// Watch the egress stderr for a host-key mismatch so we can surface a
	// recovery hint; it shadows os.Stderr and does not alter the real output.
	hostKeyWatcher := &helpers.HostKeyWatcher{}

	cmd := exec.Command(command[0], command[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = io.MultiWriter(os.Stderr, hostKeyWatcher)

	err = cmd.Start()
	if err != nil {
		return
	}

	err = cmd.Wait()
	if err != nil {
		var ok bool
		cmdError, ok = err.(*exec.ExitError)
		if !ok {
			return
		}
		err = nil
	}

	// If the host key changed, point the user at the forget command (gated on trust).
	if hostKeyWatcher.Triggered() {
		fmt.Fprint(os.Stderr, helpers.HostKeyMismatchHint(
			ct.User.User.Username, config.GetSBHostname(), config.GetSSHPort(),
			access.Host, access.Port,
		))
	}

	return
}

// buildEgressBaseCommand assembles the common prefix of the egress SSH command
// used to proxy a transfer to a distant host: the ssh binary, the hardening
// options (agent forwarding off, no local command, all forwardings cleared),
// pinned host-key verification against the user's managed known_hosts with the
// configured policy, the target port and login user, and each private key.
//
// It deliberately stops before the "-- host <command>" tail so callers can
// append either the legacy "scp -t/-f" command or, in SFTP mode, an sftp
// subsystem request, keeping a single place that owns the security-relevant
// options. The returned slice's first element is sshPath.
func (c *Scp) buildEgressBaseCommand(sshPath string, access *models.Access, keyFiles []string, knownHostsFile, strictHostKeyChecking string) []string {
	// 11 fixed elements (ssh path, the hardening/host-key options, -p/-l pairs)
	// plus two entries per private key.
	command := make([]string, 0, 11+2*len(keyFiles))
	command = append(command,
		sshPath,
		"-x",
		"-oForwardAgent=no",
		"-oPermitLocalCommand=no",
		"-oClearAllForwardings=yes",
		fmt.Sprintf("-oUserKnownHostsFile=%s", knownHostsFile),
		fmt.Sprintf("-oStrictHostKeyChecking=%s", strictHostKeyChecking),
		"-p", strconv.Itoa(access.Port),
		"-l", access.User,
	)
	for _, privateKeyFile := range keyFiles {
		command = append(command, "-i", privateKeyFile)
	}
	return command
}

func (c *Scp) PostExecute(repl models.ReplicationData) (err error) {
	return
}

func (c *Scp) Replicate(repl models.ReplicationData) (err error) {
	return
}

func (c *Scp) getUniqueAccessFromAvailableAccesses(accesses []*models.Access, host string) (a *models.Access, err error) {

	// We initialize with the first access returned
	uniqueAccesses := make([]*models.Access, 0)

	for i := 0; i < len(accesses); i++ {
		unique := true

		// In case of a wide prefix stored access, we replace the Host by the user input
		if accesses[i].Host == "" {
			accesses[i].Host = host
		}

		for _, ua := range uniqueAccesses {
			if accesses[i].Equals(ua) {
				unique = false
			}
		}

		if unique {
			uniqueAccesses = append(uniqueAccesses, accesses[i])
		}
	}

	if len(uniqueAccesses) == 1 {
		return uniqueAccesses[0], nil
	}

	return a, fmt.Errorf("can't request fine access from user input in SCP context")
}
