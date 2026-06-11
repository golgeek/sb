package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/golgeek/sb/internal/commands"
	"github.com/golgeek/sb/internal/config"
	"github.com/golgeek/sb/internal/helpers"
	"github.com/golgeek/sb/internal/models"
	"github.com/golgeek/sb/internal/storage"
	"maze.io/x/ttyrec"

	"github.com/fatih/color"
)

// Ttyrec describes the ttyrec command
type Ttyrec struct{}

// lockedWriter serializes writes to an underlying writer behind a mutex. The
// session's stdout and stderr are drained by two separate goroutines that both
// record into the same ttyrec.Encoder, which is not safe for concurrent use; a
// lockedWriter wrapping the encoder makes each frame write atomic so the two
// streams can be recorded as they arrive without corrupting the recording.
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

// Write forwards p to the wrapped writer while holding the mutex, so concurrent
// callers never interleave a single frame. It returns the wrapped writer's
// result unchanged.
func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func init() {
	commands.Register(commands.CommandSpec{
		Name:   "ttyrec",
		Rights: models.HasAccess,
		Help: helpers.Helper{
			Header:      "start an SSH session to a distant host with ttyrec enabled",
			Usage:       "ttyrec user@host",
			Description: "start an SSH session to a distant host with ttyrec enabled",
		},
		Args: map[string]commands.Argument{
			"access": {
				Required:    true,
				Description: "The host to access",
			},
			"client": {
				Required:    true,
				Description: "The client to use SSH or MOSH",
			},
			"client-arguments": {
				Required: false,
			},
		},
		Trusted: true,
		New:     func() commands.Command { return new(Ttyrec) },
	})
}

// Checks checks whether or not the user can execute this method
func (c *Ttyrec) Checks(ct *commands.Context) error {
	return nil
}

// Execute executes the command
func (c *Ttyrec) Execute(ct *commands.Context) (repl models.ReplicationData, cmdError error, err error) {

	c.displayHeader(ct.User.User.Username)

	c.displayMatchingGrants(ct.AI.Sources)

	access, err := c.getUniqueAccessFromAvailableAccesses(ct.AI.Accesses, ct.BA.Host)
	if err != nil {
		return
	}

	// We override the currently stored access (which might be an alias) with the
	// final one. This is a best-effort audit write, so a failure is logged rather
	// than aborting the connection the user is establishing.
	if err := ct.Log.SetTargetAccess(access); err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: unable to persist target access in audit log: %s\n", err)
	}

	// We will provide the ttyrec record path as a replication data for the post exec step
	repl = models.ReplicationData{
		"ttyrec-record-path": fmt.Sprintf("%s/%s.ttyrec", ct.User.GetTtyrecDirectory(), ct.Log.UniqID),
	}

	// Building the SSH command. The egress hop pins host-key verification
	// against the user's managed known_hosts with the configured policy
	// (TOFU-with-pinning by default), so the session and the forwarded agent are
	// never silently exposed to a host whose key has changed.
	sshCommand, err := c.buildSSHCommand(access, ct.AI.KeyFilepathes, ct.RawArguments, ct.User.GetKnownHostsFilepath(), config.GetEgressStrictHostKeyChecking())
	if err != nil {
		return
	}

	// In case client is mosh, mosh-server will launch ttyrec that will launch ssh
	if ct.FormattedArguments["client"] == "mosh" {
		moshCommand, errMosh := c.buildMOSHCommand(ct.FormattedArguments["client-arguments"])
		if errMosh != nil {
			err = errMosh
			return
		}

		sshCommand = append(moshCommand, sshCommand...)
	}

	fmt.Printf("... connecting you to the distant host (if it's alive :)) ...\n")
	fmt.Printf("---\n")

	// Creating command
	cmd := exec.Command(sshCommand[0], sshCommand[1:]...)

	// Piping stdin, stdout and stderr
	cmd.Stdin = os.Stdin
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		err = fmt.Errorf("unable to open stdout pipe: %w", err)
		return
	}
	defer stdout.Close()
	stderr, err := cmd.StderrPipe()
	if err != nil {
		err = fmt.Errorf("unable to open stderr pipe: %w", err)
		return
	}
	defer stderr.Close()

	// Watch the egress stderr for a host-key-mismatch so we can hand the user a
	// recovery hint after the connection is refused. It is one leg of the stderr
	// fan-out below, so the real error output is unaffected.
	hostKeyWatcher := &helpers.HostKeyWatcher{}

	// Open the recording file up front so a failure is reported immediately
	// rather than from inside a goroutine. Recording is best-effort: if the file
	// cannot be created we still run a live session, writing the recording to
	// io.Discard, so a recording problem never blocks the user's connection.
	// Both stream copiers below share this single encoder, serialized by
	// lockedWriter because ttyrec.Encoder is not safe for concurrent use.
	// io.Discard is typed io.Writer, so rec stays an io.Writer that the
	// successful branch can reassign to the recording encoder.
	rec := io.Discard
	if f, ferr := os.Create(repl["ttyrec-record-path"]); ferr != nil {
		fmt.Fprintf(os.Stderr, "ERROR: unable to open ttyrec file: %s\n", ferr)
	} else {
		defer f.Close()
		rec = &lockedWriter{w: ttyrec.NewEncoder(f)}
	}

	// Start the command
	err = cmd.Start()
	if err != nil {
		err = fmt.Errorf("unable to start command: %w", err)
		return
	}

	// Drain stdout and stderr CONCURRENTLY, each in its own goroutine. The
	// previous implementation wrapped both pipes in a single io.MultiReader,
	// which reads stdout to EOF — i.e. until the egress process exits — before it
	// ever touches stderr. ssh writes its own diagnostics (host-key mismatch,
	// "Permission denied", connection errors) to stderr, so that ordering hid
	// every error from the user until the session was already over, starved the
	// host-key watcher of its input until shutdown, and recorded all of stderr
	// appended after all of stdout instead of in the order they actually
	// occurred. Copying each stream independently forwards errors to the terminal
	// the instant ssh emits them and records frames in true arrival order. Each
	// stream fans out to the terminal and the recorder; stderr additionally feeds
	// the host-key watcher.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if _, cerr := io.Copy(io.MultiWriter(os.Stdout, rec), stdout); cerr != nil {
			fmt.Fprintf(os.Stderr, "ERROR: unable to record session stdout: %s\n", cerr)
		}
	}()
	go func() {
		defer wg.Done()
		if _, cerr := io.Copy(io.MultiWriter(os.Stderr, hostKeyWatcher, rec), stderr); cerr != nil {
			fmt.Fprintf(os.Stderr, "ERROR: unable to record session stderr: %s\n", cerr)
		}
	}()

	// Both pipes reach EOF when the egress process closes them (i.e. when it
	// exits), so this returns once the session output is fully drained and
	// scanned — which must happen before Wait closes the pipes out from under
	// the readers.
	wg.Wait()

	// Wait until user exits the shell
	err = cmd.Wait()
	if err != nil {

		var ok bool
		cmdError, ok = err.(*exec.ExitError)
		if !ok {
			err = fmt.Errorf("unable to wait for command: %w", err)
			return
		}

		err = nil
	}

	fmt.Printf("<< Exited shell: %s\n", cmd.ProcessState.String())

	if cmd.ProcessState.ExitCode() > 0 {
		cmdError = fmt.Errorf("failed to execute command on distant host: %w", cmdError)
	}

	// If the connection was refused because the distant host's key changed, give
	// the user a copy-pasteable command to clear the stale pin (gated on trust).
	if hostKeyWatcher.Triggered() {
		fmt.Fprint(os.Stderr, helpers.HostKeyMismatchHint(
			ct.User.User.Username, config.GetSBHostname(), config.GetSSHPort(),
			access.Host, access.Port,
		))
	}

	return
}

func (c *Ttyrec) Replicate(repl models.ReplicationData) (err error) {
	return
}

func (c *Ttyrec) PostExecute(repl models.ReplicationData) (err error) {

	// If TTYRecs offloading is enabled, we offload the ttyrec to a storage
	ttyRecsOffloadingConfig := config.GetTTYRecsOffloadingConfig()
	if !ttyRecsOffloadingConfig.Enabled {
		fmt.Println("Replication is not enabled, no need to off-load to GCS...")
		return
	}

	rs, err := storage.GetStorage(ttyRecsOffloadingConfig)
	if err != nil {
		return
	}

	// Let's start by generating the filenames we'll require
	filename := repl["ttyrec-record-path"]
	encryptedFilename := fmt.Sprintf("%s.bin", filename)

	fmt.Printf("Starting to push %s to a storage\n", filename)

	// Encrypt the file
	fmt.Printf("Encrypting the file...")
	err = helpers.EncryptFile(filename, encryptedFilename, config.GetEncryptionKey())
	if err != nil {
		return
	}

	// Push the file to the storage
	fmt.Printf("Pushing the file to storage...")
	err = rs.PushToStorage(filepath.Base(encryptedFilename), encryptedFilename)
	if err != nil {
		return
	}

	// Remove encrypted and original ttyrec from local disk
	err = os.Remove(filename)
	if err != nil {
		return
	}
	err = os.Remove(encryptedFilename)
	if err != nil {
		return
	}

	return
}

func (c *Ttyrec) askForAccessToUse(availableAccesses []*models.Access) (a *models.Access, err error) {

	fmt.Printf("Multiple configuration of granted accesses match your request:\n")
	for id, availableAccesses := range availableAccesses {
		fmt.Printf("%d: %s\n", id+1, availableAccesses.ShortString())
	}

	var idAsInt int
	for idAsInt == 0 {

		fmt.Print("Please enter the ID of the granted configuration you want to connect to: ")

		// Scan stdin to get the key to delete
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		id := scanner.Text()

		idAsInt, err = c.checkAccessInput(id, availableAccesses)
		if err != nil {
			fmt.Printf("Error: %s\n", err)
		}

	}

	a = availableAccesses[idAsInt-1]

	return
}

func (c *Ttyrec) buildMOSHCommand(clientArguments string) (cmd []string, err error) {

	moshPath, err := exec.LookPath("mosh-server")
	if err != nil {
		fmt.Printf("Unable to find ssh on system: %s\n", err)
		return
	}

	moshArguments := strings.Split(clientArguments, ",")
	moshArguments = append(moshArguments, "-p", config.GetMOSHPortsRange(), "--")

	cmd = make([]string, 0, 2+len(moshArguments))
	cmd = append(cmd, moshPath, "new")
	cmd = append(cmd, moshArguments...)

	return
}

func (c *Ttyrec) buildSSHCommand(access *models.Access, keyfilePathes []string, rawArguments []string, knownHostsFile, strictHostKeyChecking string) (cmd []string, err error) {

	// Set sb environment
	for _, envVar := range config.GetEnvironmentVarsToForward() {
		os.Setenv(fmt.Sprintf("LC_SB_%s", strings.ToUpper(envVar)), os.Getenv(envVar))
	}

	// Get ssh command path on the system
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		fmt.Printf("Unable to find ssh on system: %s\n", err)
		return
	}

	// Building the ssh command. Host-key verification is pinned explicitly
	// rather than left to inherited ssh defaults: -oUserKnownHostsFile points at
	// the user's managed known_hosts and -oStrictHostKeyChecking carries the
	// configured policy (accept-new by default: pin on first sight, refuse a
	// later changed key). -A keeps agent forwarding for onward auth from the
	// distant host.
	cmd = []string{
		sshPath, access.Host,
		"-l", access.User,
		"-p", fmt.Sprintf("%d", access.Port),
		"-A",
		fmt.Sprintf("-oUserKnownHostsFile=%s", knownHostsFile),
		fmt.Sprintf("-oStrictHostKeyChecking=%s", strictHostKeyChecking),
	}

	// We push environment variables to forward
	for _, envVar := range config.GetEnvironmentVarsToForward() {
		cmd = append(cmd, "-o", fmt.Sprintf("SendEnv=LC_SB_%s", strings.ToUpper(envVar)))
	}

	// We push the private keys to use
	for _, privateKeyFile := range keyfilePathes {
		cmd = append(cmd, "-i", privateKeyFile)
	}

	// Append the other arguments the user gave us
	if len(rawArguments) > 0 {
		cmd = append(cmd, "--")
		cmd = append(cmd, rawArguments...)
	}

	return
}

func (c *Ttyrec) checkAccessInput(id string, availableAccesses []*models.Access) (idAsInt int, err error) {
	idAsInt, err = strconv.Atoi(id)
	if err != nil || idAsInt > len(availableAccesses) || idAsInt < 1 {
		err = fmt.Errorf("input provided is not a digit on the allowed range [%d-%d]", 1, len(availableAccesses))
		idAsInt = 0
		return
	}
	return
}

func (c *Ttyrec) displayHeader(username string) {

	green := color.New(color.FgGreen).SprintFunc()

	fmt.Printf(`*------------------------------------------------------------------------------*
|THIS IS A PRIVATE COMPUTER SYSTEM, UNAUTHORIZED ACCESS IS STRICTLY PROHIBITED.|
|ALL CONNECTIONS ARE LOGGED. IF YOU ARE NOT AUTHORIZED, DISCONNECT NOW.        |
*------------------------------------------------------------------------------*
`)
	fmt.Printf("Hey! Welcome to %s, %s!\n", green(config.GetSBName()), green(username))

}

func (c *Ttyrec) displayMatchingGrants(sources []*models.Source) {

	// We display which rules matched
	sourcesDisplay := make([]string, 0, len(sources))
	for _, source := range sources {
		sourcesDisplay = append(sourcesDisplay, source.String())
	}
	fmt.Printf("Access to this host is granted by:\n%s\n", strings.Join(sourcesDisplay, "\n"))
}

func (c *Ttyrec) getUniqueAccessFromAvailableAccesses(accesses []*models.Access, host string) (a *models.Access, err error) {

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

	return c.askForAccessToUse(uniqueAccesses)
}
