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

func init() {
	commands.RegisterCommand("ttyrec", func() (c commands.Command, r models.Right, h helpers.Helper, args map[string]commands.Argument) {
		return new(Ttyrec), models.HasAccess, helpers.Helper{
				Header:      "start an SSH session to a distant host with ttyrec enabled",
				Usage:       "ttyrec user@host",
				Description: "start an SSH session to a distant host with ttyrec enabled",
			}, map[string]commands.Argument{
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
			}
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

	// We override the currently stored access (which might be an alias) with the final one
	ct.Log.SetTargetAccess(access)

	// We will provide the ttyrec record path as a replication data for the post exec step
	repl = models.ReplicationData{
		"ttyrec-record-path": fmt.Sprintf("%s/%s.ttyrec", ct.User.GetTtyrecDirectory(), ct.Log.UniqID),
	}

	// Building the SSH command
	sshCommand, err := c.buildSSHCommand(access, ct.AI.KeyFilepathes, ct.RawArguments)
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

	// Handle ttyrec to a file
	go func(filename string, r io.Reader) (written int64, err error) {

		f, err := os.Create(filename)
		if err != nil {
			err = fmt.Errorf("unable to open ttyrec file: %w", err)
			return
		}
		defer f.Close()

		e := ttyrec.NewEncoder(f)

		written, err = io.Copy(e, r)
		if err != nil {
			err = fmt.Errorf("unable to write SSH session to ttyrec: %w", err)
			return
		}

		return
	}(
		repl["ttyrec-record-path"],
		io.MultiReader(
			io.TeeReader(stdout, os.Stdout),
			io.TeeReader(stderr, os.Stderr),
		),
	)

	// Start the command
	err = cmd.Start()
	if err != nil {
		err = fmt.Errorf("unable to start command: %w", err)
		return
	}

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

	cmd = []string{moshPath, "new"}
	cmd = append(cmd, moshArguments...)

	return
}

func (c *Ttyrec) buildSSHCommand(access *models.Access, keyfilePathes []string, rawArguments []string) (cmd []string, err error) {

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

	// Building the ssh command
	cmd = []string{
		sshPath, access.Host,
		"-l", access.User,
		"-p", fmt.Sprintf("%d", access.Port),
		"-A",
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
