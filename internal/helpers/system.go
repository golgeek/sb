package helpers

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/golgeek/sb/internal/config"
	"golang.org/x/crypto/ssh"
)

var (
	etcGroupFilePath  string
	etcPasswdFilePath string
)

// AddAccountInGroup adds an account in a group's membership group
func AddAccountInGroup(groupName string, account string, membershipType string) (err error) {

	// Fail closed on the privilege boundary: both names are passed to usermod, so
	// reject anything that could be parsed as a flag or break the group list
	// before we shell out.
	if err = ValidateSystemNames(groupName, account); err != nil {
		return
	}

	// Build the true groupname and all the groups names
	if !strings.HasPrefix(groupName, "bg_") {
		groupName = fmt.Sprintf("bg_%s", groupName)
	}

	actualGroupName := groupName
	switch membershipType {
	case "o", "gk", "aclk":
		actualGroupName = fmt.Sprintf("%s-%s", groupName, membershipType)
	case "m":
		// Nothing to do
	default:
		err = fmt.Errorf("membershipType's value should be from the list: o, gk, aclk, m")
		return
	}

	// Add the owner account in all the groups
	command := []string{"/usr/bin/sudo", "/usr/sbin/usermod", "-a", "-G", actualGroupName, account}
	return runCommand(command[0], command[1:]...)
}

// AddGroup creates a new group on the system
func AddGroup(groupname string, ownerAccount string) (err error) {

	// Creating one group really means:
	//    - creating the group as bg_GROUPNAME
	//    - creating the group as bg_GROUPNAME-o
	//    - creating the group as bg_GROUPNAME-gk
	//    - creating the group as bg_GROUPNAME-aclk
	//    - creating a user for the group as bg_GROUPNAME
	//    - adding a /etc/sudoers.d template for the group
	//    - putting ownerAccount in all the created groups
	//    - create the skelleton of the home folder

	// Fail closed on the privilege boundary: the group name flows into addgroup,
	// adduser, usermod, the comma-separated -G list and the /etc/sudoers.d/<group>
	// path, and the owner account flows into usermod, so both must be validated
	// before we shell out.
	if err = ValidateSystemNames(groupname, ownerAccount); err != nil {
		return
	}

	// Build the true groupname and all the groups names
	if !strings.HasPrefix(groupname, "bg_") {
		groupname = fmt.Sprintf("bg_%s", groupname)
	}
	groups := make([]string, 0, 4)
	groups = append(groups, groupname)
	for _, suffix := range []string{"o", "gk", "aclk"} {
		groups = append(groups, fmt.Sprintf("%s-%s", groupname, suffix))
	}

	// We'll build all commands, and the then execute them
	commands := make([][]string, 0, len(groups)+1+1)

	// Build commands to create all the groups
	for _, group := range groups {
		commands = append(commands, []string{"/usr/bin/sudo", "/usr/sbin/addgroup", group})
	}

	// Build the command to create a user for the group
	commands = append(commands, []string{
		"/usr/bin/sudo",
		"/usr/sbin/adduser",
		"--home", fmt.Sprintf("/home/%s", groupname),
		"--shell", "/usr/sbin/nologin",
		"--ingroup", groupname,
		"--disabled-password",
		"--gecos", "''",
		groupname,
	})

	// Add the owner account in all the groups
	commands = append(commands, []string{"/usr/bin/sudo", "/usr/sbin/usermod", "-a", "-G", strings.Join(groups, ","), ownerAccount})

	// Add the group's sudoers file
	err = runPipedCommands([]string{"echo", getGroupSudoersTemplate(groupname)}, []string{"/usr/bin/sudo", "tee", fmt.Sprintf("/etc/sudoers.d/%s", groupname)})
	if err != nil {
		return
	}

	// Execute all commands
	for _, command := range commands {
		err := runCommand(command[0], command[1:]...)
		if err != nil {
			return err
		}
	}

	return CreateHomeSkeleton(fmt.Sprintf("/home/%s", groupname), groupname, "group")
}

// AddUser creates a new user on the system
func AddUser(homedir, username, shellPath string) (err error) {

	// Fail closed on the privilege boundary: the username is passed to adduser and
	// usermod, so reject anything that could be parsed as a flag before we shell
	// out. homedir and shellPath are sb-derived, not user-supplied, so they are
	// not validated here.
	if err = ValidateSystemName(username); err != nil {
		return
	}

	commands := make([][]string, 0, 2)

	// Calling adduser
	commands = append(commands, []string{"/usr/bin/sudo", "/usr/sbin/adduser", "--home", homedir, "--shell", shellPath, "--disabled-password", "--gecos", "''", username})

	// Adding the new user to group sb
	commands = append(commands, []string{"/usr/bin/sudo", "/usr/sbin/usermod", "-a", "-G", config.GetSBUsername(), username})

	// Execute all commands
	for _, command := range commands {
		err := runCommand(command[0], command[1:]...)
		if err != nil {
			return err
		}
	}

	return
}

// CreateHomeSkeleton creates the home-directory layout of a freshly created
// user or group account (its .ssh directory, databases, ttyrecs directory,
// ...), delegating every filesystem mutation to sudo with the exact argument
// shapes whitelisted in the sudoers templates.
//
// Existence is probed with os.Stat run as the *calling* user, which is often
// an unprivileged sb owner (account and group creation are SBOwner-level
// commands, not root-only). Such a caller typically cannot see inside the new
// account's home directory, so a stat there fails with a permission error,
// not with "does not exist". Only a successful stat may skip the creation
// step: any stat failure falls back to attempting the (whitelisted, sudo-run)
// creation. A previous version skipped creation unless the failure was
// specifically os.IsNotExist, which silently dropped the mkdir/touch for
// non-root callers and made the subsequent chmod fail on the missing path —
// breaking account and group creation for everyone but root.
func CreateHomeSkeleton(homedir string, username string, homeType string) (err error) {

	commands, err := homeSkeletonCommands(homedir, username, homeType, func(path string) bool {
		_, statErr := os.Stat(path)
		return statErr == nil
	})
	if err != nil {
		return err
	}

	for _, command := range commands {
		err := runCommand(command[0], command[1:]...)
		if err != nil {
			return err
		}
	}

	return
}

// homeSkeletonCommands computes the ordered list of privileged commands that
// lay out a user or group home skeleton. It is pure (no filesystem access, no
// exec) so the command plan can be unit tested: the pathExists probe is
// injected by the caller precisely because probing is caller-dependent (see
// CreateHomeSkeleton). Each returned command is an argv slice starting with
// /usr/bin/sudo, and every shape must stay in lockstep with the sudoers
// templates in templates.go — a command that drifts from the whitelist fails
// in production.
//
// homeType selects the layout ("user" or "group"); any other value returns an
// error. Creation commands run as the target username via sudo -u and are
// emitted only when pathExists cannot positively confirm the path; chmod and
// chown always run so ownership and modes converge even on pre-existing
// paths.
func homeSkeletonCommands(homedir, username, homeType string, pathExists func(string) bool) (commands [][]string, err error) {

	type pathConfiguration struct {
		action string
		path   string
		chmod  string
		chown  string
	}

	pathConfigurations := make([]pathConfiguration, 0)

	switch homeType {
	case "user":
		pathConfigurations = append(pathConfigurations,
			pathConfiguration{action: "/bin/mkdir", path: ".ssh", chmod: "0755", chown: fmt.Sprintf("%s:%s", username, username)},
			pathConfiguration{action: "/bin/mkdir", path: "ttyrecs", chmod: "0755", chown: fmt.Sprintf("%s:%s", username, username)},
			pathConfiguration{action: "/usr/bin/touch", path: "accesses.db", chmod: "0640", chown: fmt.Sprintf("%s:%s", username, username)},
			pathConfiguration{action: "/usr/bin/touch", path: "logs.db", chmod: "0640", chown: fmt.Sprintf("%s:%s", username, username)},
			pathConfiguration{action: "/usr/bin/touch", path: ".ssh/authorized_keys", chmod: "0640", chown: fmt.Sprintf("%s:%s", username, username)},
		)
	case "group":
		pathConfigurations = append(pathConfigurations,
			pathConfiguration{action: "/bin/mkdir", path: "", chmod: "0775", chown: fmt.Sprintf("%s:%s-aclk", username, username)},
			pathConfiguration{action: "/bin/mkdir", path: ".ssh", chmod: "0755", chown: fmt.Sprintf("%s:%s", username, username)},
			pathConfiguration{action: "/usr/bin/touch", path: "accesses.db", chmod: "0664", chown: fmt.Sprintf("%s:%s-aclk", username, username)},
		)
	default:
		return nil, fmt.Errorf("invalid home type %s", homeType)
	}

	commands = make([][]string, 0, 3*len(pathConfigurations))
	for _, pathConf := range pathConfigurations {
		fullPath := fmt.Sprintf("%s/%s", homedir, pathConf.path)

		// Create the path unless it positively exists. Failing toward
		// creation is the safe direction: the creation command is whitelisted
		// in sudoers and fails loudly if the path is truly already there,
		// whereas skipping it leaves the skeleton incomplete.
		if !pathExists(fullPath) {
			commands = append(commands, []string{"/usr/bin/sudo", "-u", username, pathConf.action, fullPath})
		}

		// We always chown/chmod
		commands = append(commands,
			[]string{"/usr/bin/sudo", "/bin/chmod", pathConf.chmod, fullPath},
			[]string{"/usr/bin/sudo", "/bin/chown", pathConf.chown, fullPath},
		)
	}

	return commands, nil
}

// DeleteAccount deletes a group from the system
func DeleteAccount(username, archiveSuffix string) (err error) {

	// Fail closed on the privilege boundary: the username is passed to usermod and
	// groupmod, so validate it before we shell out. The archive suffix is
	// generated internally (bak_<timestamp>) and is not user-supplied.
	if err = ValidateSystemName(username); err != nil {
		return
	}

	// Build the command to archive the user
	commands := [][]string{
		{
			"/usr/bin/sudo",
			"/usr/sbin/usermod", "-s", "/usr/sbin/nologin", username,
		},
		{
			"/usr/bin/sudo",
			"/usr/sbin/usermod", "-l", fmt.Sprintf("%s.%s", username, archiveSuffix), username,
		},
		{
			"/usr/bin/sudo",
			"/usr/sbin/groupmod", "-n", fmt.Sprintf("%s.%s", username, archiveSuffix), username,
		},
	}

	// Execute all commands
	for _, command := range commands {
		err := runCommand(command[0], command[1:]...)
		if err != nil {
			return err
		}
	}

	return ArchiveHomeSkelleton(fmt.Sprintf("/home/%s", username), archiveSuffix)
}

// DeleteGroup deletes a group from the system
func DeleteGroup(groupname, archiveSuffix string) (err error) {

	// Deleting one group really means:
	//    - deleting the group as bg_GROUPNAME
	//    - deleting the group as bg_GROUPNAME-o
	//    - deleting the group as bg_GROUPNAME-gk
	//    - deleting the group as bg_GROUPNAME-aclk
	//    - deleting the user for the group as bg_GROUPNAME
	//    - removing a /etc/sudoers.d template for the group
	//    - moving the home folder

	// Fail closed on the privilege boundary: the group name is passed to usermod,
	// groupmod and the /etc/sudoers.d/<group> path, so validate it before we shell
	// out. The archive suffix is generated internally (bak_<timestamp>) and is not
	// user-supplied.
	if err = ValidateSystemName(groupname); err != nil {
		return
	}

	// Build the true groupname and all the groups names
	if !strings.HasPrefix(groupname, "bg_") {
		groupname = fmt.Sprintf("bg_%s", groupname)
	}
	groups := make([]string, 0, 4)
	groups = append(groups, groupname)
	for _, suffix := range []string{"o", "gk", "aclk"} {
		groups = append(groups, fmt.Sprintf("%s-%s", groupname, suffix))
	}

	// We'll build all commands, and the then execute them
	commands := make([][]string, 0, 2+len(groups)+1)

	// Build the command to archive the user for the group
	commands = append(commands,
		[]string{
			"/usr/bin/sudo",
			"/usr/sbin/usermod", "-s", "/usr/sbin/nologin", groupname,
		},
		[]string{
			"/usr/bin/sudo",
			"/usr/sbin/usermod", "-l", fmt.Sprintf("%s.%s", groupname, archiveSuffix), groupname,
		},
	)

	// Build commands to rename all the groups
	for _, group := range groups {
		commands = append(commands, []string{"/usr/bin/sudo", "/usr/sbin/groupmod", "-n", fmt.Sprintf("a_%s.%s", group, archiveSuffix), group})
	}

	// Build the command to rm the sudoers file
	commands = append(commands, []string{
		"/usr/bin/sudo",
		"/bin/rm",
		fmt.Sprintf("/etc/sudoers.d/%s", groupname),
	})

	// Execute all commands
	for _, command := range commands {
		err := runCommand(command[0], command[1:]...)
		if err != nil {
			return err
		}
	}

	return ArchiveHomeSkelleton(fmt.Sprintf("/home/%s", groupname), archiveSuffix)
}

// FillUserAuthorizedKeysFile creates the .ssh directory, put the public key in the authorized_keys file and chmods everything
func FillUserAuthorizedKeysFile(sshdir string, username string, pk string) (err error) {

	authorizedKeysFile := fmt.Sprintf("%s/authorized_keys", sshdir)

	err = runPipedCommands([]string{"echo", pk}, []string{"/usr/bin/sudo", "-u", username, "tee", "-a", authorizedKeysFile})
	if err != nil {
		return
	}

	err = runCommand("/usr/bin/sudo", "/bin/chmod", "0640", authorizedKeysFile)
	if err != nil {
		return
	}

	return
}

func ChmodFile(filePath, owner, permissions string) (err error) {
	return runCommand("/usr/bin/sudo", "-u", owner, "/bin/chmod", permissions, filePath)
}

func WriteGroupPrivateKey(privateKey, privateKeyFile, owner string) (err error) {

	err = WritePrivateKey(privateKey, privateKeyFile, owner)
	if err != nil {
		return
	}

	return ChmodFile(privateKeyFile, owner, "0440")
}

func WritePrivateKey(privateKey, privateKeyFile, owner string) (err error) {

	err = runPipedCommands([]string{"echo", privateKey}, []string{"/usr/bin/sudo", "-u", owner, "tee", privateKeyFile})
	if err != nil {
		return
	}

	return ChmodFile(privateKeyFile, owner, "0600")
}

func WritePublicKey(publicKey, publicKeyFile, owner string) (err error) {
	err = runPipedCommands([]string{"echo", publicKey}, []string{"/usr/bin/sudo", "-u", owner, "tee", publicKeyFile})
	if err != nil {
		return
	}

	return ChmodFile(publicKeyFile, owner, "0644")
}

func WriteSelfPrivateKey(privateKey, privateKeyFile, owner string) (err error) {

	err = os.WriteFile(privateKeyFile, []byte(privateKey+"\n"), 0600)
	if err != nil {
		return
	}

	usr, err := user.Lookup(owner)
	if err != nil {
		return
	}

	uid, _ := strconv.Atoi(usr.Uid)
	gid, _ := strconv.Atoi(usr.Gid)

	return os.Chown(privateKeyFile, uid, gid)
}

func WriteSelfPublicKey(publicKey, publicKeyFile, owner string) (err error) {
	// A public key is not secret and follows the conventional world-readable 0644
	// mode for .pub files, so the broader-than-0600 permission is intentional.
	err = os.WriteFile(publicKeyFile, []byte(publicKey), 0644) //nolint:gosec // G306: public key file, intentionally world-readable
	if err != nil {
		return
	}

	usr, err := user.Lookup(owner)
	if err != nil {
		return
	}

	uid, _ := strconv.Atoi(usr.Uid)
	gid, _ := strconv.Atoi(usr.Gid)

	return os.Chown(publicKeyFile, uid, gid)
}

func GenerateNewEgressGroupKey(algo string, size string, passphrase string, groupname string) (privateKey, publicKey, privateKeyFilePath, publicKeyFilePath, filesOwner string, err error) {

	// GenerateNewEgressKey expects the username parameter to be the real system user
	// and for groups, it means bg_GROUPNAME
	if !strings.HasPrefix(groupname, "bg_") {
		groupname = fmt.Sprintf("bg_%s", groupname)
	}

	return GenerateNewEgressKey(algo, size, passphrase, groupname)

}

func RemoveHostKey(username, knownHostsFilePath, hostkey string) (err error) {
	command := []string{"/usr/bin/ssh-keygen", "-f", knownHostsFilePath, "-R", hostkey}
	err = runCommand(command[0], command[1:]...)
	if err != nil {
		return
	}

	usr, err := user.Lookup(username)
	if err != nil {
		return
	}

	uid, _ := strconv.Atoi(usr.Uid)
	gid, _ := strconv.Atoi(usr.Gid)

	return os.Chown(knownHostsFilePath, uid, gid)
}

func GenerateNewEgressKey(algo string, size string, passphrase string, username string) (privateKey, publicKey, privateKeyFilePath, publicKeyFilePath, filesOwner string, err error) {

	// Two short random suffixes keep the key comment and the on-disk key
	// filename unique. They are not secrets, but they share the now
	// cryptographically secure generator, which can fail to read the system
	// entropy source; if it does we abort rather than build paths from an empty
	// or weak suffix.
	suffixes, err := GetRandomStrings(2, 5)
	if err != nil {
		err = fmt.Errorf("unable to generate random key suffixes: %w", err)
		return
	}

	keyComment := fmt.Sprintf("%s@sb:%s:%d", username, suffixes[0], time.Now().Unix())
	privateKeyFilePath = fmt.Sprintf("/home/%s/.ssh/id_%s_%s_private.%s_%d", username, algo, size, suffixes[1], time.Now().Unix())
	publicKeyFilePath = fmt.Sprintf("%s.pub", privateKeyFilePath)
	filesOwner = username

	sizeInt, err := strconv.Atoi(size)
	if err != nil {
		return
	}

	var pk interface{}
	var pubk interface{}

	switch algo {
	case "rsa":
		var pkrsa *rsa.PrivateKey
		pkrsa, err = rsa.GenerateKey(rand.Reader, sizeInt)
		if err != nil {
			err = fmt.Errorf("unable to generate rsa key: %w", err)
			return
		}
		pk = pkrsa
		pubk = &pkrsa.PublicKey

	case "ecdsa":
		var pkecdsa *ecdsa.PrivateKey
		var pubkeyCurve elliptic.Curve

		switch size {
		case "256":
			pubkeyCurve = elliptic.P256()
		case "384":
			pubkeyCurve = elliptic.P384()
		case "512":
			pubkeyCurve = elliptic.P521()
		}

		pkecdsa, err = ecdsa.GenerateKey(pubkeyCurve, rand.Reader)
		if err != nil {
			err = fmt.Errorf("unable to generate ecdsa key: %w", err)
			return
		}

		pk = pkecdsa
		pubk = &pkecdsa.PublicKey

	case "ed25519":
		pubk, pk, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			err = fmt.Errorf("unable to generate ed25519 key: %w", err)
			return
		}
	}

	sshPublicKey, err := ssh.NewPublicKey(pubk)
	if err != nil {
		err = fmt.Errorf("unable to derive publickey from privatekey: %w", err)
		return
	}

	var block *pem.Block
	if passphrase != "" {
		block, err = MarshalPrivateKeyWithPassphrase(pk, keyComment, []byte(passphrase))
	} else {
		block, err = MarshalPrivateKey(pk, keyComment)
	}
	if err != nil {
		return
	}

	// Get private key ready to be written
	privateKey = string(pem.EncodeToMemory(block))
	privateKey = strings.TrimSpace(privateKey)

	// Get publick key ready to be written
	publicKey = string(ssh.MarshalAuthorizedKey(sshPublicKey))
	publicKey = strings.TrimSpace(publicKey)
	publicKey = fmt.Sprintf("%s %s", publicKey, keyComment)

	return
}

// GetEtcGroupFilePath returns /etc/group or an other specifically set filepath
func GetEtcGroupFilePath() string {
	if etcGroupFilePath != "" {
		return etcGroupFilePath
	}
	return "/etc/group"
}

// GetEtcPasswdFilePath returns /etc/passwd or an other specifically set filepath
func GetEtcPasswdFilePath() string {
	if etcPasswdFilePath != "" {
		return etcPasswdFilePath
	}
	return "/etc/passwd"
}

// SetEtcGroupFilePath sets a specific filepath to oveerride /etc/group (mainly for tests purposes)
func SetEtcGroupFilePath(path string) {
	etcGroupFilePath = path
}

// SetEtcPasswdFilePath sets a specific filepath to oveerride /etc/passwd (mainly for tests purposes)
func SetEtcPasswdFilePath(path string) {
	etcPasswdFilePath = path
}

// GetSystemGroups returns the content of /etc/group
func GetSystemGroups() (groups [][]string, err error) {

	// Open /etc/group
	file, err := os.Open(GetEtcGroupFilePath())
	if err != nil {
		return
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		groups = append(groups, strings.Split(scanner.Text(), ":"))
	}

	err = scanner.Err()
	if err != nil {
		return
	}

	return
}

// GetSystemGroups returns the content of /etc/passwd
func GetSystemUsers() (groups [][]string, err error) {

	// Open /etc/passwd
	file, err := os.Open(GetEtcPasswdFilePath())
	if err != nil {
		return
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		groups = append(groups, strings.Split(scanner.Text(), ":"))
	}

	err = scanner.Err()
	if err != nil {
		return
	}

	return
}

// ArchiveHomeSkelleton moves user home to home.bak
func ArchiveHomeSkelleton(homedir, suffix string) (err error) {
	command := []string{"/usr/bin/sudo", "/bin/mv", homedir, fmt.Sprintf("%s.%s", homedir, suffix)}
	return runCommand(command[0], command[1:]...)
}

// RemoveAccountFromGroup adds an account in a group's membership group
func RemoveAccountFromGroup(groupName string, account string, membershipType string) (err error) {

	// Fail closed on the privilege boundary: both names are passed to deluser, so
	// validate them before we shell out.
	if err = ValidateSystemNames(groupName, account); err != nil {
		return
	}

	// Build the true groupname and all the groups names
	if !strings.HasPrefix(groupName, "bg_") {
		groupName = fmt.Sprintf("bg_%s", groupName)
	}

	actualGroupName := groupName
	switch membershipType {
	case "o", "gk", "aclk":
		actualGroupName = fmt.Sprintf("%s-%s", groupName, membershipType)
	case "m":
		// Nothing to do
	default:
		err = fmt.Errorf("membershipType's value should be from the list: o, gk, aclk, m")
		return
	}

	// Add the owner account in all the groups
	command := []string{"/usr/bin/sudo", "/usr/sbin/deluser", account, actualGroupName}
	return runCommand(command[0], command[1:]...)
}

// runCommand executes a system command
func runCommand(command string, arguments ...string) (err error) {

	// Building the command to execute
	cmd := exec.Command(command, arguments...)

	// Redirecting command output to a bytes.Buffer
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err = cmd.Run()
	if err != nil {
		// If erverything didn't go as planned, displaying the command output
		fmt.Printf("Error while running command: %s\n", out.String())
	}

	return
}

// runPipedCommands runs a chain of system commands, wiring each command's stdout
// into the next command's stdin (the equivalent of "cmd0 | cmd1 | ... | cmdN").
// The last command's output and stderr are captured so they can be reported if
// the pipeline fails. It returns the first error encountered while wiring,
// starting, running or waiting on any command.
func runPipedCommands(commands ...[]string) (err error) {

	if len(commands) == 0 {
		return fmt.Errorf("runPipedCommands called with no commands")
	}

	// Build every *exec.Cmd up front.
	cmds := make([]*exec.Cmd, len(commands))
	for i := range commands {
		cmds[i] = exec.Command(commands[i][0], commands[i][1:]...)
	}

	// Wire each command's stdout into the next command's stdin. StdoutPipe must
	// be obtained before the producing command is started, and its error must not
	// be ignored: a dropped pipe error here would otherwise surface later as a
	// confusing "broken pipe" or a silently empty downstream input.
	for i := 1; i < len(cmds); i++ {
		stdout, errPipe := cmds[i-1].StdoutPipe()
		if errPipe != nil {
			return fmt.Errorf("unable to connect command %d output to command %d input: %w", i, i+1, errPipe)
		}
		cmds[i].Stdin = stdout
	}

	// Capture the last command's output and stderr for diagnostics. These must be
	// set before the command is started (exec.Cmd reads them at Start), which the
	// previous implementation got wrong by assigning Stdout after Start.
	var out bytes.Buffer
	last := cmds[len(cmds)-1]
	last.Stdout = &out
	last.Stderr = &out

	// Start every downstream command so they are ready to consume their piped
	// input before the first command begins producing it.
	for i := 1; i < len(cmds); i++ {
		if err = cmds[i].Start(); err != nil {
			return fmt.Errorf("unable to start command %d (%s): %w", i+1, commands[i][0], err)
		}
	}

	// Run the first command to completion; this drives the whole pipeline.
	if err = cmds[0].Run(); err != nil {
		return fmt.Errorf("unable to run command 1 (%s): %w", commands[0][0], err)
	}

	// Wait for each downstream command, in order, to finish.
	for i := 1; i < len(cmds); i++ {
		if err = cmds[i].Wait(); err != nil {
			return fmt.Errorf("command %d (%s) failed: %w\nOutput: %s", i+1, commands[i][0], err, out.String())
		}
	}

	return
}
