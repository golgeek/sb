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
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
)

var (
	etcGroupFilePath  string
	etcPasswdFilePath string
)

// AddAccountInGroup adds an account in a group's membership group
func AddAccountInGroup(groupName string, account string, membershipType string) (err error) {

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

	// Build the true groupname and all the groups names
	if !strings.HasPrefix(groupname, "bg_") {
		groupname = fmt.Sprintf("bg_%s", groupname)
	}
	groups := []string{groupname}
	for _, suffix := range []string{"o", "gk", "aclk"} {
		groups = append(groups, fmt.Sprintf("%s-%s", groupname, suffix))
	}

	// We'll build all commands, and the then execute them
	commands := make([][]string, 0)

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
	commands := make([][]string, 0)

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

// CreateHomeSkeleton creates user home
func CreateHomeSkeleton(homedir string, username string, homeType string) (err error) {

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
		return fmt.Errorf("invalid home type %s", homeType)
	}

	for _, pathConf := range pathConfigurations {
		fullPath := fmt.Sprintf("%s/%s", homedir, pathConf.path)
		commands := make([][]string, 0)

		// If path doesn't exist, we create it
		if _, err := os.Stat(fullPath); os.IsNotExist(err) {
			commands = append(commands, []string{"/usr/bin/sudo", "-u", username, pathConf.action, fullPath})
		}

		// We always chown/chmod
		commands = append(commands,
			[]string{"/usr/bin/sudo", "/bin/chmod", pathConf.chmod, fullPath},
			[]string{"/usr/bin/sudo", "/bin/chown", pathConf.chown, fullPath},
		)
		for _, command := range commands {
			err := runCommand(command[0], command[1:]...)
			if err != nil {
				return err
			}
		}
	}

	return
}

// DeleteAccount deletes a group from the system
func DeleteAccount(username, archiveSuffix string) (err error) {

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

	// Build the true groupname and all the groups names
	if !strings.HasPrefix(groupname, "bg_") {
		groupname = fmt.Sprintf("bg_%s", groupname)
	}
	groups := []string{groupname}
	for _, suffix := range []string{"o", "gk", "aclk"} {
		groups = append(groups, fmt.Sprintf("%s-%s", groupname, suffix))
	}

	// We'll build all commands, and the then execute them
	commands := make([][]string, 0)

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
	err = os.WriteFile(publicKeyFile, []byte(publicKey), 0644)
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
		err = errors.Wrap(err, "Unable to generate random key suffixes")
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
			err = errors.Wrap(err, "Unable to generate rsa key")
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
			err = errors.Wrap(err, "Unable to generate ecdsa key")
			return
		}

		pk = pkecdsa
		pubk = &pkecdsa.PublicKey

	case "ed25519":
		pubk, pk, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			err = errors.Wrap(err, "Unable to generate ed25519 key")
			return
		}
	}

	sshPublicKey, err := ssh.NewPublicKey(pubk)
	if err != nil {
		err = errors.Wrap(err, "Unable to derive publickey from privatekey")
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

// runPipedCommand executes two piped system commands
func runPipedCommands(commands ...[]string) (err error) {

	var out bytes.Buffer
	cmds := make([]*exec.Cmd, len(commands))

	// Create the first command
	cmds[0] = exec.Command(commands[0][0], commands[0][1:]...)

	for i := 1; i < len(commands); i++ {
		// Create the next commands and pipe stdin to the previous stdout
		cmds[i] = exec.Command(commands[i][0], commands[i][1:]...)
		cmds[i].Stdin, _ = cmds[i-1].StdoutPipe()
		err = cmds[i].Start()
		if err != nil {
			fmt.Printf("Error while starting command %d: %s\n", i+1, err)
			return
		}
	}

	// Create the last command and pipe stdout to a bytes buffer
	cmds[len(commands)-1].Stdout = &out

	// Run the first command
	err = cmds[0].Run()
	if err != nil {
		fmt.Printf("Error while running first command: %s\n", err)
		return
	}

	// Wait for the last command
	err = cmds[len(commands)-1].Wait()
	if err != nil {
		// If erverything didn't go as planned, displaying the command output
		fmt.Printf("Error while waiting for last command: %s\nOutput: %s\n", err, out.String())
		return
	}

	return
}
