package models

import (
	"bufio"
	"fmt"
	"net"
	"os"
	osuser "os/user"
	"strconv"
	"strings"

	"github.com/golgeek/sb/internal/config"
	"github.com/golgeek/sb/internal/helpers"

	"github.com/fatih/color"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
)

// User descibes the basic properties of a sb user
type User struct {
	User   *osuser.User
	Groups map[string]*Group

	OverriddenDatabaseAccessFilePath string
	OverriddenAuthorizedKeysFilePath string
}

// GetAllSBUsers returns all sb users
func GetAllSBUsers() (users []string, err error) {

	allUsers, err := helpers.GetSystemUsers()
	if err != nil {
		return
	}

	for _, user := range allUsers {
		if strings.HasPrefix(user[0], "#") {
			continue
		}

		if user[6] == config.GetBinaryPath() {
			users = append(users, user[0])
		}
	}

	return
}

// LoadCurrentUser loads the current user into a sbuser object by calling the LoadUser method
func LoadCurrentUser() (bu *User, err error) {
	u, err := osuser.Current()
	if err != nil {
		return
	}
	return LoadUser(u.Username)
}

// LoadUser loads a system user into a sbuser object
func LoadUser(username string) (bu *User, err error) {

	bu = new(User)
	bu.User, err = osuser.Lookup(username)
	if err != nil {
		return
	}

	bu.Groups = make(map[string]*Group)

	// We gather the user's group IDs
	groupIDs, err := bu.User.GroupIds()
	if err != nil {
		return
	}

	// Let's build the list of groups the user is member of
	groups := make([]string, 0)
	for _, groupID := range groupIDs {
		// Lookup for group name from groupID
		g, errLookup := osuser.LookupGroupId(groupID)
		if errLookup != nil {
			return bu, errLookup
		}
		groups = append(groups, g.Name)
	}

	bu.BuildGroupsMembership(groups)

	return
}

// AddAccess adds an access to the group
func (bu *User) AddAccess(host, user, port, alias, comment string, db ...*gorm.DB) (ba *Access, err error) {
	ba, err = BuildSBAccess(host, user, port, alias, true)
	if err != nil {
		return
	}

	ba.Comment = comment

	var dbHandler *gorm.DB
	if len(db) > 0 {
		dbHandler = db[0]
	} else {
		dbHandler, err = GetAccessGormDB(bu.getDatabaseAccessFilePath())
		if err != nil {
			return
		}
	}

	err = ba.Save(dbHandler)

	return
}

// AddIngressKey adds an ingress key to authorized_keys file
func (bu *User) AddIngressKey(publicKey string) (err error) {

	path := bu.getAuthorizedKeysFilePathes()

	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}

	defer file.Close()

	_, err = fmt.Fprintf(file, "%s\n", publicKey)
	if err != nil {
		return err
	}

	return
}

// BuildGroupsMembership builds the user's membership based on the groups that were given in input
func (bu *User) BuildGroupsMembership(groupNames []string) {

	for _, groupName := range groupNames {
		matches := SBGroupNameRegexp.FindStringSubmatch(groupName)
		if len(matches) > 0 {

			actualGroupName := matches[1]

			// If we never encountered this group, we will add it to the user's groups map
			_, ok := bu.Groups[actualGroupName]
			if !ok {
				bu.Groups[actualGroupName] = &Group{
					Name:       actualGroupName,
					SystemName: fmt.Sprintf("bg_%s", actualGroupName),
				}
			}

			// Manage the rights level of the user on the group
			// This part is optional: empty is just member
			switch matches[3] {
			case "":
				bu.Groups[actualGroupName].Member = true
			case "aclk":
				bu.Groups[actualGroupName].ACLKeeper = true
			case "gk":
				bu.Groups[actualGroupName].GateKeeper = true
			case "o":
				bu.Groups[actualGroupName].Owner = true
			}
		}
	}
}

// DeleteAccess deletes an access from the personal access database
func (bu *User) DeleteAccess(host, user, port string, db ...*gorm.DB) (ba *Access, err error) {

	var dbHandler *gorm.DB
	if len(db) > 0 {
		dbHandler = db[0]
	} else {
		dbHandler, err = GetAccessGormDB(bu.getDatabaseAccessFilePath())
		if err != nil {
			return
		}
	}

	ba, err = LoadSBAccess(host, user, port, dbHandler)
	if err != nil {
		return
	}

	err = ba.Delete(dbHandler)

	return
}

// DeletePubKey deletes a key
func (bu *User) DeletePubKey(keyType string, pk helpers.PublicKey) (err error) {

	pathes := make([]string, 0)
	switch keyType {
	case "egress":
		pathes, err = bu.getPubKeyFilePathes()
		if err != nil {
			return
		}
	case "ingress":
		pathes = append(pathes, bu.getAuthorizedKeysFilePathes())
		if err != nil {
			return
		}
	default:
		return fmt.Errorf("unknown type of key %s", keyType)
	}

	// We will iterate on each path
	for _, path := range pathes {

		// For each file, we will write in the file the keys we want to retain
		keysToRetain := make([]string, 0)

		// Open the file for reading
		file, err := os.Open(path)
		if err != nil {
			return err
		}

		// Reading the file
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {

			key := scanner.Text()

			publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key))
			if err != nil {
				// We got an error parsing this key, let's not keep it
				continue
			}

			// If the key matches the one we want to drop, let's not keep it
			if !pk.Equals(publicKey) {
				keysToRetain = append(keysToRetain, key)
			}
		}

		// Manually closing the file before writing to it
		file.Close()

		// If reading the file failed partway through, do not overwrite it with a
		// truncated key set — that could silently drop keys we meant to keep.
		if err = scanner.Err(); err != nil {
			return fmt.Errorf("unable to read %s while deleting key: %w", path, err)
		}

		// Write back the keys we are keeping (WriteFile truncates, then writes). A
		// failed write must be reported: silently ignoring it could leave the
		// key we are revoking still present in authorized_keys, so it would stay
		// accepted and the revocation would not take effect.
		// authorized_keys holds public keys (not secret) and is read group-wide by
		// the sb tooling, so the broader-than-0600 permission is intentional.
		if err = os.WriteFile(path, []byte(fmt.Sprintf("%s\n", strings.Join(keysToRetain, "\n"))), 0644); err != nil { //nolint:gosec // G306: authorized_keys, public keys read group-wide
			return fmt.Errorf("unable to write %s while deleting key: %w", path, err)
		}
	}

	return
}

// DisplayPubKeys pretty displays the public key
func (bu *User) DisplayPubKeys(keyType string) (str string, keys []helpers.PublicKey, err error) {

	keys, err = bu.listPubKeys(keyType)
	if err != nil {
		return
	}

	green := color.New(color.FgGreen).SprintFunc()
	for id, key := range keys {
		str += fmt.Sprintf("%s: %s", green(id+1), green(key.String()))
		if id != len(keys)-1 {
			str += "\n---\n"
		}
	}

	return
}

// GetAccesses returns the list of user's authorized accesses
func (bu *User) GetAccesses(db ...*gorm.DB) (accesses []*AccessesByKeys, err error) {

	// Start by managing self accesses
	userAccesses, err := bu.GetSelfAccesses(db...)
	if err != nil {
		return
	}

	// Initializing our array with the self access
	accesses = []*AccessesByKeys{userAccesses}

	// Then listing group's accesses
	for _, group := range bu.Groups {
		if group.Owner || group.Member {
			groupAccesses, err := group.GetAccesses()
			if err != nil {
				return accesses, err
			}
			accesses = append(accesses, groupAccesses)
		}
	}

	return
}

// GetAllGroups returns all user's groups
func (bu *User) GetAllGroups() (map[string]*Group, error) {
	return bu.Groups, nil
}

// GetLocalLogDatabasePath returns the path of the user private database
func (bu *User) GetLocalLogDatabasePath() string {
	return fmt.Sprintf("%s/logs.db", bu.User.HomeDir)
}

// GetSelfAccesses returns the list of user's authorized accesses
func (bu *User) GetSelfAccesses(db ...*gorm.DB) (accesses *AccessesByKeys, err error) {

	var dbHandler *gorm.DB
	if len(db) > 0 {
		dbHandler = db[0]
	} else {
		dbHandler, err = GetAccessGormDB(bu.getDatabaseAccessFilePath())
		if err != nil {
			return
		}
	}

	// Start by managing self accesses
	userAccesses, err := GetAllAccesses(dbHandler)
	if err != nil {
		return
	}
	sshKeyPairs, err := bu.GetSSHKeyPairs()
	if err != nil {
		return
	}

	// Initializing our array with the self access
	accesses = &AccessesByKeys{
		Accesses: userAccesses,
		Keys:     sshKeyPairs,
		Type:     "self",
	}

	return
}

// GetLastSSHSessions returns the user last SSH sessions
func (bu *User) GetLastSSHSessions(limit int) ([]*helpers.SSHSession, error) {
	return GetLastSSHSessions(bu.GetLocalLogDatabasePath(), limit)
}

// GetSSHKeyPairs returns all the egress SSH key pairs of the user
func (bu *User) GetSSHKeyPairs() (kp []*helpers.SSHKeyPair, err error) {

	pathes, err := bu.getKeyFilePathes()
	if err != nil {
		return
	}

	for _, privateKeyFilePath := range pathes {

		pubKeyFilePath := fmt.Sprintf("%s.pub", privateKeyFilePath)

		// Open the public key file
		file, err := os.Open(pubKeyFilePath)
		if err != nil {
			return kp, err
		}
		defer file.Close()

		// In a SSH key pair, we only have one line
		scanner := bufio.NewScanner(file)
		scanner.Scan()

		// Let's check the public key validity
		publicKey, comment, options, rest, err := ssh.ParseAuthorizedKey(scanner.Bytes())
		if err != nil {
			continue
		}

		pk := &helpers.PublicKey{
			PublicKey: publicKey,
			Comment:   comment,
			Options:   options,
			Rest:      rest,
		}

		sshkp := &helpers.SSHKeyPair{
			PublicKey:          pk,
			PrivateKeyFilepath: privateKeyFilePath,
		}
		kp = append(kp, sshkp)
	}

	return
}

// GetTOTP reports whether the calling user has TOTP (2FA) configured and, when
// they do, returns the shared secret and the remaining emergency/scratch codes
// read from their ~/.google_authenticator file.
//
// The enabled flag is true only when a well-formed file containing a secret line
// is found. A missing file is the normal "TOTP not set up" case and is reported
// as (false, "", nil, nil). Any other failure — the file cannot be read, or it
// exists but is empty/truncated and carries no secret line — is returned as a
// non-nil error so the caller can fail closed instead of acting on a missing
// secret. Previously an empty or truncated file caused an index-out-of-range
// panic at lines[0], which on the main.go startup path (run for every command
// when replication is enabled) was a denial of service for the affected user.
func (bu *User) GetTOTP() (enabled bool, secret string, emergencyPasswords []string, err error) {

	file, err := os.Open(bu.GetTOTPFilepath())
	if err != nil {
		// A missing file simply means TOTP was never enabled; that is the normal
		// case and not an error. Any other open error (e.g. permissions) is
		// surfaced so the caller can decide how to handle it.
		if os.IsNotExist(err) {
			err = nil
		}
		return
	}
	defer file.Close()

	lines := make([]string, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "\"") {
			lines = append(lines, line)
		}
	}
	if err = scanner.Err(); err != nil {
		err = fmt.Errorf("unable to read TOTP file %s: %w", bu.GetTOTPFilepath(), err)
		return
	}

	// The first non-option line is the shared secret; every line after it is an
	// emergency/scratch code. A file with no secret line — or one whose first line
	// is blank — is malformed: surface the corruption rather than panicking on
	// lines[0] or returning an empty secret.
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		err = fmt.Errorf("TOTP file %s is empty or malformed: no secret found", bu.GetTOTPFilepath())
		return
	}

	enabled = true
	secret = lines[0]
	emergencyPasswords = lines[1:]

	return
}

// GetTOTPFilepath returns the user's TOTP file path
func (bu *User) GetTOTPFilepath() string {
	return fmt.Sprintf("%s/.google_authenticator", bu.User.HomeDir)
}

// GetTtyrecDirectory returns the user's ttyrecs directory
func (bu *User) GetTtyrecDirectory() string {
	return fmt.Sprintf("%s/ttyrecs", bu.User.HomeDir)
}

// GetKnownHostsFilepath returns the user's known_hosts file path
func (bu *User) GetKnownHostsFilepath() string {
	return fmt.Sprintf("%s/.ssh/known_hosts", bu.User.HomeDir)
}

// HasAccess returns a boolean value of whether or not the user can access the specified access with the specified user
func (bu *User) HasAccess(ba *Access, db ...*gorm.DB) (accessInfo *Info, err error) {

	userAccesses, err := bu.GetAccesses(db...)
	if err != nil {
		return
	}

	accessInfo = &Info{
		Authorized:    false,
		KeyFilepathes: make([]string, 0),
		Sources:       make([]*Source, 0),
		Accesses:      make([]*Access, 0),
	}

	for _, userAccessesByKeyPairs := range userAccesses {

		found := false

		for _, a := range userAccessesByKeyPairs.Accesses {

			// If ba object doesn't have a net.IP key, we do a host comparaison
			if ba.IP == nil {

				// If host or alias doesn't match (or alias is empty), we don't go further
				if a.Host != ba.Host && a.Alias != ba.Host {
					continue
				}

			} else {

				// We'll check if the net.IP is in the access prefix
				_, hostIPNet, errParseCIDR := net.ParseCIDR(a.Prefix)
				if errParseCIDR != nil {
					err = fmt.Errorf("error while parsing net.IPNet: %s", errParseCIDR)
					return
				}

				// If not, we don't go further
				if !hostIPNet.Contains(ba.IP) {
					continue
				}
			}

			// ba.User an ba.Port could be empty if we try to connect with an alias shortcut to a registered and authorized auth
			// For example, if we have granted access to host: [root@meow.com:555 with alias meow]
			// and our user just connects with "sb meow", we will forward the connection to root@meow.com:555
			if ba.User != "" && a.User != ba.User {
				continue
			}
			if ba.Port != 0 && a.Port != ba.Port {
				continue
			}

			// Hey! We have a match!
			found = true
			accessInfo.Accesses = append(accessInfo.Accesses, a)
		}

		if found {
			accessInfo.Authorized = true
			accessInfo.Sources = append(accessInfo.Sources, &Source{Type: userAccessesByKeyPairs.Type, Group: userAccessesByKeyPairs.Group})
			for _, key := range userAccessesByKeyPairs.Keys {
				accessInfo.KeyFilepathes = append(accessInfo.KeyFilepathes, key.PrivateKeyFilepath)
			}
		}

		// We reset found for the next access type
		found = false
	}

	return
}

// IsACLKeeperOfGroup checks if the user is member of the group passed as parameter
func (bu *User) IsACLKeeperOfGroup(groupName string) bool {
	group, ok := bu.Groups[groupName]
	if !ok || !group.ACLKeeper {
		return false
	}
	return true
}

// IsGateKeeperOfGroup checks if the user is member of the group passed as parameter
func (bu *User) IsGateKeeperOfGroup(groupName string) bool {
	group, ok := bu.Groups[groupName]
	if !ok || !group.GateKeeper {
		return false
	}
	return true
}

// IsMemberOfGroup checks if the user is member of the group passed as parameter
func (bu *User) IsMemberOfGroup(groupName string) bool {
	group, ok := bu.Groups[groupName]
	if !ok || !group.Member {
		return false
	}
	return true
}

// IsOwnerOfGroup checks if the user is member of the group passed as parameter
func (bu *User) IsOwnerOfGroup(groupName string) bool {
	group, ok := bu.Groups[groupName]
	if !ok || !group.Owner {
		return false
	}
	return true
}

// OverrideAuthorizedKeysFilePath allows to override the authorized_keys file path of the user (mainly for tests purposes)
func (bu *User) OverrideAuthorizedKeysFilePath(path string) error {
	bu.OverriddenAuthorizedKeysFilePath = path
	return nil
}

// OverrideDatabaseAccessFilePath allows to override the database access file path of the user (mainly for tests purposes)
func (bu *User) OverrideDatabaseAccessFilePath(path string) error {
	bu.OverriddenDatabaseAccessFilePath = path
	return nil
}

// RemoveTOTPSecret disables TOTP on the account
func (bu *User) RemoveTOTPSecret() (err error) {
	return os.Remove(bu.GetTOTPFilepath())
}

// SetTOTPSecret sets TOTP on the current account
func (bu *User) SetTOTPSecret(secret string, emergencyCodes []string) error {
	content := []byte(helpers.GetTOTPFile(secret, emergencyCodes))
	err := os.WriteFile(bu.GetTOTPFilepath(), content, 0600)
	if err != nil {
		return err
	}

	uid, err := strconv.Atoi(bu.User.Uid)
	if err != nil {
		return fmt.Errorf("unable to convert user's UID to int: %w", err)
	}
	gid, err := strconv.Atoi(bu.User.Gid)
	if err != nil {
		return fmt.Errorf("unable to convert user's GID to int: %w", err)
	}

	return os.Chown(bu.GetTOTPFilepath(), uid, gid)
}

// ShortString returns a pretty print short display of the user
func (bu *User) ShortString() string {
	green := color.New(color.FgGreen).SprintFunc()
	return green(bu.User.Username)
}

// getAuthorizedKeysFilePath returns the filepath of the private authorized_keys file
func (bu *User) getAuthorizedKeysFilePathes() string {
	if bu.OverriddenAuthorizedKeysFilePath != "" {
		return bu.OverriddenAuthorizedKeysFilePath
	}

	return fmt.Sprintf("%s/.ssh/authorized_keys", bu.User.HomeDir)
}

// getDatabaseAccessFilePath returns the filepath of the private authorized accesses database
func (bu *User) getDatabaseAccessFilePath() string {
	if bu.OverriddenDatabaseAccessFilePath != "" {
		return bu.OverriddenDatabaseAccessFilePath
	}

	return fmt.Sprintf("%s/accesses.db", bu.User.HomeDir)
}

// getKeyFilePathes returns the filepathes of every private key in the user's .ssh folder
func (bu *User) getKeyFilePathes() (filepathes []string, err error) {

	rootDir := fmt.Sprintf("%s/.ssh/", bu.User.HomeDir)

	files, err := os.ReadDir(rootDir)
	if err != nil {
		return
	}

	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".pub") {
			filepathes = append(filepathes, fmt.Sprintf("%s%s", rootDir, f.Name()[:len(f.Name())-4]))
		}
	}

	return
}

// GetPubKeyFilePathes returns the filepathes of the public keys in the user .ssh folder
func (bu *User) getPubKeyFilePathes() (filepathes []string, err error) {

	rootDir := fmt.Sprintf("%s/.ssh/", bu.User.HomeDir)

	files, err := os.ReadDir(rootDir)
	if err != nil {
		return
	}

	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".pub") {
			filepathes = append(filepathes, fmt.Sprintf("%s%s", rootDir, f.Name()))
		}
	}

	return
}

// listEgressKeys returns the list of public keys contained in HomeDir/.ssh/*.pub
func (bu *User) listPubKeys(keyType string) (keys []helpers.PublicKey, err error) {

	pathes := make([]string, 0)
	switch keyType {
	case "egress":
		pathes, err = bu.getPubKeyFilePathes()
		if err != nil {
			return
		}
	case "ingress":
		pathes = append(pathes, bu.getAuthorizedKeysFilePathes())
		if err != nil {
			return
		}
	default:
		return keys, fmt.Errorf("unknown type of key")
	}

	for _, path := range pathes {

		file, err := os.Open(path)
		if err != nil {
			return keys, err
		}

		defer file.Close()

		scanner := bufio.NewScanner(file)

		for scanner.Scan() {
			publicKey, comment, options, rest, err := ssh.ParseAuthorizedKey(scanner.Bytes())
			if err != nil {
				continue
			}

			pk := helpers.PublicKey{
				PublicKey: publicKey,
				Comment:   comment,
				Options:   options,
				Rest:      rest,
			}
			keys = append(keys, pk)
		}
	}

	return
}
