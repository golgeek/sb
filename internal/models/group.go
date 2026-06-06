package models

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/golgeek/sb/internal/helpers"

	"github.com/fatih/color"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
)

// SBGroupNameRegexp represents the regex that matches a sb group
var SBGroupNameRegexp = regexp.MustCompile(`^bg_([^-]*)(-(.*))?$`)

// Group describes the basic properties of a sb group
type Group struct {
	Name       string
	SystemName string
	ACLKeeper  bool
	GateKeeper bool
	Member     bool
	Owner      bool

	OverriddenDatabaseAccessFilePath string
	OverriddenKeyFilesRootDir        string
}

// GetAllSBGroups lists all sb groups. Results can be provided with optional user's right and can be filtered on group's name
func GetAllSBGroups() (groups map[string]*Group, err error) {

	groups = make(map[string]*Group)

	allGroups, err := helpers.GetSystemGroups()
	if err != nil {
		return
	}

	for _, group := range allGroups {
		matches := SBGroupNameRegexp.FindStringSubmatch(group[0])
		if len(matches) > 0 {
			actualGroupName := matches[1]
			// If we never encountered this group, we will add it to the user's groups map
			_, ok := groups[actualGroupName]
			if !ok {
				groups[actualGroupName] = &Group{
					Name:       actualGroupName,
					SystemName: fmt.Sprintf("bg_%s", actualGroupName),
				}
			}
		}
	}

	return
}

// GetGroup returns a group if it exists
func GetGroup(groupName string) (group *Group, err error) {

	groups, err := GetAllSBGroups()
	if err != nil {
		return
	}

	group, ok := groups[groupName]
	if !ok {
		return group, fmt.Errorf("group not found")
	}

	return
}

// AddAccess adds an access to the group
func (bg *Group) AddAccess(host, user, port, alias, comment string, db ...*gorm.DB) (ba *Access, err error) {
	ba, err = BuildSBAccess(host, user, port, alias, true)
	if err != nil {
		return
	}

	ba.Comment = comment

	var dbHandler *gorm.DB
	if len(db) > 0 {
		dbHandler = db[0]
	} else {
		dbHandler, err = GetAccessGormDB(bg.getDatabaseAccessFilePath())
		if err != nil {
			return
		}
	}

	err = ba.Save(dbHandler)

	return
}

// GetMembers pretty displays the members of a group
func (bg *Group) GetMembers(memberType string) (members []string, err error) {

	actualGroupName := bg.SystemName
	switch memberType {
	case "owner":
		actualGroupName = fmt.Sprintf("%s-o", bg.SystemName)
	case "gk", "gate-keeper", "gatekeeper":
		actualGroupName = fmt.Sprintf("%s-gk", bg.SystemName)
	case "aclk", "acl-keeper", "aclkeeper":
		actualGroupName = fmt.Sprintf("%s-aclk", bg.SystemName)
	case "member":
		// Nothing to do
	default:
		err = fmt.Errorf("memberType's value should be from the list: owner, gatekeeper, aclkeeper, member")
		return
	}

	// Open /etc/group
	file, err := os.Open(helpers.GetEtcGroupFilePath())
	if err != nil {
		return
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		groupLine := scanner.Text()
		groupInfo := strings.Split(groupLine, ":")
		if groupInfo[0] == actualGroupName {
			members = strings.Split(groupInfo[3], ",")
		}
	}
	err = scanner.Err()
	if err != nil {
		return
	}

	return
}

// DeleteAccess deletes an access from the group
func (bg *Group) DeleteAccess(host, user, port string, db ...*gorm.DB) (ba *Access, err error) {

	var dbHandler *gorm.DB
	if len(db) > 0 {
		dbHandler = db[0]
	} else {
		dbHandler, err = GetAccessGormDB(bg.getDatabaseAccessFilePath())
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

// DisplayPubKeys pretty displays the public key
func (bg *Group) DisplayPubKeys(keyType string) (str string, keys []helpers.PublicKey, err error) {

	keys, err = bg.listPubKeys(keyType)
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

// GetAccesses returns the list of group's authorized accesses
func (bg *Group) GetAccesses(db ...*gorm.DB) (accesses *AccessesByKeys, err error) {

	var dbHandler *gorm.DB
	if len(db) > 0 {
		dbHandler = db[0]
	} else {
		dbHandler, err = GetAccessGormDB(bg.getDatabaseAccessFilePath())
		if err != nil {
			return
		}
	}

	groupAccesses, err := GetAllAccesses(dbHandler)
	if err != nil {
		return
	}
	sshKeyPairs, err := bg.GetSSHKeyPairs()
	if err != nil {
		return
	}

	// Initializing our array with the self access
	accesses = &AccessesByKeys{
		Accesses: groupAccesses,
		Keys:     sshKeyPairs,
		Type:     "group",
		Group:    bg.Name,
	}

	return
}

// GetSSHKeyPairs returns all the egress SSH key pairs of the user
func (bg *Group) GetSSHKeyPairs() (kp []*helpers.SSHKeyPair, err error) {

	pathes, err := bg.getKeyFilePathes()
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

// OverrideDatabaseAccessFilePath allows to override the database access file path of the group (mainly for tests purposes)
func (bg *Group) OverrideDatabaseAccessFilePath(path string) {
	bg.OverriddenDatabaseAccessFilePath = path
}

// OverrideKeyFilesRootDir allows to override the the keypairs file path of the group (mainly for tests purposes)
func (bg *Group) OverrideKeyFilesRootDir(path string) {
	bg.OverriddenKeyFilesRootDir = path
}

// getDatabaseAccessFilePath returns the filepath of the private authorized accesses
func (bg *Group) getDatabaseAccessFilePath() string {
	if bg.OverriddenDatabaseAccessFilePath != "" {
		return bg.OverriddenDatabaseAccessFilePath
	}
	return fmt.Sprintf("/home/%s/accesses.db", bg.SystemName)
}

func (bg *Group) getKeyFilesRootDir() string {
	if bg.OverriddenKeyFilesRootDir != "" {
		return bg.OverriddenKeyFilesRootDir
	}
	return fmt.Sprintf("/home/%s/.ssh", bg.SystemName)
}

// getKeyFilePathes returns the filepathes of every private key in the user's .ssh folder
func (bg *Group) getKeyFilePathes() (filepathes []string, err error) {

	rootDir := bg.getKeyFilesRootDir()

	files, err := os.ReadDir(rootDir)
	if err != nil {
		return
	}

	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".pub") {
			filepathes = append(filepathes, fmt.Sprintf("%s/%s", rootDir, f.Name()[:len(f.Name())-4]))
		}
	}

	return
}

// getPubKeyFilePathes returns the filepathes of the public keys in the user .ssh folder
func (bg *Group) getPubKeyFilePathes() (filepathes []string, err error) {

	rootDir := bg.getKeyFilesRootDir()

	files, err := os.ReadDir(rootDir)
	if err != nil {
		return
	}

	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".pub") {
			filepathes = append(filepathes, fmt.Sprintf("%s/%s", rootDir, f.Name()))
		}
	}

	return
}

// listEgressKeys returns the list of public keys contained in HomeDir/.ssh/*.pub
func (bg *Group) listPubKeys(keyType string) (keys []helpers.PublicKey, err error) {

	var pathes []string
	if keyType == "egress" {
		pathes, err = bg.getPubKeyFilePathes()
		if err != nil {
			return
		}
	} else {
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
