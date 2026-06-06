package models

import (
	"fmt"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/golgeek/sb/internal/helpers"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestGetAllGroups(t *testing.T) {

	// Start by getting group info in an invalid file
	helpers.SetEtcGroupFilePath("INVALID_PATH")

	_, err := GetAllSBGroups()
	require.Error(t, err, "An error should have occurred with this invalid path")

	_, err = GetGroup("test_group")
	require.Error(t, err, "An error should have occurred with this invalid path")

	// Build a valid path for the subsequent tests
	_, filename, _, _ := runtime.Caller(0)
	etcGroupPath := fmt.Sprintf("%s/test_assets/group/group", filepath.Dir(filename))

	expectedGroups := map[string]*Group{
		"owners": {
			Name:       "owners",
			SystemName: "bg_owners",
		},
		"developers": {
			Name:       "developers",
			SystemName: "bg_developers",
		},
		"sysadmins": {
			Name:       "sysadmins",
			SystemName: "bg_sysadmins",
		},
		"everyone": {
			Name:       "everyone",
			SystemName: "bg_everyone",
		},
	}

	helpers.SetEtcGroupFilePath(etcGroupPath)

	groups, err := GetAllSBGroups()
	require.NoError(t, err, "An unexpected error occurred when calling GetAllSBGroups")
	require.Equal(t, expectedGroups, groups, "GetAllSBGroups returned an invalid value")

	_, err = GetGroup("test_group")
	require.Error(t, err, "An error should have occurred with this invalid group when calling GetGroup")

	group, err := GetGroup("developers")
	require.NoError(t, err, "An unexpected error occurred when calling GetGroup")
	require.Equal(t, expectedGroups["developers"], group, "GetAllSBGroups returned an invalid value")
}

func TestOverrides(t *testing.T) {
	// Build a valid path for tests
	_, filename, _, _ := runtime.Caller(0)
	etcGroupPath := fmt.Sprintf("%s/test_assets/group/group", filepath.Dir(filename))

	helpers.SetEtcGroupFilePath(etcGroupPath)

	group, err := GetGroup("developers")
	require.NoError(t, err, "An unexpected error occurred when calling GetGroup")

	keyFilesRootDirStartValue := group.getKeyFilesRootDir()
	databaseAccessFilePathStartValue := group.getDatabaseAccessFilePath()

	group.OverrideKeyFilesRootDir("TEST")
	group.OverrideDatabaseAccessFilePath("TEST")

	require.NotEqual(t, keyFilesRootDirStartValue, group.getKeyFilesRootDir(), "Key files root dir should have been overridden")
	require.NotEqual(t, databaseAccessFilePathStartValue, group.getDatabaseAccessFilePath(), "Database access file path should have been overridden")
}

func TestGetMembers(t *testing.T) {

	// Build a valid path for tests
	_, filename, _, _ := runtime.Caller(0)
	etcGroupPath := fmt.Sprintf("%s/test_assets/group/group", filepath.Dir(filename))

	helpers.SetEtcGroupFilePath(etcGroupPath)

	group, err := GetGroup("developers")
	require.NoError(t, err, "An unexpected error occurred when calling GetGroup")

	helpers.SetEtcGroupFilePath(etcGroupPath)

	tests := map[string]map[string][]string{
		"owner": {
			"types":   {"owner"},
			"members": {"test3"},
		},
		"gate-keeper": {
			"types":   {"gk", "gate-keeper", "gatekeeper"},
			"members": {"test3"},
		},
		"acl-keeper": {
			"types":   {"aclk", "acl-keeper", "aclkeeper"},
			"members": {"test3", "test2"},
		},
		"member": {
			"types":   {"member"},
			"members": {"test3", "test", "test4"},
		},
	}

	for _, configuration := range tests {
		for _, memberType := range configuration["types"] {
			members, err := group.GetMembers(memberType)
			require.NoError(t, err, "An unexpected error occurred when calling GetMembers")
			require.Equal(t, configuration["members"], members, "GetMembers didn't return the expected members")
		}
	}

	_, err = group.GetMembers("INVALID_TYPE")
	require.Error(t, err, "An error should have occurred with this invalid type when calling GetMembers")

	helpers.SetEtcGroupFilePath("INVALID_PATH")
	_, err = group.GetMembers("owner")
	require.Error(t, err, "An error should have occurred when calling GetMembers with an invalid path to /etc/group")
}

func TestGetAccessesNoHandler(t *testing.T) {

	// Build a valid path for tests
	_, filename, _, _ := runtime.Caller(0)
	etcGroupPath := fmt.Sprintf("%s/test_assets/group/group", filepath.Dir(filename))
	keyFilesRootDir := fmt.Sprintf("%s/test_assets/group/.ssh", filepath.Dir(filename))

	helpers.SetEtcGroupFilePath(etcGroupPath)

	group, err := GetGroup("developers")
	require.NoError(t, err, "An unexpected error occurred when calling GetGroup")

	// Start by testing the instanciation of the database
	group.OverrideDatabaseAccessFilePath(":memory:")
	group.OverrideKeyFilesRootDir(keyFilesRootDir)

	// Getting empty accesses
	accesses, err := group.GetAccesses()
	require.NoError(t, err, "An unexpected error occurred when calling GetAccesses")
	require.Equal(t, 0, len(accesses.Accesses), "There should not be any access available")
	require.Equal(t, 2, len(accesses.Keys), "There should be two SSH key pairs")
	require.Equal(t, "group", accesses.Type, "The access type should be a group one")
	require.Equal(t, group.Name, accesses.Group, "The access Group property should match the group name")
}

func TestAddAccessNoHandler(t *testing.T) {

	// Build a valid path for tests
	_, filename, _, _ := runtime.Caller(0)
	etcGroupPath := fmt.Sprintf("%s/test_assets/group/group", filepath.Dir(filename))

	helpers.SetEtcGroupFilePath(etcGroupPath)

	group, err := GetGroup("developers")
	require.NoError(t, err, "An unexpected error occurred when calling GetGroup")

	group.OverrideDatabaseAccessFilePath(":memory:")

	// Add an access without a DB handler
	_, err = group.AddAccess("test.com", "root", "22", "test", "Added for tests")
	require.NoError(t, err, "An unexpected error occurred when calling AddAccess")

	// Add an access that fails a DB handler
	_, err = group.AddAccess("NOT_A_VALID_HOST", "root", "22", "test", "Added for tests")
	require.Error(t, err, fmt.Errorf("host is neither an IP, a prefix or a resolvable host"), "An error should have occurred when calling AddAccess")
}

func TestDeleteAccessNoHandler(t *testing.T) {

	// Build a valid path for tests
	_, filename, _, _ := runtime.Caller(0)
	etcGroupPath := fmt.Sprintf("%s/test_assets/group/group", filepath.Dir(filename))

	helpers.SetEtcGroupFilePath(etcGroupPath)

	group, err := GetGroup("developers")
	require.NoError(t, err, "An unexpected error occurred when calling GetGroup")

	group.OverrideDatabaseAccessFilePath(":memory:")

	// Delete an unknown access without a DB handler
	_, err = group.DeleteAccess("test.com", "root", "22")
	require.Error(t, err, fmt.Errorf("record not found"), "An error should have been raised when deleting an unknown host")

	// Add an access that fails a DB handler
	_, err = group.DeleteAccess("NOT_A_VALID_HOST", "root", "22")
	require.Error(t, err, fmt.Errorf("host is neither an IP, a prefix or a resolvable host"), "An error should have occurred when calling DeleteAccess on an invalid host")
}

func TestGroupAccesses(t *testing.T) {

	// Build a valid path for tests
	_, filename, _, _ := runtime.Caller(0)
	etcGroupPath := fmt.Sprintf("%s/test_assets/group/group", filepath.Dir(filename))
	keyFilesRootDir := fmt.Sprintf("%s/test_assets/group/.ssh", filepath.Dir(filename))

	helpers.SetEtcGroupFilePath(etcGroupPath)

	group, err := GetGroup("developers")
	require.NoError(t, err, "An unexpected error occurred when calling GetGroup")

	group.OverrideKeyFilesRootDir(keyFilesRootDir)

	// Working with a gorm.DB handler
	db, err := GetAccessGormDB(":memory:")
	require.NoError(t, err, "An unexpected error occurred when getting the database handler")

	ba, err := group.AddAccess("test.com", "root", "22", "test", "Added for tests", db)
	require.NoError(t, err, "An unexpected error occurred when calling AddAccess")
	// We reset the data we don't store in database for comparaison later
	ba.IP = nil

	accesses, err := group.GetAccesses(db)
	require.NoError(t, err, "An unexpected error occurred when calling GetAccesses")
	require.Equal(t, 1, len(accesses.Accesses), "There should only be one access available")
	require.Equal(t, ba, accesses.Accesses[0], "There should only be one access available")
	require.Equal(t, 2, len(accesses.Keys), "There should be two SSH key pairs")
	require.Equal(t, "group", accesses.Type, "The access type should be a group one")
	require.Equal(t, group.Name, accesses.Group, "The access Group property should match the group name")

	_, err = group.DeleteAccess("test.com", "root", "22", db)
	require.NoError(t, err, "An unexpected error occurred when calling DeleteAccess")

	// Getting empty accesses
	accesses, err = group.GetAccesses(db)
	require.NoError(t, err, "An unexpected error occurred when calling GetAccesses")
	require.Equal(t, 0, len(accesses.Accesses), "There should not be any access available")
}

func TestDisplayPubKeys(t *testing.T) {

	// Build a valid path for tests
	_, filename, _, _ := runtime.Caller(0)
	etcGroupPath := fmt.Sprintf("%s/test_assets/group/group", filepath.Dir(filename))
	keyFilesRootDir := fmt.Sprintf("%s/test_assets/group/.ssh", filepath.Dir(filename))

	helpers.SetEtcGroupFilePath(etcGroupPath)

	group, err := GetGroup("developers")
	require.NoError(t, err, "An unexpected error occurred when calling GetGroup")

	// Override the key files root dir with an invalid value to generate an error when reading the directory
	group.OverrideKeyFilesRootDir("INVALID_PATH")
	_, _, err = group.DisplayPubKeys("egress")
	require.Error(t, err, fmt.Errorf("open INVALID_PATH: no such file or directory"), "An error should be raised if the file path is invalid")

	// Set the key files root dir with our assets values
	group.OverrideKeyFilesRootDir(keyFilesRootDir)

	// Test an invalid type of keys
	_, _, err = group.DisplayPubKeys("ingress")
	require.Error(t, err, fmt.Errorf("unknown type of key"), "There are no ingress keys for groups")

	// Prepare the expected results
	pubKeys := []string{
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFxu5J1fpfRBHe/2JKreeDGgJlMZji3n97fYm3KJt8Yv sb@localhost",
		"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDDviAgF0HG8m+Fu93Ob0ZgNsboHED1FEi7/LhakVO55Jka0HVV/dKm1Dg+X0+pHlKNteRrLjBT9MA8+cjTdpxCYj/jWovlUcBqZupJTi+xvSGP4q2flZdKTUh+D/bhTwcrQ910BwAzR9iMGqny3m4F62GUTQayhNMHpkOl6wicdwuMN6BYLrcm5qy9tpq0IrBYBWPyi/7knbMNTEH0UqjIIAfrO5ZHlfRs6jJ5R9gMBuJ/C4PIslzIG8WCyzS5kKrSz14xBldcj63eHtoB1ZU6RuaN4OluJLzdFFkRfGsVWQ6sVhpIMAJRCddRD2oACeHzlZiA7k32ddUKuw4Y3v1B sb@localhost",
	}

	expectedResult := make([]helpers.PublicKey, 0)
	for _, key := range pubKeys {
		publicKey, comment, options, rest, _ := ssh.ParseAuthorizedKey([]byte(key))

		expectedResult = append(expectedResult, helpers.PublicKey{
			PublicKey: publicKey,
			Comment:   comment,
			Options:   options,
			Rest:      rest,
		})
	}

	// Call the function and compare the result
	_, keys, err := group.DisplayPubKeys("egress")
	require.NoError(t, err, "An unexpected error occurred when calling DisplayPubKeys()")
	require.Equal(t, expectedResult, keys, "The array of helpers.PublicKey is not valid")

}
