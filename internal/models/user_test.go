package models

import (
	"fmt"
	"os"
	osuser "os/user"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/golgeek/sb/internal/helpers"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestIsMemberOf(t *testing.T) {

	user := &User{
		User: &osuser.User{
			Uid:      "1000",
			Gid:      "1000",
			Username: "testuser",
			Name:     "Test User",
			HomeDir:  "",
		},
		Groups: map[string]*Group{},
	}

	user.BuildGroupsMembership([]string{"bg_owners-o", "bg_groupaclk-aclk", "bg_groupgatek-gk", "bg_groupmember"})

	require.Equal(t, false, user.IsACLKeeperOfGroup("groupgatek"), "User is not ACL keeper of group groupgatek")
	require.Equal(t, false, user.IsGateKeeperOfGroup("groupaclk"), "User is not gate keeper of group groupaclk")
	require.Equal(t, false, user.IsMemberOfGroup("groupgatek"), "User is not member of group groupgatek")
	require.Equal(t, false, user.IsOwnerOfGroup("groupgatek"), "User is not owner of group groupgatek")
	require.Equal(t, true, user.IsACLKeeperOfGroup("groupaclk"), "User is ACL keeper of group groupaclk")
	require.Equal(t, true, user.IsGateKeeperOfGroup("groupgatek"), "User is gate keeper of group groupgatek")
	require.Equal(t, true, user.IsMemberOfGroup("groupmember"), "User is not member of group groupmember")
	require.Equal(t, true, user.IsOwnerOfGroup("owners"), "User is not owner of group owners")

	groups, err := user.GetAllGroups()
	require.NoError(t, err, "An unexpected error occurred when calling GetAllGroups()")
	require.Equal(t, user.Groups, groups, "The groups returned are not valid")
}

func TestFilePathes(t *testing.T) {

	// Guess the working directory
	_, filename, _, _ := runtime.Caller(0)
	homeDir := filepath.Dir(filename)

	user := &User{
		User: &osuser.User{
			Uid:      "1000",
			Gid:      "1000",
			Username: "testuser",
			Name:     "Test User",
			HomeDir:  fmt.Sprintf("%s/test_assets/user", homeDir),
		},
		Groups: map[string]*Group{},
	}

	require.Equal(t, fmt.Sprintf("%s/logs.db", user.User.HomeDir), user.GetLocalLogDatabasePath(), "Log database path is not valid")
	require.Equal(t, fmt.Sprintf("%s/accesses.db", user.User.HomeDir), user.getDatabaseAccessFilePath(), "Access database path is not valid")
	require.Equal(t, fmt.Sprintf("%s/.ssh/authorized_keys", user.User.HomeDir), user.getAuthorizedKeysFilePathes(), "Authorized keys path is not valid")
	require.Equal(t, fmt.Sprintf("%s/ttyrecs", user.User.HomeDir), user.GetTtyrecDirectory(), "Ttyrecs directory is not valid")

	expectedKeyFilepathes := []string{
		fmt.Sprintf("%s/test_assets/user/.ssh/id_ed25519", homeDir),
		fmt.Sprintf("%s/test_assets/user/.ssh/id_invalid", homeDir),
		fmt.Sprintf("%s/test_assets/user/.ssh/id_rsa", homeDir),
	}

	keyFiles, err := user.getKeyFilePathes()
	require.NoError(t, err, "An unexpected error occurred when calling getKeyFilePathes")
	require.Equal(t, expectedKeyFilepathes, keyFiles, "Keyfile pathes are not valid")

	expectedPubkeyFilepathes := []string{
		fmt.Sprintf("%s/test_assets/user/.ssh/id_ed25519.pub", homeDir),
		fmt.Sprintf("%s/test_assets/user/.ssh/id_invalid.pub", homeDir),
		fmt.Sprintf("%s/test_assets/user/.ssh/id_rsa.pub", homeDir),
	}

	pubkeyFiles, err := user.getPubKeyFilePathes()
	require.NoError(t, err, "An unexpected error occurred when calling getKeyFilePathes")
	require.Equal(t, expectedPubkeyFilepathes, pubkeyFiles, "Keyfile pathes are not valid")

	err = user.OverrideDatabaseAccessFilePath(":memory:")
	require.NoError(t, err, "An error occurred while calling OverrideDatabaseAccessFilePath")
	require.Equal(t, ":memory:", user.getDatabaseAccessFilePath(), "Overridden access database path is not valid")

	_, _, err = user.DisplayPubKeys("NOT_A_VALID_TYPE")
	require.Error(t, err, fmt.Errorf("unknown type of key"), "NOT_A_VALID_TYPE is not a valid type")
	_, _, err = user.DisplayPubKeys("ingress")
	require.NoError(t, err, "An unexpected error occurred while calling DisplayPubKeys()")
	_, _, err = user.DisplayPubKeys("egress")
	require.NoError(t, err, "An unexpected error occurred while calling DisplayPubKeys()")
}

func TestListPubKeys(t *testing.T) {

	// Guess the working directory
	_, filename, _, _ := runtime.Caller(0)
	homeDir := filepath.Dir(filename)

	user := &User{
		User: &osuser.User{
			Uid:      "1000",
			Gid:      "1000",
			Username: "testuser",
			Name:     "Test User",
			HomeDir:  fmt.Sprintf("%s/test_assets/user", homeDir),
		},
		Groups: map[string]*Group{},
	}

	pubKeys := map[string][]string{
		"ingress": {
			"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFxu5J1fpfRBHe/2JKreeDGgJlMZji3n97fYm3KJt8Yv sb@localhost",
		},
		"egress": {
			"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFxu5J1fpfRBHe/2JKreeDGgJlMZji3n97fYm3KJt8Yv sb@localhost",
			"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDDviAgF0HG8m+Fu93Ob0ZgNsboHED1FEi7/LhakVO55Jka0HVV/dKm1Dg+X0+pHlKNteRrLjBT9MA8+cjTdpxCYj/jWovlUcBqZupJTi+xvSGP4q2flZdKTUh+D/bhTwcrQ910BwAzR9iMGqny3m4F62GUTQayhNMHpkOl6wicdwuMN6BYLrcm5qy9tpq0IrBYBWPyi/7knbMNTEH0UqjIIAfrO5ZHlfRs6jJ5R9gMBuJ/C4PIslzIG8WCyzS5kKrSz14xBldcj63eHtoB1ZU6RuaN4OluJLzdFFkRfGsVWQ6sVhpIMAJRCddRD2oACeHzlZiA7k32ddUKuw4Y3v1B sb@localhost",
		},
	}

	_, err := user.listPubKeys("NOT_A_VALID_TYPE")
	require.Error(t, err, fmt.Errorf("unknown type of key"), "NOT_A_VALID_TYPE is not a valid type")

	for keyType, keys := range pubKeys {

		expectedResult := make([]helpers.PublicKey, 0, len(keys))
		for _, key := range keys {
			publicKey, comment, options, rest, _ := ssh.ParseAuthorizedKey([]byte(key))

			expectedResult = append(expectedResult, helpers.PublicKey{
				PublicKey: publicKey,
				Comment:   comment,
				Options:   options,
				Rest:      rest,
			})
		}

		keys, err := user.listPubKeys(keyType)
		require.NoError(t, err, "An unexpected error occurred when calling listPubKeys")
		require.Equal(t, expectedResult, keys, "The array of helpers.PublicKey is not valid")

	}

}

func TestManageKeys(t *testing.T) {

	// Guess the working directory
	_, filename, _, _ := runtime.Caller(0)
	homeDir := filepath.Dir(filename)

	user := &User{
		User: &osuser.User{
			Uid:      "1000",
			Gid:      "1000",
			Username: "testuser",
			Name:     "Test User",
			HomeDir:  fmt.Sprintf("%s/test_assets/user", homeDir),
		},
		Groups: map[string]*Group{},
	}

	// Start by overriding the authorized_keys file path
	file, _ := os.CreateTemp("/tmp", "")
	require.NoError(t, user.OverrideAuthorizedKeysFilePath(file.Name()))

	// Add a new ingress key
	pubKey := "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDDviAgF0HG8m+Fu93Ob0ZgNsboHED1FEi7/LhakVO55Jka0HVV/dKm1Dg+X0+pHlKNteRrLjBT9MA8+cjTdpxCYj/jWovlUcBqZupJTi+xvSGP4q2flZdKTUh+D/bhTwcrQ910BwAzR9iMGqny3m4F62GUTQayhNMHpkOl6wicdwuMN6BYLrcm5qy9tpq0IrBYBWPyi/7knbMNTEH0UqjIIAfrO5ZHlfRs6jJ5R9gMBuJ/C4PIslzIG8WCyzS5kKrSz14xBldcj63eHtoB1ZU6RuaN4OluJLzdFFkRfGsVWQ6sVhpIMAJRCddRD2oACeHzlZiA7k32ddUKuw4Y3v1B sb@localhost"
	publicKey, comment, options, rest, _ := ssh.ParseAuthorizedKey([]byte(pubKey))
	pubkeyHelper := helpers.PublicKey{
		PublicKey: publicKey,
		Comment:   comment,
		Options:   options,
		Rest:      rest,
	}

	err := user.AddIngressKey(pubkeyHelper.String())
	require.NoError(t, err, "An unexpected error occurred when adding a new ingress public key")

	// List the ingress keys
	keys, err := user.listPubKeys("ingress")
	require.NoError(t, err, "An unexpected error occurred when listing ingress public keys")
	require.Equal(t, []helpers.PublicKey{pubkeyHelper}, keys, "The added ingress key is not present in the final file")

	// Delete the ingress key
	err = user.DeletePubKey("ingress", pubkeyHelper)
	require.NoError(t, err, "An unexpected error occurred when deleting an ingress public key")

	// Relist the ingress keys to check it's disappeared
	keys, err = user.listPubKeys("ingress")
	require.NoError(t, err, "An unexpected error occurred when listing ingress public keys")
	require.Equal(t, 0, len(keys), "The added ingress key is still present in the final file")

	// Delete a wrong type
	err = user.DeletePubKey("NOT_A_VALID_TYPE", pubkeyHelper)
	require.Error(t, err, "NOT_A_VALID_TYPE is not a valid type and should have raise an error")

	// Add an egress pubkey to try the delete method
	egressPubKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC2FqWH9g+71ul7s2TPuXP+GoGt+HapvY+1pWc1f0uVj sb@localhost"
	publicKey, comment, options, rest, _ = ssh.ParseAuthorizedKey([]byte(egressPubKey))
	pubkeyHelper = helpers.PublicKey{
		PublicKey: publicKey,
		Comment:   comment,
		Options:   options,
		Rest:      rest,
	}

	// Delete the ingress key
	err = user.DeletePubKey("egress", pubkeyHelper)
	require.NoError(t, err, "An unexpected error occurred when deleting an ingress public key")
}

func TestShortString(t *testing.T) {

	user := &User{
		User: &osuser.User{
			Uid:      "1000",
			Gid:      "1000",
			Username: "testuser",
			Name:     "Test User",
			HomeDir:  "",
		},
		Groups: map[string]*Group{},
	}

	require.Equal(t, user.User.Username, user.ShortString(), "The ShortString() func is not valid")

}

func TestLoadCurrentUser(t *testing.T) {
	user, err := LoadCurrentUser()
	require.NoError(t, err, "An unexpected error occurred while calling LoadCurrentUser()")
	require.Equal(t, os.Getenv("USER"), user.User.Username, "The LoadCurrentUser doesn't match the current user in environment variable")
}

func TestGetAllSBUsers(t *testing.T) {

	// Build a valid path for the subsequent tests
	_, filename, _, _ := runtime.Caller(0)
	etcPasswdPath := fmt.Sprintf("%s/test_assets/user/passwd", filepath.Dir(filename))
	helpers.SetEtcPasswdFilePath(etcPasswdPath)

	users, err := GetAllSBUsers()
	require.NoError(t, err, "An unexpected error occurred when calling GetAllSBUsers")
	require.Equal(t, 5, len(users), "GetAllSBUsers returned an invalid value")

}

func TestInvalidUser(t *testing.T) {
	_, err := LoadUser("INVALID_USERNAME")
	require.Error(t, err, "INVALID_USERNAME is not a real user")
}

func TestLastSSHSessions(t *testing.T) {

	// Guess the working directory
	_, filename, _, _ := runtime.Caller(0)
	homeDir := filepath.Dir(filename)

	user := &User{
		User: &osuser.User{
			Uid:      "1000",
			Gid:      "1000",
			Username: "testuser",
			Name:     "Test User",
			HomeDir:  fmt.Sprintf("%s/test_assets/user", homeDir),
		},
		Groups: map[string]*Group{},
	}

	require.NoError(t, user.OverrideDatabaseAccessFilePath(":memory:"))

	sessions, err := user.GetLastSSHSessions(20)
	require.NoError(t, err, "An unexpected error occurred when calling GetLastSSHSessions()")
	require.Equal(t, 0, len(sessions), "There shouldn't be any session")
}

func TestUserAccesses(t *testing.T) {

	// Guess the working directory
	_, filename, _, _ := runtime.Caller(0)
	homeDir := filepath.Dir(filename)

	user := &User{
		User: &osuser.User{
			Uid:      "1000",
			Gid:      "1000",
			Username: "testuser",
			Name:     "Test User",
			HomeDir:  fmt.Sprintf("%s/test_assets/user", homeDir),
		},
		Groups: map[string]*Group{},
	}

	// Add with classic DB
	require.NoError(t, user.OverrideDatabaseAccessFilePath(":memory:"))

	_, err := user.AddAccess("test.com", "root", "22", "test", "Added for tests")
	require.NoError(t, err, "An unexpected error occurred when calling AddAccess")

	_, err = user.AddAccess("NOT_A_VALID_HOST", "root", "22", "test", "Added for tests")
	require.Error(t, err, fmt.Errorf("host is neither an IP, a prefix or a resolvable host"), "An error should have occurred when calling AddAccess")

	accesses, err := user.GetAccesses()
	require.NoError(t, err, "An unexpected error occurred when calling GetAccesses")
	require.Equal(t, 0, len(accesses[0].Accesses), "There should not be any access available")

	_, err = user.DeleteAccess("test.com", "root", "22")
	require.Error(t, err, fmt.Errorf("record not found"), "Record shouldn't have been found in the memory database")

	// Working with a gorm.DB handler
	db, err := GetAccessGormDB(":memory:")
	require.NoError(t, err, "An unexpected error occurred when getting the database handler")

	ba, err := user.AddAccess("test.com", "root", "22", "test", "Added for tests", db)
	require.NoError(t, err, "An unexpected error occurred when calling AddAccess")
	// We reset the data we don't store in database for comparaison later
	ba.IP = nil

	accesses, err = user.GetAccesses(db)
	require.NoError(t, err, "An unexpected error occurred when calling GetAccesses")
	require.Equal(t, 1, len(accesses[0].Accesses), "There should only be one access available")
	require.Equal(t, ba, accesses[0].Accesses[0], "There should only be one access available")

	_, err = user.DeleteAccess("test.com", "root", "22", db)
	require.NoError(t, err, "An unexpected error occurred when calling DeleteAccess")
}

func TestHasAccesses(t *testing.T) {

	// Guess the working directory
	_, filename, _, _ := runtime.Caller(0)
	homeDir := filepath.Dir(filename)

	user := &User{
		User: &osuser.User{
			Uid:      "1000",
			Gid:      "1000",
			Username: "testuser",
			Name:     "Test User",
			HomeDir:  fmt.Sprintf("%s/test_assets/user", homeDir),
		},
		Groups: map[string]*Group{
			"developers": {
				Name:       "developers",
				SystemName: "bg_developers",
				Member:     true,
				Owner:      false,
				ACLKeeper:  false,
				GateKeeper: false,
			},
		},
	}

	user.Groups["developers"].OverrideDatabaseAccessFilePath(":memory:")
	user.Groups["developers"].OverrideKeyFilesRootDir(fmt.Sprintf("%s/.ssh", user.User.HomeDir))

	// Working with a gorm.DB handler
	db, err := GetAccessGormDB(":memory:")
	require.NoError(t, err, "An unexpected error occurred when getting the database handler")

	ba, err := user.AddAccess("test.com", "root", "22", "test", "Added for tests", db)
	require.NoError(t, err, "An unexpected error occurred when calling AddAccess")

	baCf, err := user.AddAccess("one.one.one.one", "root", "22", "one", "Added for tests", db)
	require.NoError(t, err, "An unexpected error occurred when calling AddAccess")

	baCf22022, err := user.AddAccess("one.one.one.one", "test", "22022", "cf", "Added for tests", db)
	require.NoError(t, err, "An unexpected error occurred when calling AddAccess")

	unauthorizedAccessHost, _ := BuildSBAccess("meow.com", "test", "22022", "", false)
	unauthorizedAccessRange, _ := BuildSBAccess("10.0.0.0/8", "test", "22022", "", false)
	unauthorizedAccessAlias, _ := BuildSBAccess("ALIAS", "", "", "", false)
	unauthorizedAccessUser, _ := BuildSBAccess("test.com", "titi", "22", "", false)
	unauthorizedAccessPort, _ := BuildSBAccess("test.com", "root", "22022", "", false)

	accessInfo, err := user.HasAccess(ba, db)
	require.NoError(t, err, "An unexpected error occurred when calling HasAccess")
	require.Equal(t, accessInfo.Authorized, true, "Access should be granted")

	accessInfo, err = user.HasAccess(baCf, db)
	require.NoError(t, err, "An unexpected error occurred when calling HasAccess")
	require.Equal(t, accessInfo.Authorized, true, "Access should be granted")

	accessInfo, err = user.HasAccess(baCf22022, db)
	require.NoError(t, err, "An unexpected error occurred when calling HasAccess")
	require.Equal(t, accessInfo.Authorized, true, "Access should be granted")

	accessInfo, err = user.HasAccess(unauthorizedAccessHost, db)
	require.NoError(t, err, "An unexpected error occurred when calling HasAccess")
	require.Equal(t, accessInfo.Authorized, false, "Access should not be granted")

	accessInfo, err = user.HasAccess(unauthorizedAccessRange, db)
	require.NoError(t, err, "An unexpected error occurred when calling HasAccess")
	require.Equal(t, accessInfo.Authorized, false, "Access should not be granted")

	accessInfo, err = user.HasAccess(unauthorizedAccessAlias, db)
	require.NoError(t, err, "An unexpected error occurred when calling HasAccess")
	require.Equal(t, accessInfo.Authorized, false, "Access should not be granted")

	accessInfo, err = user.HasAccess(unauthorizedAccessUser, db)
	require.NoError(t, err, "An unexpected error occurred when calling HasAccess")
	require.Equal(t, accessInfo.Authorized, false, "Access should not be granted")

	accessInfo, err = user.HasAccess(unauthorizedAccessPort, db)
	require.NoError(t, err, "An unexpected error occurred when calling HasAccess")
	require.Equal(t, accessInfo.Authorized, false, "Access should not be granted")

	_, err = user.DeleteAccess("test.com", "root", "22", db)
	require.NoError(t, err, "An unexpected error occurred when calling DeleteAccess")
}

func TestGetSSHKeyPairsInvalidPath(t *testing.T) {

	user := &User{
		User: &osuser.User{
			Uid:      "1000",
			Gid:      "1000",
			Username: "testuser",
			Name:     "Test User",
			HomeDir:  "INVALID_PATH",
		},
		Groups: map[string]*Group{},
	}

	_, err := user.GetSSHKeyPairs()
	require.Error(t, err, fmt.Errorf("open INVALID_PATH: no such file or directory"), "An error should be raised if the file path is invalid")
}

func TestTOTP(t *testing.T) {
	// Guess the working directory
	_, filename, _, _ := runtime.Caller(0)
	homeDir := filepath.Dir(filename)

	user := &User{
		User: &osuser.User{
			Uid:      "1000",
			Gid:      "1000",
			Username: "testuser",
			Name:     "Test User",
			HomeDir:  fmt.Sprintf("%s/test_assets/user", homeDir),
		},
	}
	testSecret := "randomstring"
	testEmergencyCodes := []string{"10", "11", "12", "13", "14"}

	enabled, _, _, err := user.GetTOTP()
	require.NoError(t, err, "reading a missing TOTP file should not be an error")
	require.Equal(t, false, enabled, "The TOTP for this user should be disabled")

	// SetTOTPSecret writes the secret file (which is what this test needs) and
	// then chowns it to the target user, which requires root. Unprivileged in the
	// test environment that chown fails, so the error is intentionally ignored
	// here; the written content is still verified by GetTOTP below.
	_ = user.SetTOTPSecret(testSecret, testEmergencyCodes)

	enabled, secret, emergencyCodes, err := user.GetTOTP()
	require.NoError(t, err, "reading a well-formed TOTP file should not error")
	require.Equal(t, true, enabled, "The TOTP for this user should be enabled")
	require.Equal(t, testSecret, secret, "The secret value is unexpected")
	require.Equal(t, testEmergencyCodes, emergencyCodes, "The emergency codes are unexpected")

	err = user.RemoveTOTPSecret()
	require.NoError(t, err, "An unexpected error occurred when removing TOTP")

	enabled, _, _, err = user.GetTOTP()
	require.NoError(t, err, "reading a removed TOTP file should not be an error")
	require.Equal(t, false, enabled, "The TOTP for this user should be disabled")
}

// TestGetTOTPMalformedFile asserts that GetTOTP fails closed — returns an error
// instead of panicking — when the .google_authenticator file exists but holds no
// secret line. The google_authenticator format puts the shared secret on the
// first line and option lines start with a double quote; a file made up of only
// option lines (or an empty file) therefore has no secret. Before this change,
// indexing the empty slice at lines[0] panicked, which on the per-command
// startup path was a denial of service for the affected user.
func TestGetTOTPMalformedFile(t *testing.T) {
	tests := map[string]string{
		"empty file":        "",
		"only option lines": "\" RATE_LIMIT 3 30\n\" WINDOW_SIZE 17\n",
		"trailing newlines": "\n\n",
	}

	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			// A throwaway home directory keeps the test hermetic — it never
			// touches the shared test_assets fixtures.
			home := t.TempDir()
			user := &User{User: &osuser.User{HomeDir: home}}

			err := os.WriteFile(filepath.Join(home, ".google_authenticator"), []byte(content), 0600)
			require.NoError(t, err, "failed to write the malformed TOTP fixture")

			require.NotPanics(t, func() {
				enabled, secret, codes, totpErr := user.GetTOTP()
				require.Error(t, totpErr, "a secret-less TOTP file must be reported as an error")
				require.False(t, enabled, "a malformed TOTP file must not be reported as enabled")
				require.Empty(t, secret, "no secret should be returned for a malformed file")
				require.Empty(t, codes, "no emergency codes should be returned for a malformed file")
			}, "GetTOTP must not panic on a malformed file")
		})
	}
}

// parseTestPublicKey builds a helpers.PublicKey from an authorized_keys line for
// use in the DeletePubKey tests.
func parseTestPublicKey(t *testing.T, line string) helpers.PublicKey {
	t.Helper()
	publicKey, comment, options, rest, err := ssh.ParseAuthorizedKey([]byte(line))
	require.NoError(t, err, "failed to parse the test public key")
	return helpers.PublicKey{PublicKey: publicKey, Comment: comment, Options: options, Rest: rest}
}

// TestDeletePubKeyReportsWriteError asserts that DeletePubKey surfaces a failure
// to rewrite authorized_keys instead of silently ignoring it. A swallowed write
// error would be a revocation bug: the key being removed could remain in the
// file and stay accepted, so revocation would appear to succeed while the key
// still worked.
func TestDeletePubKeyReportsWriteError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a write-permission failure cannot be provoked when running as root")
	}

	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFxu5J1fpfRBHe/2JKreeDGgJlMZji3n97fYm3KJt8Yv sb@localhost"
	pk := parseTestPublicKey(t, key)

	// A readable but unwritable authorized_keys file: the open and scan succeed,
	// but the subsequent rewrite fails with a permission error.
	path := filepath.Join(t.TempDir(), "authorized_keys")
	require.NoError(t, os.WriteFile(path, []byte(key+"\n"), 0444))

	user := &User{User: &osuser.User{HomeDir: t.TempDir()}}
	require.NoError(t, user.OverrideAuthorizedKeysFilePath(path))

	err := user.DeletePubKey("ingress", pk)
	require.Error(t, err, "a failed rewrite of authorized_keys must be reported")
}

// TestDeletePubKeyReportsReadError asserts that DeletePubKey aborts when the
// authorized_keys file cannot be read cleanly, instead of overwriting it with a
// possibly truncated key set. Pointing the path at a directory makes the open
// succeed but the scan fail.
func TestDeletePubKeyReportsReadError(t *testing.T) {
	pk := parseTestPublicKey(t, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFxu5J1fpfRBHe/2JKreeDGgJlMZji3n97fYm3KJt8Yv sb@localhost")

	user := &User{User: &osuser.User{HomeDir: t.TempDir()}}
	require.NoError(t, user.OverrideAuthorizedKeysFilePath(t.TempDir())) // a directory, not a file

	err := user.DeletePubKey("ingress", pk)
	require.Error(t, err, "a read failure must abort instead of overwriting with a truncated set")
}
