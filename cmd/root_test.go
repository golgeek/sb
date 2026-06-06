package cmd

import (
	"fmt"
	"os"
	osuser "os/user"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/golgeek/sb/internal/commands"
	"github.com/golgeek/sb/internal/helpers"
	"github.com/golgeek/sb/internal/models"
	"github.com/golgeek/sb/internal/types"

	"github.com/stretchr/testify/require"
)

type commandTestStructure struct {
	i commandTestStructureInputData
	o error
}
type commandTestStructureInputData struct {
	arguments []string
	user      *models.User
}

func TestIsATrustedCommand(t *testing.T) {

	require.Equal(t, true, commands.IsAPublicCommand("self accesses list"), "The command self accesses list is a public command")
	require.Equal(t, false, commands.IsAPublicCommand("INVALID_COMMAND"), "The command INVALID_COMMAND is not a public command")
	require.Equal(t, false, commands.IsAPublicCommand("ttyrec"), "The command INVALID_COMMAND is not a public command")
}

func TestBuildSBCommand(t *testing.T) {

	// Build a valid path for tests
	_, filename, _, _ := runtime.Caller(0)
	etcGroupPath := fmt.Sprintf("%s/../internal/models/test_assets/group/group", filepath.Dir(filename))

	helpers.SetEtcGroupFilePath(etcGroupPath)

	owner := &models.User{
		User: &osuser.User{
			Uid:      "1000",
			Gid:      "1000",
			Username: "testuser",
			Name:     "Test User",
			HomeDir:  "",
		},
		Groups: map[string]*models.Group{},
	}
	owner.BuildGroupsMembership([]string{"bg_owners-o"})

	user := &models.User{
		User: &osuser.User{
			Uid:      "1000",
			Gid:      "1000",
			Username: "testuser",
			Name:     "Test User",
			HomeDir:  "",
		},
		Groups: map[string]*models.Group{},
	}
	user.BuildGroupsMembership([]string{"bg_developers-aclk", "bg_sysadmins-gk", "bg_everyone"})

	tests := []commandTestStructure{
		{
			i: commandTestStructureInputData{user: user, arguments: []string{"help"}},
			o: nil,
		},
		{
			i: commandTestStructureInputData{user: user, arguments: []string{"INVALID_COMMAND"}},
			o: fmt.Errorf("unknown command"),
		},
		{
			i: commandTestStructureInputData{user: user, arguments: []string{"self access add", "help"}},
			o: types.ErrMissingArguments,
		},
		{
			i: commandTestStructureInputData{user: user, arguments: []string{"self access add", "--host", "test"}},
			o: types.ErrMissingArguments,
		},
		{
			i: commandTestStructureInputData{user: user, arguments: []string{"self egress-key generate", "--algo", "ed25519"}},
			o: fmt.Errorf("please provide required argument --size"),
		},
		{
			i: commandTestStructureInputData{user: user, arguments: []string{"self egress-key generate", "--algo", "ed25519", "--size", "INVALID"}},
			o: fmt.Errorf("please provide a valid numeric size"),
		},
		{
			i: commandTestStructureInputData{user: user, arguments: []string{"self egress-key generate", "--algo", "INVALID_ALGO", "--size", "256"}},
			o: fmt.Errorf("argument --algo's value should be from the list: rsa, ecdsa, ed25519"),
		},
		{
			i: commandTestStructureInputData{user: user, arguments: []string{"self egress-key generate", "--algo", "ed25519", "--size", "512"}},
			o: fmt.Errorf("for ED25519, size is always 256"),
		},
		{
			i: commandTestStructureInputData{user: user, arguments: []string{"self egress-key generate", "--algo", "rsa", "--size", "128"}},
			o: fmt.Errorf("for RSA, choose a size between 2048 and 8192 (4096 is good)"),
		},
		{
			i: commandTestStructureInputData{user: user, arguments: []string{"self egress-key generate", "--algo", "ecdsa", "--size", "128"}},
			o: fmt.Errorf("for ECDSA, choose either 256, 384 or 512"),
		},
		{
			i: commandTestStructureInputData{user: owner, arguments: []string{"self egress-key generate", "--algo", "ed25519", "--size", "256"}},
			o: nil,
		},
		{
			i: commandTestStructureInputData{user: owner, arguments: []string{"group egress-key generate", "--group", "owners", "--algo", "ed25519"}},
			o: fmt.Errorf("please provide required argument --size"),
		},
		{
			i: commandTestStructureInputData{user: owner, arguments: []string{"group egress-key generate", "--algo", "ed25519", "--size", "INVALID"}},
			o: fmt.Errorf("please provide a valid numeric size"),
		},
		{
			i: commandTestStructureInputData{user: owner, arguments: []string{"group egress-key generate", "--group", "owners", "--algo", "INVALID_ALGO", "--size", "256"}},
			o: fmt.Errorf("argument --algo's value should be from the list: rsa, ecdsa, ed25519"),
		},
		{
			i: commandTestStructureInputData{user: owner, arguments: []string{"groupGenerateEgressKey", "--group", "owners", "--algo", "ed25519", "--size", "512"}},
			o: fmt.Errorf("for ED25519, size is always 256"),
		},
		{
			i: commandTestStructureInputData{user: owner, arguments: []string{"group egress-key generate", "--group", "owners", "--algo", "rsa", "--size", "128"}},
			o: fmt.Errorf("for RSA, choose a size between 2048 and 8192 (4096 is good)"),
		},
		{
			i: commandTestStructureInputData{user: owner, arguments: []string{"group egress-key generate", "--group", "owners", "--algo", "ecdsa", "--size", "128"}},
			o: fmt.Errorf("for ECDSA, choose either 256, 384 or 512"),
		},
		{
			i: commandTestStructureInputData{user: owner, arguments: []string{"group egress-key generate", "--group", "owners", "--algo", "ed25519", "--size", "256"}},
			o: nil,
		},
		{
			i: commandTestStructureInputData{user: user, arguments: []string{"group access add", "--group", "developers", "--host", "test.com", "--user", "test"}},
			o: nil,
		},
		{
			i: commandTestStructureInputData{user: owner, arguments: []string{"group access add", "--group", "developers", "--host", "test.com", "--user", "test"}},
			o: fmt.Errorf("user is not an ACL keeper of the group"),
		},
		{
			i: commandTestStructureInputData{user: user, arguments: []string{"group access add", "--group", "developers", "--host", "test.com", "--user", "test", "--alias", "account delete"}},
			o: fmt.Errorf("the host or alias provided matches a sb command name, please provide a different value"),
		},
		{
			i: commandTestStructureInputData{user: user, arguments: []string{"group member add", "--group", "sysadmins", "--account", os.Getenv("USER")}},
			o: nil,
		},
		{
			i: commandTestStructureInputData{user: user, arguments: []string{"group member add", "--group", "developers", "--account", os.Getenv("USER")}},
			o: fmt.Errorf("user is not a gate keeper of the group"),
		},
		{
			i: commandTestStructureInputData{user: user, arguments: []string{"group accesses list", "--group", "everyone"}},
			o: nil,
		},
		{
			i: commandTestStructureInputData{user: user, arguments: []string{"group accesses list", "--group", "developers"}},
			o: fmt.Errorf("user is not a member of the group"),
		},
		{
			i: commandTestStructureInputData{user: user, arguments: []string{"group accesses list", "--group", "everyone"}},
			o: nil,
		},
		{
			i: commandTestStructureInputData{user: user, arguments: []string{"group owner add", "--group", "developers", "--account", os.Getenv("USER")}},
			o: fmt.Errorf("user is not an owner of the group"),
		},
		{
			i: commandTestStructureInputData{user: owner, arguments: []string{"group owner add", "--group", "owners", "--account", os.Getenv("USER")}},
			o: nil,
		},
		{
			i: commandTestStructureInputData{user: user, arguments: []string{"account create", "--username", "test", "--public-key", "test"}},
			o: fmt.Errorf("user is not a sb owner"),
		},
		{
			i: commandTestStructureInputData{user: owner, arguments: []string{"account create", "--username", "test", "--public-key", "test"}},
			o: fmt.Errorf("ssh: no key found"),
		},
		{
			i: commandTestStructureInputData{user: owner, arguments: []string{"account create", "--username", "test", "--public-key", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFxu5J1fpfRBHe/2JKreeDGgJlMZji3n97fYm3KJt8Yv sb@localhost"}},
			o: nil,
		},
		{
			i: commandTestStructureInputData{user: user, arguments: []string{"group accesses list", "--group", "everyone"}},
			o: nil,
		},
	}

	for _, testData := range tests {

		log := models.NewLog(testData.i.user.User.Username, []string{":memory:"}, testData.i.arguments)

		_, _, err := commands.BuildSBCommand(log, testData.i.user, testData.i.arguments...)
		if testData.o == nil {
			require.NoError(t, err, "An unexpected error occurred while testing BuildSBCommand()")
		} else {
			require.Error(t, err, testData.o.Error(), "An error should have occurred while testing BuildSBCommand()")
		}

	}

}
