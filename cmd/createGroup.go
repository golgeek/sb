package cmd

import (
	"fmt"
	"strconv"
	"syscall"

	"github.com/golgeek/sb/internal/commands"
	"github.com/golgeek/sb/internal/helpers"
	"github.com/golgeek/sb/internal/models"

	"golang.org/x/term"
)

// CreateGroup describes the command
type CreateGroup struct{}

func init() {
	commands.Register(commands.CommandSpec{
		Name:    "group create",
		Aliases: []string{"createGroup"},
		Rights:  models.SBOwner,
		Help: helpers.Helper{
			Header:      "create a new group on sb",
			Usage:       "group create --name NAME --owner-account USERNAME --algo ALGO --size SIZE [--encrypted]",
			Description: "create a new group on sb",
		},
		Args: map[string]commands.Argument{
			"name": {
				Required:    true,
				Description: "The name of the group",
			},
			"owner-account": {
				Required:    true,
				Description: "The username of the group's owner account",
			},
			"algo": {
				Required:      true,
				Description:   "Specifies the algo of the key, either rsa, ecdsa or ed25519",
				AllowedValues: []string{"rsa", "ecdsa", "ed25519"},
			},
			"size": {
				Required: true,
				Description: `Size of the key to generate:
	- for RSA, choose between 2048 and 8192 (4096 is good)
	- for ECDSA, choose either 256, 384 or 521
	- for ED25519, size is always 256`,
			},
			"encrypted": {
				Required:    false,
				Description: "If specified, a passphrase will be prompted for the new key",
				Type:        commands.BOOL,
			},
		},
		New: func() commands.Command { return new(CreateGroup) },
	})
}

// Checks checks whether or not the user can execute this method
func (c *CreateGroup) Checks(ct *commands.Context) (err error) {

	// Validate the requested group name up front so a malformed name is rejected
	// with a clear message before any system change is attempted. The same
	// validation is enforced again deeper in helpers.AddGroup as the fail-closed
	// security boundary.
	if err = helpers.ValidateSystemName(ct.FormattedArguments["name"]); err != nil {
		return
	}

	// Check if the chosen group name is available
	groups, err := models.GetAllSBGroups()
	if err != nil {
		return
	}
	if _, ok := groups[ct.FormattedArguments["name"]]; ok {
		err = fmt.Errorf("group %s already exists", ct.FormattedArguments["name"])
		return
	}

	// Check if the owner-account exists
	_, err = models.LoadUser(ct.FormattedArguments["owner-account"])
	if err != nil {
		return
	}

	// Check the ssh key parameters
	sizeInt, err := strconv.Atoi(ct.FormattedArguments["size"])
	if err != nil {
		err = fmt.Errorf("please provide a valid numeric size")
		return
	}
	switch ct.FormattedArguments["algo"] {
	case "rsa":
		if sizeInt < 2048 || sizeInt > 8192 {
			err = fmt.Errorf("for RSA, choose a size between 2048 and 8192 (4096 is good)")
			return
		}
	case "ecdsa":
		if sizeInt != 256 && sizeInt != 384 && sizeInt != 521 {
			err = fmt.Errorf("for ECDSA, choose either 256, 384 or 521")
			return
		}
	case "ed25519":
		if sizeInt != 256 {
			err = fmt.Errorf("for ED25519, size is always 256")
			return
		}
	}

	return
}

// Execute executes the command
func (c *CreateGroup) Execute(ct *commands.Context) (repl models.ReplicationData, cmdError error, err error) {

	// Ask for the passphrase if requested
	passphrase, ok := ct.FormattedArguments["encrypted"]
	if ok {
		// We'll ask for a passphrase, here
		fmt.Printf("Please enter a passphrase for the new sb group key (not echoed): ")
		passphrase1, errRead := term.ReadPassword(syscall.Stdin)
		fmt.Println()
		if errRead != nil {
			err = errRead
			return
		}
		if len(passphrase1) < 5 {
			err = fmt.Errorf("passphrase needs to be at least 5 chars")
			return
		}

		fmt.Printf("Please enter it again: ")
		passphrase2, errRead := term.ReadPassword(syscall.Stdin)
		fmt.Println()
		if errRead != nil {
			err = errRead
			return
		}

		if string(passphrase1) != string(passphrase2) {
			err = fmt.Errorf("passphrases don't match, please try again")
			return
		}

		passphrase = string(passphrase1)
	}

	// Generate the new SSH keypair of the group
	privateKey, publicKey, privateKeyFile, publicKeyFile, filesOwner, err := helpers.GenerateNewEgressGroupKey(ct.FormattedArguments["algo"], ct.FormattedArguments["size"], passphrase, ct.FormattedArguments["name"])
	if err != nil {
		return
	}

	// We gathered all required data without modifying the system
	repl = models.ReplicationData{
		"name":             ct.FormattedArguments["name"],
		"owner-account":    ct.FormattedArguments["owner-account"],
		"files-owner":      filesOwner,
		"private-key":      privateKey,
		"public-key":       publicKey,
		"private-key-file": privateKeyFile,
		"public-key-file":  publicKeyFile,
	}

	// Let's let the replication function do all the heavy lifting with the provided data
	err = c.Replicate(repl)

	return
}

func (c *CreateGroup) PostExecute(repl models.ReplicationData) (err error) {
	return
}

func (c *CreateGroup) Replicate(repl models.ReplicationData) (err error) {

	err = helpers.AddGroup(repl["name"], repl["owner-account"])
	if err != nil {
		return
	}

	fmt.Printf("Group %s was successfully created\n", repl["name"])

	err = helpers.WriteGroupPrivateKey(repl["private-key"], repl["private-key-file"], repl["files-owner"])
	if err != nil {
		return
	}

	err = helpers.WritePublicKey(repl["public-key"], repl["public-key-file"], repl["files-owner"])
	if err != nil {
		return
	}

	fmt.Println("The new egress private SSH key was successfully generated")

	return
}
