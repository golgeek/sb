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

// GroupGenerateEgressKey describes the command
type GroupGenerateEgressKey struct {
}

func init() {
	commands.Register(commands.CommandSpec{
		Name:    "group egress-key generate",
		Aliases: []string{"groupGenerateEgressKey"},
		Rights:  models.GroupOwner,
		Help: helpers.Helper{
			Header:      "generate a new SSH egress (sb -> distant host) key for a group",
			Usage:       "group egress-key generate --group GROUP --algo ALGO --size SIZE [--encrypted]",
			Description: "generate a new public + private key pair for a group",
		},
		Args: map[string]commands.Argument{
			"group": {
				Required:    true,
				Description: "The group",
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
		New: func() commands.Command { return new(GroupGenerateEgressKey) },
	})
}

// Checks checks whether or not the user can execute this method
func (c *GroupGenerateEgressKey) Checks(ct *commands.Context) (err error) {

	// Check SSH key parameters
	sizeInt, err := strconv.Atoi(ct.FormattedArguments["size"])
	if err != nil {
		return fmt.Errorf("please provide a valid numeric size")
	}
	switch ct.FormattedArguments["algo"] {
	case "rsa":
		if sizeInt < 2048 || sizeInt > 8192 {
			return fmt.Errorf("for RSA, choose a size between 2048 and 8192 (4096 is good)")
		}
	case "ecdsa":
		if sizeInt != 256 && sizeInt != 384 && sizeInt != 521 {
			return fmt.Errorf("for ECDSA, choose either 256, 384 or 512")
		}
	case "ed25519":
		if sizeInt != 256 {
			return fmt.Errorf("for ED25519, size is always 256")
		}
	}

	return nil
}

// Execute executes the command
func (c *GroupGenerateEgressKey) Execute(ct *commands.Context) (repl models.ReplicationData, cmdError error, err error) {

	passphrase, ok := ct.FormattedArguments["encrypted"]
	if ok {
		// We'll ask for a passphrase, here
		fmt.Printf("Please enter a passphrase for your new personal sb key (not echoed): ")
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

	privateKey, publicKey, privateKeyFile, publicKeyFile, filesOwner, err := helpers.GenerateNewEgressGroupKey(ct.FormattedArguments["algo"], ct.FormattedArguments["size"], passphrase, ct.Group.Name)
	if err != nil {
		return
	}

	repl = models.ReplicationData{
		"files-owner":      filesOwner,
		"private-key":      privateKey,
		"public-key":       publicKey,
		"private-key-file": privateKeyFile,
		"public-key-file":  publicKeyFile,
	}

	err = c.Replicate(repl)

	if ct.User.IsOwnerOfGroup(ct.FormattedArguments["group"]) {
		str, _, errPK := ct.Group.DisplayPubKeys("egress")
		if errPK != nil {
			err = errPK
			return
		}

		fmt.Printf("Here is the list of the group's egress public SSH keys (sb -> distant host):\n%s\n", str)
	}

	return
}

func (c *GroupGenerateEgressKey) PostExecute(repl models.ReplicationData) (err error) {
	return
}

func (c *GroupGenerateEgressKey) Replicate(repl models.ReplicationData) (err error) {

	err = helpers.WriteGroupPrivateKey(repl["private-key"], repl["private-key-file"], repl["files-owner"])
	if err != nil {
		return
	}

	err = helpers.WritePublicKey(repl["public-key"], repl["public-key-file"], repl["files-owner"])
	if err != nil {
		return
	}

	fmt.Println("The new egress SSH key was successfully generated")

	return
}
