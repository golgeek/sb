package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strconv"

	"github.com/golgeek/sb/internal/commands"
	"github.com/golgeek/sb/internal/helpers"
	"github.com/golgeek/sb/internal/models"

	"golang.org/x/crypto/ssh"
)

// SelfDelIngressKey describes the selfDelIngresKey command
type SelfDelIngressKey struct{}

func init() {
	commands.RegisterCommand("self ingress-key delete", func() (c commands.Command, r models.Right, h helpers.Helper, args map[string]commands.Argument) {
		return new(SelfDelIngressKey), models.Public, helpers.Helper{
				Header:      "delete a public ingress key (you -> sb) from your account",
				Usage:       "self ingress-key delete [--public-key 'KEY']",
				Description: "delete a public ingress key (you -> sb) from your account",
				Aliases:     []string{"selfDelIngressKey"},
			}, map[string]commands.Argument{
				"public-key": {
					Required:    false,
					Description: "The ingress (you -> sb) public SSH key to delete from the sb (you will need to '\"double escape it\"'); if not present, you'll be prompted for it",
				},
			}
	})
}

// Checks checks whether or not the user can execute this method
func (c *SelfDelIngressKey) Checks(ct *commands.Context) error {
	// No specific rights needed but a sb account
	return nil
}

// Execute executes the command
func (c *SelfDelIngressKey) Execute(ct *commands.Context) (repl models.ReplicationData, cmdError error, err error) {

	str, keys, err := ct.User.DisplayPubKeys("ingress")
	if err != nil {
		return
	}

	if len(keys) < 2 {
		fmt.Println("Error: you cannot delete your last key")
		return
	}

	var publicKey string

	if ct.FormattedArguments["public-key"] == "" {
		// Interactive mode

		// We start by displaying the current keys (output of selfListIngressKeys)
		fmt.Printf("Here is the list of your current ingress public SSH keys (you -> sb):\n%s\n", str)

		// Then we request the new key to add
		for publicKey == "" {

			fmt.Print("Please enter the ID of the public key you want to delete: ")
			// Scan stdin to get the key to delete
			scanner := bufio.NewScanner(os.Stdin)
			scanner.Scan()
			ct.FormattedArguments["public-key"] = scanner.Text()

			publicKey, err = c.checkPublicKeyID(ct.FormattedArguments["public-key"], keys)
			if err != nil {
				fmt.Printf("Error: %s\n", err)
			}
		}
	} else {
		// Non-interactive mode

		// We try to validate the provided public-key
		publicKey, err = c.checkPublicKeyExists(ct.FormattedArguments["public-key"], keys)
		if err != nil {
			return
		}
	}

	repl = models.ReplicationData{
		"account":    ct.User.User.Username,
		"public-key": publicKey,
	}

	err = c.Replicate(repl)

	// We finally display the account's keys (output of selfListIngressKeys)
	str, _, _ = ct.User.DisplayPubKeys("ingress")
	fmt.Printf("Here is the list of your current ingress public SSH keys (you -> sb):\n%s\n", str)

	return
}

func (c *SelfDelIngressKey) PostExecute(repl models.ReplicationData) (err error) {
	return
}

func (c *SelfDelIngressKey) Replicate(repl models.ReplicationData) (err error) {

	// Load the user account
	user, err := models.LoadUser(repl["account"])
	if err != nil {
		return
	}

	// Convert the private key in our internal format to ease the comparisons
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(repl["public-key"]))
	if err != nil {
		return
	}

	publicKey := helpers.PublicKey{
		PublicKey: pk,
	}

	// Delete the key from the account
	err = user.DeletePubKey("ingress", publicKey)
	if err != nil {
		return
	}

	fmt.Println("Your key was successfully deleted.")

	return
}

func (c *SelfDelIngressKey) checkPublicKeyID(arg string, keys []helpers.PublicKey) (publicKey string, err error) {

	pkID, err := strconv.Atoi(arg)
	if err != nil || pkID > len(keys) || pkID < 1 {
		err = fmt.Errorf("input provided is not a digit on the allowed range [%d-%d]", 1, len(keys))
		return
	}

	publicKey = keys[pkID-1].String()

	return
}

// checkPublicKeyId checks if the provided public key is valid and not already available
func (c *SelfDelIngressKey) checkPublicKeyExists(arg string, keys []helpers.PublicKey) (publicKey string, err error) {

	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(arg))
	if err != nil {
		return
	}

	for _, key := range keys {
		if key.Equals(pk) {
			return key.String(), nil
		}
	}

	return "", fmt.Errorf("key not found")
}
