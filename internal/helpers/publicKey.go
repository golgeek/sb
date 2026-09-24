package helpers

import (
	"fmt"
	"strings"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/crypto/ssh"
)

// PublicKey describes the basic properties of a sb PublicKey type
type PublicKey struct {
	PublicKey ssh.PublicKey
	Comment   string
	Options   []string
	Rest      []byte
}

func (k *PublicKey) String() string {

	key := ssh.MarshalAuthorizedKey(k.PublicKey)

	// Remove the \n character
	key = key[:len(key)-1]
	keystr := strings.TrimSuffix(string(key), "\n")

	// ParseAuthorizedKey preserves each option's authorized_keys quoting.
	// Keep that syntax and order intact: dropping options silently removes
	// restrictions, and quoting them again would change their meaning.
	if len(k.Options) > 0 {
		keystr = strings.Join(k.Options, ",") + " " + keystr
	}

	// We want to add a comment to the key
	if k.Comment != "" {
		// Append the comment
		keystr = fmt.Sprintf("%s %s", keystr, k.Comment)
	}

	return keystr
}

// Equals returns true if the helpers.PublicKey matches the ssh.PublicKey
func (k *PublicKey) Equals(key ssh.PublicKey) bool {

	marshaledKey := ssh.MarshalAuthorizedKey(k.PublicKey)
	marshaledKey2 := ssh.MarshalAuthorizedKey(key)

	return cmp.Equal(marshaledKey, marshaledKey2)
}

// CheckStringPK checks if the provided public key is valid and not already present in the optional keys slice
func CheckStringPK(arg string, keys []PublicKey) (pk *PublicKey, err error) {

	publicKey, comment, options, rest, err := ssh.ParseAuthorizedKey([]byte(arg))
	if err != nil {
		return
	}

	for _, key := range keys {
		if key.Equals(publicKey) {
			err = fmt.Errorf("key already exists")
			return
		}
	}

	pk = &PublicKey{
		PublicKey: publicKey,
		Comment:   comment,
		Options:   options,
		Rest:      rest,
	}

	return
}
