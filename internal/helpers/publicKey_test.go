package helpers

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

type publicKeyTestStructure struct {
	i []byte
	o bool
}

type publicKeyTestStringStructure struct {
	i []byte
	o string
}

func TestEquals(t *testing.T) {

	pk, comment, options, rest, _ := ssh.ParseAuthorizedKey([]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFxu5J1fpfRBHe/2JKreeDGgJlMZji3n97fYm3KJt8Yv sb@localhost"))
	basePublicKey := &PublicKey{
		PublicKey: pk,
		Comment:   comment,
		Options:   options,
		Rest:      rest,
	}

	publicKeys := []publicKeyTestStructure{
		{
			i: []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFxu5J1fpfRBHe/2JKreeDGgJlMZji3n97fYm3KJt8Yv sb@localhost"),
			o: true,
		},
		{
			i: []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFxu5J1fpfRBHe/2JKreeDGgJlMZji3n97fYm3KJt8Yv"),
			o: true,
		},
		{
			i: []byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDDviAgF0HG8m+Fu93Ob0ZgNsboHED1FEi7/LhakVO55Jka0HVV/dKm1Dg+X0+pHlKNteRrLjBT9MA8+cjTdpxCYj/jWovlUcBqZupJTi+xvSGP4q2flZdKTUh+D/bhTwcrQ910BwAzR9iMGqny3m4F62GUTQayhNMHpkOl6wicdwuMN6BYLrcm5qy9tpq0IrBYBWPyi/7knbMNTEH0UqjIIAfrO5ZHlfRs6jJ5R9gMBuJ/C4PIslzIG8WCyzS5kKrSz14xBldcj63eHtoB1ZU6RuaN4OluJLzdFFkRfGsVWQ6sVhpIMAJRCddRD2oACeHzlZiA7k32ddUKuw4Y3v1B sb@localhost"),
			o: false,
		},
	}

	for _, test := range publicKeys {
		pk, _, _, _, _ := ssh.ParseAuthorizedKey(test.i)
		require.Equal(t, test.o, basePublicKey.Equals(pk), "The public key comparaison function returned a wrong value")
	}
}

func TestCheckStringPK(t *testing.T) {

	pkToTestStr := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFxu5J1fpfRBHe/2JKreeDGgJlMZji3n97fYm3KJt8Yv sb@localhost"
	pkToTest, comment, options, rest, _ := ssh.ParseAuthorizedKey([]byte(pkToTestStr))
	testedPublicKey := &PublicKey{
		PublicKey: pkToTest,
		Comment:   comment,
		Options:   options,
		Rest:      rest,
	}

	publicKeys := [][]byte{
		[]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFxu5J1fpfRBHe/2JKreeDGgJlMZji3n97fYm3KJt8Yv sb@localhost"),
		[]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFxu5J1fpfRBHe/2JKreeDGgJlMZji3n97fYm3KJt8Yv"),
		[]byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDDviAgF0HG8m+Fu93Ob0ZgNsboHED1FEi7/LhakVO55Jka0HVV/dKm1Dg+X0+pHlKNteRrLjBT9MA8+cjTdpxCYj/jWovlUcBqZupJTi+xvSGP4q2flZdKTUh+D/bhTwcrQ910BwAzR9iMGqny3m4F62GUTQayhNMHpkOl6wicdwuMN6BYLrcm5qy9tpq0IrBYBWPyi/7knbMNTEH0UqjIIAfrO5ZHlfRs6jJ5R9gMBuJ/C4PIslzIG8WCyzS5kKrSz14xBldcj63eHtoB1ZU6RuaN4OluJLzdFFkRfGsVWQ6sVhpIMAJRCddRD2oACeHzlZiA7k32ddUKuw4Y3v1B sb@localhost"),
	}

	existingPublicKeys := make([]PublicKey, 0, len(publicKeys))
	for _, test := range publicKeys {
		pk, comment, options, rest, _ := ssh.ParseAuthorizedKey(test)
		existingPublicKeys = append(existingPublicKeys, PublicKey{
			PublicKey: pk,
			Comment:   comment,
			Options:   options,
			Rest:      rest,
		})
	}

	_, err := CheckStringPK(pkToTestStr, existingPublicKeys)
	require.Error(t, err, fmt.Errorf("key already exists").Error(), "An error should have occurred as the public key already exists")

	_, err = CheckStringPK("INVALID_KEY", []PublicKey{})
	require.Error(t, err, fmt.Errorf("ssh: key not found").Error(), "An error should have occurred as the public key is invalid")

	pk, err := CheckStringPK(pkToTestStr, []PublicKey{})
	require.NoError(t, err, "An unexpected error occurred while checking public key")
	require.Equal(t, testedPublicKey, pk, "The public key return doesn't match the expected one")
}

func TestString(t *testing.T) {
	publicKeys := []publicKeyTestStringStructure{
		{
			i: []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFxu5J1fpfRBHe/2JKreeDGgJlMZji3n97fYm3KJt8Yv sb@localhost"),
			o: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFxu5J1fpfRBHe/2JKreeDGgJlMZji3n97fYm3KJt8Yv sb@localhost",
		},
		{
			i: []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFxu5J1fpfRBHe/2JKreeDGgJlMZji3n97fYm3KJt8Yv"),
			o: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFxu5J1fpfRBHe/2JKreeDGgJlMZji3n97fYm3KJt8Yv",
		},
		{
			i: []byte("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDDviAgF0HG8m+Fu93Ob0ZgNsboHED1FEi7/LhakVO55Jka0HVV/dKm1Dg+X0+pHlKNteRrLjBT9MA8+cjTdpxCYj/jWovlUcBqZupJTi+xvSGP4q2flZdKTUh+D/bhTwcrQ910BwAzR9iMGqny3m4F62GUTQayhNMHpkOl6wicdwuMN6BYLrcm5qy9tpq0IrBYBWPyi/7knbMNTEH0UqjIIAfrO5ZHlfRs6jJ5R9gMBuJ/C4PIslzIG8WCyzS5kKrSz14xBldcj63eHtoB1ZU6RuaN4OluJLzdFFkRfGsVWQ6sVhpIMAJRCddRD2oACeHzlZiA7k32ddUKuw4Y3v1B sb@localhost"),
			o: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDDviAgF0HG8m+Fu93Ob0ZgNsboHED1FEi7/LhakVO55Jka0HVV/dKm1Dg+X0+pHlKNteRrLjBT9MA8+cjTdpxCYj/jWovlUcBqZupJTi+xvSGP4q2flZdKTUh+D/bhTwcrQ910BwAzR9iMGqny3m4F62GUTQayhNMHpkOl6wicdwuMN6BYLrcm5qy9tpq0IrBYBWPyi/7knbMNTEH0UqjIIAfrO5ZHlfRs6jJ5R9gMBuJ/C4PIslzIG8WCyzS5kKrSz14xBldcj63eHtoB1ZU6RuaN4OluJLzdFFkRfGsVWQ6sVhpIMAJRCddRD2oACeHzlZiA7k32ddUKuw4Y3v1B sb@localhost",
		},
	}

	for _, test := range publicKeys {
		pk, comment, options, rest, _ := ssh.ParseAuthorizedKey(test.i)
		key := PublicKey{
			PublicKey: pk,
			Comment:   comment,
			Options:   options,
			Rest:      rest,
		}
		require.Equal(t, test.o, key.String(), "The String() method returned a wrong value")
	}
}
