package helpers

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"

	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/ssh"
)

//
// WARNING: the content of this file is straight out of the proposition to add MarshalPrivateKey() and MarshalPrivateKeyWithPassphrase()
// in the golang.org/x/crypto/ssh package here: https://go-review.googlesource.com/c/crypto/+/218620/
// Once the PR is merged in the package, this file will be dropped and helpers.MarshalPrivateKey() will become ssh.MarshalPrivateKey().
//

// MarshalPrivateKey returns a PEM block with the private key serialized in the
// OpenSSH format.
func MarshalPrivateKey(key crypto.PrivateKey, comment string) (*pem.Block, error) {
	return marshalOpenSSHPrivateKey(key, comment, unencryptedOpenSSHMarshaler)
}

// MarshalPrivateKeyWithPassphrase returns an encrypted PEM block with the
// private key serialized in the OpenSSH format.
func MarshalPrivateKeyWithPassphrase(key crypto.PrivateKey, comment string, passphrase []byte) (*pem.Block, error) {
	return marshalOpenSSHPrivateKey(key, comment, passphraseProtectedOpenSSHMarshaler(passphrase))
}

func randomSalt(size int) ([]byte, error) {
	salt := make([]byte, size)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

func unencryptedOpenSSHMarshaler(privKeyBlock []byte) ([]byte, string, string, string, error) {
	key := generateOpenSSHPadding(privKeyBlock, 8)
	return key, "none", "none", "", nil
}

func passphraseProtectedOpenSSHMarshaler(passphrase []byte) openSSHEncryptFunc {
	return func(PrivKeyBlock []byte) ([]byte, string, string, string, error) {
		salt, err := randomSalt(16)
		if err != nil {
			return nil, "", "", "", err
		}

		opts := struct {
			Salt   []byte
			Rounds uint32
		}{salt, 16}

		// Derive key to encrypt the private key block.
		k, err := BcryptPbkdfKey(passphrase, salt, int(opts.Rounds), 32+aes.BlockSize)
		if err != nil {
			return nil, "", "", "", err
		}

		// Add padding matching the block size of AES.
		keyBlock := generateOpenSSHPadding(PrivKeyBlock, aes.BlockSize)

		// Encrypt the private key using the derived secret.
		dst := make([]byte, len(keyBlock))
		iv := k[32 : 32+aes.BlockSize]
		block, err := aes.NewCipher(k[:32])
		if err != nil {
			return nil, "", "", "", err
		}

		stream := cipher.NewCTR(block, iv)
		stream.XORKeyStream(dst, keyBlock)

		return dst, "aes256-ctr", "bcrypt", string(ssh.Marshal(opts)), nil
	}
}

func marshalOpenSSHPrivateKey(key crypto.PrivateKey, comment string, encrypt openSSHEncryptFunc) (*pem.Block, error) {
	var w struct {
		CipherName   string
		KdfName      string
		KdfOpts      string
		NumKeys      uint32
		PubKey       []byte
		PrivKeyBlock []byte
	}
	var pk1 struct {
		Check1  uint32
		Check2  uint32
		Keytype string
		Rest    []byte `ssh:"rest"`
	}

	// Random check bytes.
	var check uint32
	if err := binary.Read(rand.Reader, binary.BigEndian, &check); err != nil {
		return nil, err
	}

	pk1.Check1 = check
	pk1.Check2 = check
	w.NumKeys = 1

	// Use a []byte directly on ed25519 keys.
	if k, ok := key.(*ed25519.PrivateKey); ok {
		key = *k
	}

	switch k := key.(type) {
	case *rsa.PrivateKey:
		E := new(big.Int).SetInt64(int64(k.E))
		// Marshal public key:
		// E and N are in reversed order in the public and private key.
		pubKey := struct {
			KeyType string
			E       *big.Int
			N       *big.Int
		}{
			ssh.KeyAlgoRSA,
			E, k.N,
		}
		w.PubKey = ssh.Marshal(pubKey)

		// Marshal private key.
		key := struct {
			N       *big.Int
			E       *big.Int
			D       *big.Int
			Iqmp    *big.Int
			P       *big.Int
			Q       *big.Int
			Comment string
		}{
			k.N, E,
			k.D, k.Precomputed.Qinv, k.Primes[0], k.Primes[1],
			comment,
		}
		pk1.Keytype = ssh.KeyAlgoRSA
		pk1.Rest = ssh.Marshal(key)
	case ed25519.PrivateKey:
		pub := make([]byte, ed25519.PublicKeySize)
		priv := make([]byte, ed25519.PrivateKeySize)
		copy(pub, k[ed25519.PublicKeySize:])
		copy(priv, k)

		// Marshal public key.
		pubKey := struct {
			KeyType string
			Pub     []byte
		}{
			ssh.KeyAlgoED25519, pub,
		}
		w.PubKey = ssh.Marshal(pubKey)

		// Marshal private key.
		key := struct {
			Pub     []byte
			Priv    []byte
			Comment string
		}{
			pub, priv,
			comment,
		}
		pk1.Keytype = ssh.KeyAlgoED25519
		pk1.Rest = ssh.Marshal(key)
	case *ecdsa.PrivateKey:
		var curve, keyType string
		switch name := k.Curve.Params().Name; name {
		case "P-256":
			curve = "nistp256"
			keyType = ssh.KeyAlgoECDSA256
		case "P-384":
			curve = "nistp384"
			keyType = ssh.KeyAlgoECDSA384
		case "P-521":
			curve = "nistp521"
			keyType = ssh.KeyAlgoECDSA521
		default:
			return nil, errors.New("ssh: unhandled elliptic curve " + name)
		}

		pub := elliptic.Marshal(k.Curve, k.X, k.Y)

		// Marshal public key.
		pubKey := struct {
			KeyType string
			Curve   string
			Pub     []byte
		}{
			keyType, curve, pub,
		}
		w.PubKey = ssh.Marshal(pubKey)

		// Marshal private key.
		key := struct {
			Curve   string
			Pub     []byte
			D       *big.Int
			Comment string
		}{
			curve, pub, k.D,
			comment,
		}
		pk1.Keytype = keyType
		pk1.Rest = ssh.Marshal(key)
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %T", k)
	}

	var err error
	// Add padding and encrypt the key if necessary.
	w.PrivKeyBlock, w.CipherName, w.KdfName, w.KdfOpts, err = encrypt(ssh.Marshal(pk1))
	if err != nil {
		return nil, err
	}

	b := ssh.Marshal(w)
	block := &pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: append([]byte(sshMagic), b...),
	}
	return block, nil
}

func generateOpenSSHPadding(block []byte, blockSize int) []byte {
	for i, l := 0, len(block); (l+i)%blockSize != 0; i++ {
		block = append(block, byte(i+1))
	}
	return block
}

const sshMagic = "openssh-key-v1\x00"

type openSSHEncryptFunc func(PrivKeyBlock []byte) (ProtectedKeyBlock []byte, cipherName, kdfName, kdfOptions string, err error)

const bcryptPbkdfBlockSize = 32

// Bcrypt_pbkdfKey derives a key from the password, salt and rounds count, returning a
// []byte of length keyLen that can be used as cryptographic key.
func BcryptPbkdfKey(password, salt []byte, rounds, keyLen int) ([]byte, error) {
	if rounds < 1 {
		return nil, errors.New("bcrypt_pbkdf: number of rounds is too small")
	}
	if len(password) == 0 {
		return nil, errors.New("bcrypt_pbkdf: empty password")
	}
	if len(salt) == 0 || len(salt) > 1<<20 {
		return nil, errors.New("bcrypt_pbkdf: bad salt length")
	}
	if keyLen > 1024 {
		return nil, errors.New("bcrypt_pbkdf: keyLen is too large")
	}

	numBlocks := (keyLen + bcryptPbkdfBlockSize - 1) / bcryptPbkdfBlockSize
	key := make([]byte, numBlocks*bcryptPbkdfBlockSize)

	h := sha512.New()
	h.Write(password)
	shapass := h.Sum(nil)

	shasalt := make([]byte, 0, sha512.Size)
	cnt, tmp := make([]byte, 4), make([]byte, bcryptPbkdfBlockSize)
	for block := 1; block <= numBlocks; block++ {
		h.Reset()
		h.Write(salt)
		cnt[0] = byte(block >> 24)
		cnt[1] = byte(block >> 16)
		cnt[2] = byte(block >> 8)
		cnt[3] = byte(block)
		h.Write(cnt)
		bcryptHash(tmp, shapass, h.Sum(shasalt))

		out := make([]byte, bcryptPbkdfBlockSize)
		copy(out, tmp)
		for i := 2; i <= rounds; i++ {
			h.Reset()
			h.Write(tmp)
			bcryptHash(tmp, shapass, h.Sum(shasalt))
			for j := 0; j < len(out); j++ {
				out[j] ^= tmp[j]
			}
		}

		for i, v := range out {
			key[i*numBlocks+(block-1)] = v
		}
	}
	return key[:keyLen], nil
}

var bcryptPbkdfMagic = []byte("OxychromaticBlowfishSwatDynamite")

func bcryptHash(out, shapass, shasalt []byte) {
	c, err := blowfish.NewSaltedCipher(shapass, shasalt)
	if err != nil {
		panic(err)
	}
	for i := 0; i < 64; i++ {
		blowfish.ExpandKey(shasalt, c)
		blowfish.ExpandKey(shapass, c)
	}
	copy(out, bcryptPbkdfMagic)
	for i := 0; i < 32; i += 8 {
		for j := 0; j < 64; j++ {
			c.Encrypt(out[i:i+8], out[i:i+8])
		}
	}
	// Swap bytes due to different endianness.
	for i := 0; i < 32; i += 4 {
		out[i+3], out[i+2], out[i+1], out[i] = out[i], out[i+1], out[i+2], out[i+3]
	}
}
