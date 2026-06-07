package helpers

import (
	"crypto/aes"
	"crypto/cipher"
	cryptorand "crypto/rand"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

const testEncKey = "changemechangemechangemechangeme" // 32 bytes -> AES-256

// writeTempFile writes content to a fresh file in dir and returns its path.
func writeTempFile(t *testing.T, dir, name string, content []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, content, 0600))
	return p
}

// randomBytes returns n cryptographically random bytes for round-trip fixtures.
func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	_, err := io.ReadFull(cryptorand.Reader, b)
	require.NoError(t, err)
	return b
}

// TestEncryptDecryptRoundTrip exercises the authenticated format across the
// chunk-boundary edge cases (empty, sub-chunk, exact chunk, exact multiples and
// off-by-one), asserting the decrypted output is byte-identical to the input.
func TestEncryptDecryptRoundTrip(t *testing.T) {
	sizes := []int{
		0,
		1,
		1024,
		fileEncChunkSize - 1,
		fileEncChunkSize,
		fileEncChunkSize + 1,
		2 * fileEncChunkSize,
		2*fileEncChunkSize + 123,
	}

	for _, size := range sizes {
		t.Run(fileSizeName(size), func(t *testing.T) {
			dir := t.TempDir()
			plaintext := randomBytes(t, size)
			in := writeTempFile(t, dir, "in", plaintext)
			enc := filepath.Join(dir, "enc")
			dec := filepath.Join(dir, "dec")

			require.NoError(t, EncryptFile(in, enc, testEncKey))

			// The ciphertext must carry the authenticated-format magic and must not
			// equal the plaintext.
			encBytes, err := os.ReadFile(enc)
			require.NoError(t, err)
			require.Equal(t, fileEncMagic, string(encBytes[:len(fileEncMagic)]), "missing format magic")

			require.NoError(t, DecryptFile(enc, dec, testEncKey))
			decBytes, err := os.ReadFile(dec)
			require.NoError(t, err)
			require.Equal(t, plaintext, decBytes, "round-trip output differs from input")
		})
	}
}

// TestEncryptFileRejectsEmptyKey asserts encryption fails closed without a key.
func TestEncryptFileRejectsEmptyKey(t *testing.T) {
	dir := t.TempDir()
	in := writeTempFile(t, dir, "in", []byte("data"))
	require.Error(t, EncryptFile(in, filepath.Join(dir, "enc"), ""))
}

// TestDecryptWrongKeyFails asserts a different key cannot decrypt the file: the
// per-file HKDF subkey differs, so GCM authentication fails.
func TestDecryptWrongKeyFails(t *testing.T) {
	dir := t.TempDir()
	in := writeTempFile(t, dir, "in", randomBytes(t, 5000))
	enc := filepath.Join(dir, "enc")
	require.NoError(t, EncryptFile(in, enc, testEncKey))

	err := DecryptFile(enc, filepath.Join(dir, "dec"), "wrongkeywrongkeywrongkeywrongkey")
	require.Error(t, err, "decryption with the wrong key must fail")
}

// TestDecryptDetectsTampering asserts that flipping a single ciphertext byte is
// detected — the property the old unauthenticated AES-CTR format lacked.
func TestDecryptDetectsTampering(t *testing.T) {
	dir := t.TempDir()
	in := writeTempFile(t, dir, "in", randomBytes(t, 5000))
	enc := filepath.Join(dir, "enc")
	require.NoError(t, EncryptFile(in, enc, testEncKey))

	encBytes, err := os.ReadFile(enc)
	require.NoError(t, err)
	// Flip a byte inside the first chunk (well past the 27-byte header).
	encBytes[40] ^= 0xff
	tampered := writeTempFile(t, dir, "tampered", encBytes)

	require.Error(t, DecryptFile(tampered, filepath.Join(dir, "dec"), testEncKey),
		"tampered ciphertext must fail authentication")
}

// TestDecryptDetectsTruncation asserts that dropping bytes off the end of the
// ciphertext is detected, so a truncated backup or recording cannot be passed
// off as complete.
func TestDecryptDetectsTruncation(t *testing.T) {
	dir := t.TempDir()
	// Two full chunks plus a bit, so truncating the tail removes a whole chunk.
	in := writeTempFile(t, dir, "in", randomBytes(t, 2*fileEncChunkSize+10))
	enc := filepath.Join(dir, "enc")
	require.NoError(t, EncryptFile(in, enc, testEncKey))

	encBytes, err := os.ReadFile(enc)
	require.NoError(t, err)
	// Remove the final chunk entirely (its tag and the partial plaintext).
	truncated := writeTempFile(t, dir, "truncated", encBytes[:fileEncChunkSize+27+gcmTagSize])

	require.Error(t, DecryptFile(truncated, filepath.Join(dir, "dec"), testEncKey),
		"truncated ciphertext must be rejected")
}

// TestDecryptLegacyCTR asserts that files written by the old, unauthenticated
// AES-CTR format remain decryptable, so existing backups and recordings are not
// lost when upgrading.
func TestDecryptLegacyCTR(t *testing.T) {
	dir := t.TempDir()
	plaintext := randomBytes(t, 4000)
	legacy := filepath.Join(dir, "legacy.bin")
	writeLegacyCTRFile(t, legacy, testEncKey, plaintext)

	dec := filepath.Join(dir, "dec")
	require.NoError(t, DecryptFile(legacy, dec, testEncKey), "legacy file must still decrypt")

	decBytes, err := os.ReadFile(dec)
	require.NoError(t, err)
	require.Equal(t, plaintext, decBytes, "legacy decryption produced wrong output")
}

const gcmTagSize = 16

// writeLegacyCTRFile reproduces the historical EncryptFile format (AES-CTR with
// the IV appended at the end and no authentication tag) so the backward-compat
// decryption path can be tested.
func writeLegacyCTRFile(t *testing.T, path, key string, plaintext []byte) {
	t.Helper()
	block, err := aes.NewCipher([]byte(key))
	require.NoError(t, err)

	iv := randomBytes(t, block.BlockSize())
	ciphertext := make([]byte, len(plaintext), len(plaintext)+len(iv))
	cipher.NewCTR(block, iv).XORKeyStream(ciphertext, plaintext)

	require.NoError(t, os.WriteFile(path, append(ciphertext, iv...), 0600))
}

// fileSizeName gives subtests a readable name for a byte size.
func fileSizeName(size int) string {
	if size == 0 {
		return "empty"
	}
	return "size_" + strconv.Itoa(size)
}
