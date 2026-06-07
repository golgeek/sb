package helpers

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/hkdf"
)

// Authenticated, streaming file-encryption format.
//
// Backups and offloaded ttyrec recordings used to be encrypted with AES-CTR and
// no authentication tag: the ciphertext was malleable and any tampering went
// undetected, while the replication path already used authenticated AES-GCM.
// This unifies them on authenticated encryption. It uses AES-256-GCM with the
// STREAM construction (a random per-file nonce prefix, a per-chunk counter and
// an end-of-stream marker), which detects modification, truncation and
// reordering while still processing arbitrarily large files in bounded memory.
//
// On-disk layout:
//
//	magic    "SBE1"            4 bytes   identifies the authenticated format
//	salt     <random>         16 bytes   HKDF salt for per-file key derivation
//	prefix   <random>          7 bytes   per-file nonce prefix
//	chunk_0  GCM(plain_0)     ...         each chunk is plaintext + 16-byte tag
//	chunk_1  GCM(plain_1)     ...
//	...
//	chunk_n  GCM(plain_n)                 the final chunk carries the EOS marker
//
// Every chunk is sealed under a 12-byte nonce = prefix(7) || counter(4, BE) ||
// final(1), where final is 0x01 only for the last chunk. The encryptor never
// emits a final chunk of the full chunk size (a final chunk only ever comes from
// a short or empty read), so the decryptor can treat any full-size ciphertext
// chunk as non-final without ambiguity. The encryptor always writes at least one
// chunk — an empty final chunk for empty or exact-multiple inputs — so a missing
// final chunk is unambiguously a truncated stream.
const (
	fileEncMagic     = "SBE1"
	fileEncSaltSize  = 16
	fileEncPrefixLen = 7
	fileEncChunkSize = 64 * 1024 // plaintext bytes per chunk
	fileEncHKDFInfo  = "sb authenticated file encryption v1"
)

// deriveFileKey derives a 32-byte AES-256 key from the configured master key and
// a per-file random salt using HKDF-SHA256, so every encrypted file uses a
// distinct key even when the same master key encrypts many files.
func deriveFileKey(masterKey, salt []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, masterKey, salt, []byte(fileEncHKDFInfo))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("unable to derive file key: %w", err)
	}
	return key, nil
}

// fileEncNonce builds the 12-byte GCM nonce for a chunk from the per-file nonce
// prefix, the chunk counter and the end-of-stream flag.
func fileEncNonce(prefix []byte, counter uint32, final bool) []byte {
	nonce := make([]byte, 12)
	copy(nonce, prefix) // first fileEncPrefixLen bytes
	binary.BigEndian.PutUint32(nonce[fileEncPrefixLen:], counter)
	if final {
		nonce[11] = 1
	}
	return nonce
}

// newFileGCM derives the per-file key and returns an AES-256-GCM AEAD for it.
func newFileGCM(key string, salt []byte) (cipher.AEAD, error) {
	subKey, err := deriveFileKey([]byte(key), salt)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(subKey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// EncryptFile encrypts filepathIn into filepathOut using authenticated streaming
// encryption keyed by key. The output is integrity-protected: any later
// modification, truncation or reordering is detected at decryption time. It
// returns an error if the key is empty or the input cannot be read or written.
func EncryptFile(filepathIn, filepathOut, key string) (err error) {
	if key == "" {
		return errors.New("encryption key must not be empty")
	}

	in, err := os.Open(filepathIn)
	if err != nil {
		return err
	}
	defer in.Close()

	// Per-file salt and nonce prefix.
	salt := make([]byte, fileEncSaltSize)
	if _, err = io.ReadFull(cryptorand.Reader, salt); err != nil {
		return fmt.Errorf("unable to generate salt: %w", err)
	}
	prefix := make([]byte, fileEncPrefixLen)
	if _, err = io.ReadFull(cryptorand.Reader, prefix); err != nil {
		return fmt.Errorf("unable to generate nonce prefix: %w", err)
	}

	gcm, err := newFileGCM(key, salt)
	if err != nil {
		return err
	}

	out, err := os.OpenFile(filepathOut, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	// Report a close error if no earlier error occurred: buffered data must reach
	// disk for the file to be decryptable.
	defer func() {
		if cerr := out.Close(); err == nil {
			err = cerr
		}
	}()

	w := bufio.NewWriter(out)

	// Header: magic || salt || nonce prefix.
	for _, part := range [][]byte{[]byte(fileEncMagic), salt, prefix} {
		if _, err = w.Write(part); err != nil {
			return err
		}
	}

	plainBuf := make([]byte, fileEncChunkSize)
	sealed := make([]byte, 0, fileEncChunkSize+gcm.Overhead())
	var counter uint32

	for {
		n, readErr := io.ReadFull(in, plainBuf)
		final := readErr == io.EOF || readErr == io.ErrUnexpectedEOF
		if readErr != nil && !final {
			return fmt.Errorf("unable to read input: %w", readErr)
		}

		nonce := fileEncNonce(prefix, counter, final)
		sealed = gcm.Seal(sealed[:0], nonce, plainBuf[:n], nil)
		if _, err = w.Write(sealed); err != nil {
			return err
		}

		if final {
			break
		}

		counter++
		if counter == 0 {
			// The counter wrapped: the input exceeds 2^32 chunks (256 TB). Refuse
			// rather than risk reusing a (key, nonce) pair.
			return errors.New("input too large to encrypt safely")
		}
	}

	return w.Flush()
}

// DecryptFile decrypts filepathIn into filepathOut using key. It auto-detects the
// format from the file header: files in the authenticated format are verified
// chunk-by-chunk, while files in the legacy unauthenticated AES-CTR format are
// still readable so backups and recordings produced before the authenticated
// format are not lost.
func DecryptFile(filepathIn, filepathOut, key string) (err error) {
	in, err := os.Open(filepathIn)
	if err != nil {
		return err
	}
	defer in.Close()

	// Peek the magic to choose the format.
	magic := make([]byte, len(fileEncMagic))
	n, rerr := io.ReadFull(in, magic)
	if rerr != nil && rerr != io.EOF && rerr != io.ErrUnexpectedEOF {
		return rerr
	}

	if rerr == nil && string(magic[:n]) == fileEncMagic {
		return decryptAuthenticated(in, filepathOut, key)
	}

	// Anything else (including a file shorter than the magic) is treated as the
	// legacy AES-CTR format, which seeks back to the start itself.
	return decryptLegacyCTR(in, filepathOut, key)
}

// decryptAuthenticated reads the authenticated format from in, whose read cursor
// is positioned immediately after the magic. It verifies and writes each chunk,
// failing closed on any authentication, truncation or reordering error.
func decryptAuthenticated(in *os.File, filepathOut, key string) (err error) {
	if key == "" {
		return errors.New("decryption key must not be empty")
	}

	salt := make([]byte, fileEncSaltSize)
	if _, err = io.ReadFull(in, salt); err != nil {
		return fmt.Errorf("unable to read salt: %w", err)
	}
	prefix := make([]byte, fileEncPrefixLen)
	if _, err = io.ReadFull(in, prefix); err != nil {
		return fmt.Errorf("unable to read nonce prefix: %w", err)
	}

	gcm, err := newFileGCM(key, salt)
	if err != nil {
		return err
	}

	out, err := os.OpenFile(filepathOut, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := out.Close(); err == nil {
			err = cerr
		}
	}()
	w := bufio.NewWriter(out)

	encBuf := make([]byte, fileEncChunkSize+gcm.Overhead())
	plain := make([]byte, 0, fileEncChunkSize)
	var counter uint32

	for {
		n, readErr := io.ReadFull(in, encBuf)
		final := readErr == io.EOF || readErr == io.ErrUnexpectedEOF
		if readErr != nil && !final {
			return fmt.Errorf("unable to read ciphertext: %w", readErr)
		}
		if final && n == 0 {
			// The stream ended after a full non-final chunk with no final chunk:
			// the ciphertext was truncated.
			return errors.New("ciphertext is truncated: missing final chunk")
		}
		if n < gcm.Overhead() {
			return errors.New("ciphertext chunk is too short")
		}

		nonce := fileEncNonce(prefix, counter, final)
		plain, err = gcm.Open(plain[:0], nonce, encBuf[:n], nil)
		if err != nil {
			return fmt.Errorf("ciphertext authentication failed at chunk %d: %w", counter, err)
		}
		if _, err = w.Write(plain); err != nil {
			return err
		}

		if final {
			break
		}
		counter++
	}

	return w.Flush()
}

// decryptLegacyCTR decrypts a file written by the old, unauthenticated AES-CTR
// format (a 16-byte IV appended at the end). It is retained read-only so backups
// and recordings produced before the authenticated format are still
// recoverable; new data is never written in this format and it provides no
// integrity guarantee. The caller's read cursor is ignored — this function reads
// from the start of in.
func decryptLegacyCTR(in *os.File, filepathOut, key string) (err error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return err
	}

	fi, err := in.Stat()
	if err != nil {
		return err
	}

	iv := make([]byte, block.BlockSize())
	msgLen := fi.Size() - int64(len(iv))
	if msgLen < 0 {
		return errors.New("legacy ciphertext is too short to contain an IV")
	}
	if _, err = in.ReadAt(iv, msgLen); err != nil {
		return err
	}

	out, err := os.OpenFile(filepathOut, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := out.Close(); err == nil {
			err = cerr
		}
	}()
	w := bufio.NewWriter(out)

	// Read the ciphertext body from the start of the file.
	if _, err = in.Seek(0, io.SeekStart); err != nil {
		return err
	}

	buf := make([]byte, 1024)
	stream := cipher.NewCTR(block, iv)
	for {
		n, rerr := in.Read(buf)
		if n > 0 {
			// The trailing IV bytes are not part of the original message.
			if int64(n) > msgLen {
				n = int(msgLen)
			}
			msgLen -= int64(n)
			stream.XORKeyStream(buf[:n], buf[:n])
			if _, werr := w.Write(buf[:n]); werr != nil {
				return werr
			}
		}
		if rerr == io.EOF || msgLen <= 0 {
			break
		}
		if rerr != nil {
			return rerr
		}
	}

	return w.Flush()
}
