package helpers

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// failingReader is an io.Reader that always fails. It stands in for a broken
// system entropy source so we can assert that random-string generation fails
// closed instead of emitting predictable or empty codes.
type failingReader struct{}

func (failingReader) Read(p []byte) (int, error) {
	return 0, errors.New("entropy source unavailable")
}

// TestGetRandomStrings_ShapeAndAlphabet exercises the production entry point
// (backed by crypto/rand) and checks the contract the TOTP scratch codes depend
// on: the right number of strings, each of the requested length, containing only
// decimal digits (so pam_google_authenticator can validate them).
func TestGetRandomStrings_ShapeAndAlphabet(t *testing.T) {
	const quantity, length = 5, 8

	got, err := GetRandomStrings(quantity, length)
	require.NoError(t, err, "generating codes from the real secure source should not fail")
	require.Len(t, got, quantity, "unexpected number of generated codes")

	for _, code := range got {
		require.Len(t, code, length, "code %q has the wrong length", code)
		for _, r := range code {
			require.True(t, r >= '0' && r <= '9', "code %q contains non-digit %q", code, r)
		}
	}
}

// TestGetRandomStrings_DeterministicFromReader proves the generator draws its
// randomness from the injected reader (not a hidden global) by feeding a fully
// deterministic byte stream and asserting the exact mapping to digits.
//
// crypto/rand.Int reads one byte per digit for an upper bound of 10 and masks it
// to the low nibble: a stream of 0x00 bytes maps every digit to '0', and a
// stream of 0x09 bytes maps every digit to '9' (0x09 & 0x0f = 9, which is < 10
// and therefore accepted without rejection).
func TestGetRandomStrings_DeterministicFromReader(t *testing.T) {
	zeros := getRandomStringsMust(t, bytes.Repeat([]byte{0x00}, 64), 2, 4)
	require.Equal(t, []string{"0000", "0000"}, zeros, "all-zero entropy should yield all '0' digits")

	nines := getRandomStringsMust(t, bytes.Repeat([]byte{0x09}, 64), 1, 5)
	require.Equal(t, []string{"99999"}, nines, "all-0x09 entropy should yield all '9' digits")
}

// TestGetRandomStrings_FailsClosed asserts that a read error from the entropy
// source aborts generation: the function returns an error and no partial output,
// so a caller can never enable 2FA with weak or empty recovery codes.
func TestGetRandomStrings_FailsClosed(t *testing.T) {
	got, err := getRandomStrings(failingReader{}, 5, 8)
	require.Error(t, err, "a failing entropy source must produce an error")
	require.Nil(t, got, "no codes should be returned when the entropy source fails")
}

// getRandomStringsMust is a test helper that runs the injectable core against a
// fixed byte stream and fails the test on any error.
func getRandomStringsMust(t *testing.T, stream []byte, quantity, length int) []string {
	t.Helper()
	got, err := getRandomStrings(bytes.NewReader(stream), quantity, length)
	require.NoError(t, err)
	return got
}
