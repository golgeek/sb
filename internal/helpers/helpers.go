package helpers

import (
	"bytes"
	cryptorand "crypto/rand"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"strings"
)

// Helper describes the basic properties of a sb Helper type
type Helper struct {
	Header      string
	Usage       string
	Description string
	Aliases     []string
}

// ParseArguments parses the os.Args arguments
func ParseArguments(clArgs []string) (c string, ca []string, ba map[string]bool, rest []string, err error) {

	// We initialize our client with "ssh"
	c = "ssh"

	// Absolutely no arguments were provided (that's odd, we should at least have ourselves at $0)
	if len(clArgs) == 0 {
		return
	}

	// We start by dropping the script name
	clArgs = clArgs[1:]

	// Absolutely no arguments were provided
	if len(clArgs) == 0 {
		return
	}

	// We might have been called from two ways:
	// - directly, then arguments are: ["command", "--arg1", "val1, "--arg2", ...]
	// - through SSH client, then arguments are: ["-c", "command --arg1 val1 --arg2 ..."]
	if clArgs[0] != "-c" {
		// Nothing to do
	} else {
		if len(clArgs) == 1 {
			// No arguments were provided
			return
		}
		// We drop the "-c" and convert the arguments string to an array of arguments
		clArgs, err = ParseCommandLine(clArgs[1])
		if err != nil {
			return
		}
	}

	// We now have two different cases:
	// - just a basic slice of arguments (in case of direct call and SSH)
	// - something starting with ["mosh-server", "new", ..., "--", args...]
	if clArgs[0] == "mosh-server" {
		c = "mosh"

		// A mosh invocation must carry at least one token after "mosh-server"
		// (normally the "new" subsystem and its arguments). A bare "mosh-server"
		// is malformed: fail closed with a clear error instead of indexing
		// clArgs[1] past the end of the slice. This input arrives from the
		// SSH-forced command before any authorization, so a panic here was a
		// denial-of-service reachable by any caller.
		if len(clArgs) < 2 {
			err = fmt.Errorf("malformed mosh-server command line: missing arguments after \"mosh-server\"")
			return
		}

		// We drop the non-arguments part of the mosh command line.
		// Second argument should be "new", in case it is not, we check this case
		if clArgs[1] == "new" {
			clArgs = clArgs[2:]
		} else {
			clArgs = clArgs[1:]
		}

		// Mosh wraps around every argument with ' and escapes the ', we'll try and fix that
		for i := 0; i < len(clArgs); i++ {
			clArgs[i] = strings.TrimPrefix(strings.TrimSuffix(strings.ReplaceAll(clArgs[i], `\'`, "'"), "'"), "'")
		}

		// Let's build a flag parser for mosh options!
		moshFlagSet := flag.NewFlagSet("mosh", flag.ContinueOnError)

		// The flag package displays a nice message if an undeclared flag is found... but that's not what we want!
		// Let's redirect output to an abandoned buffer
		var buf bytes.Buffer
		moshFlagSet.SetOutput(&buf)

		// This flags are extracted from mosh-server man page
		iface := moshFlagSet.Bool("s", false, "bind to the local interface used for an incoming SSH connection, given in the SSH_CONNECTION environment variable (for multihomed hosts)")
		v := moshFlagSet.Bool("v", false, "Print some debugging information even after detaching.  More instances of this flag will result in more debugging information.")
		ip := moshFlagSet.String("i", "", "IP address of the local interface to bind (for multihomed hosts)")
		colors := moshFlagSet.String("c", "8", "Number of colors to advertise to applications through TERM (e.g. 8, 256)")
		lang := moshFlagSet.String("l", "", "Locale-related environment variable to try as part of a fallback environment, if the startup environment does not specify a character set of UTF-8.")
		moshFlagSet.String("p", "", "UDP port number or port-range to bind.  -p 0 will let the operating system pick an available UDP port.")

		// Let's parse our mosh-server arguments. We intentionally ignore the parse
		// error and proceed best-effort: undeclared mosh flags are expected here and
		// must not abort parsing (the remaining args are recovered via Args below).
		_ = moshFlagSet.Parse(clArgs)

		// And keep everything that was trailing for the next step
		clArgs = moshFlagSet.Args()

		// We push everything we parsed into our clientArguments slice
		// Everything except the ports to use, as they're coded in our configuration file
		ca = make([]string, 0)
		if *iface {
			ca = append(ca, "-s")
		}
		if *v {
			ca = append(ca, "-v")
		}
		if *ip != "" {
			ca = append(ca, "-i", *ip)
		}
		if *colors != "" {
			ca = append(ca, "-c", *colors)
		}
		if *lang != "" {
			ca = append(ca, "-l", *lang)
		}
	}

	clArgs = RegroupCommandArguments(clArgs)

	// Here, we will introduce the parsing of sb arguments
	sbFlagSet := flag.NewFlagSet("sb", flag.ContinueOnError)

	// The flag package displays a nice message if an undeclared flag is found... but that's not what we want!
	// Let's redirect output to an abandoned buffer
	var buf bytes.Buffer
	sbFlagSet.SetOutput(&buf)

	// Let's add our sb flags
	v := sbFlagSet.Bool("v", false, "Debug")
	i := sbFlagSet.Bool("i", false, "Interactive mode")
	d := sbFlagSet.Bool("d", false, "Daemon")

	// Let's parse our sb arguments. The parse error is intentionally ignored:
	// undeclared flags are expected (they belong to the wrapped client) and the
	// trailing args are recovered via Args below.
	_ = sbFlagSet.Parse(clArgs)

	// And keep everything that was trailing for the next step
	clArgs = sbFlagSet.Args()

	if *v || *i || *d {
		ba = make(map[string]bool)
	}
	if *v {
		ba["verbose"] = true
	}
	if *i {
		ba["interactive"] = true
	}
	if *d {
		ba["daemon"] = true
	}

	// We return all remaining arguments, that's what the user really wanted to give us
	rest = clArgs

	return
}

func RegroupCommandArguments(clArgs []string) (args []string) {

	// Nothing to regroup for an empty argument list, and indexing clArgs[0]
	// below would panic. This is reachable from ParseArguments when a mosh
	// command line consumes every token (e.g. "mosh-server new" with no trailing
	// command), so guard it rather than relying on every caller passing a
	// non-empty slice.
	if len(clArgs) == 0 {
		return clArgs
	}

	var j int
	firstArg := clArgs[0]
	for j = 1; j < len(clArgs); j++ {

		arg := clArgs[j]

		if strings.HasPrefix(arg, "-") {
			break
		}

		firstArg = fmt.Sprintf("%s %s", firstArg, arg)
	}
	args = append([]string{firstArg}, clArgs[j:]...)

	return
}

// ParseCommandLine parses the string passed to us by SSH to an array of args
func ParseCommandLine(cmd string) ([]string, error) {
	var args []string
	state := "start"
	current := ""
	quote := "\""
	escapeNext := true
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]

		if state == "quotes" {
			if string(c) != quote {
				current += string(c)
			} else {
				args = append(args, current)
				current = ""
				state = "start"
			}
			continue
		}

		if escapeNext {
			current += string(c)
			escapeNext = false
			continue
		}

		if c == '\\' {
			escapeNext = true
			continue
		}

		if c == '"' || c == '\'' {
			state = "quotes"
			quote = string(c)
			continue
		}

		if state == "arg" {
			if c == ' ' || c == '\t' {
				args = append(args, current)
				current = ""
				state = "start"
			} else {
				current += string(c)
			}
			continue
		}

		if c != ' ' && c != '\t' {
			state = "arg"
			current += string(c)
		}
	}

	if state == "quotes" {
		return []string{}, fmt.Errorf("unclosed quote in command line: %s", cmd)
	}

	if current != "" {
		args = append(args, current)
	}

	return args, nil
}

// GetRandomStrings returns `quantity` random strings, each `length` decimal
// digits long, drawn from a cryptographically secure random source
// (crypto/rand).
//
// This generator is security-sensitive: it produces the TOTP emergency/recovery
// "scratch" codes written to each user's ~/.google_authenticator file (see
// cmd/selfEnableTOTP.go and cmd/selfGenerateTOTPCodes.go). Those codes bypass
// the TOTP second factor, so they must be unpredictable. A previous version used
// math/rand seeded with time.Now().UnixNano(), which made the codes recoverable
// by an attacker able to approximate the generation time; crypto/rand removes
// that weakness entirely.
//
// The alphabet is deliberately restricted to decimal digits and the length is
// left to the caller because pam_google_authenticator validates scratch codes as
// plaintext 8-digit decimal numbers. Widening the alphabet (e.g. base32),
// changing the length, or hashing the stored codes would make the PAM module
// reject them and silently break 2FA recovery, so those hardenings are not
// applied here.
//
// It returns an error if the system's secure random source cannot be read.
// Callers MUST fail closed on that error and never fall back to a weaker source
// or emit empty/partial codes.
func GetRandomStrings(quantity int, length int) (rdm []string, err error) {
	return getRandomStrings(cryptorand.Reader, quantity, length)
}

// getRandomStrings is the testable core of GetRandomStrings. It reads its
// randomness from the provided reader so unit tests can inject a deterministic
// or deliberately failing source instead of the process-wide
// crypto/rand.Reader. Production callers go through GetRandomStrings, which wires
// in crypto/rand.Reader.
func getRandomStrings(reader io.Reader, quantity int, length int) (rdm []string, err error) {

	const digits = "0123456789"

	rdm = make([]string, 0, quantity)

	for i := 0; i < quantity; i++ {

		b := make([]byte, length)
		for j := range b {
			// cryptorand.Int returns a uniformly distributed value in
			// [0, len(digits)) with no modulo bias, reading entropy from
			// `reader`. Any read failure is propagated so the caller can fail
			// closed rather than emit a predictable or truncated code.
			n, ierr := cryptorand.Int(reader, big.NewInt(int64(len(digits))))
			if ierr != nil {
				return nil, fmt.Errorf("reading from secure random source: %w", ierr)
			}
			b[j] = digits[n.Int64()]
		}
		rdm = append(rdm, string(b))
	}

	return rdm, nil
}

func GetHostname() (hostname string, err error) {
	return os.Hostname()
}
