package helpers

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
)

// ValidateMOSHArguments validates the normalized options produced by ParseArguments.
// No child command, option terminator, environment assignment outside locale
// settings, or user-selected port may enter this slice.
func ValidateMOSHArguments(args []string) error {
	for i := 0; i < len(args); i++ {
		option := args[i]
		switch option {
		case "-s", "-v":
			continue
		case "-i", "-c", "-l":
			if i+1 == len(args) {
				return fmt.Errorf("missing value for mosh option %s", option)
			}
			i++
			value := args[i]
			switch option {
			case "-i":
				if _, err := netip.ParseAddr(value); err != nil {
					return fmt.Errorf("invalid mosh bind address")
				}
			case "-c":
				colors, err := strconv.ParseInt(value, 10, 32)
				if err != nil || colors < 0 {
					return fmt.Errorf("invalid mosh color count")
				}
			case "-l":
				name, locale, ok := strings.Cut(value, "=")
				if !ok || locale == "" || strings.ContainsAny(value, "\x00\r\n") {
					return fmt.Errorf("invalid mosh locale assignment")
				}
				switch name {
				case "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "LC_NUMERIC", "LC_TIME", "LC_COLLATE", "LC_MONETARY", "LC_MESSAGES", "LC_PAPER", "LC_NAME", "LC_ADDRESS", "LC_TELEPHONE", "LC_MEASUREMENT", "LC_IDENTIFICATION":
				default:
					return fmt.Errorf("unsupported mosh locale variable %q", name)
				}
			}
		default:
			return fmt.Errorf("unsupported mosh option %q", option)
		}
	}
	return nil
}

// BuildMOSHCommand returns a validated prefix ending at the only option
// terminator. Callers append their fixed child executable and its arguments.
func BuildMOSHCommand(args []string, ports string) ([]string, error) {
	if err := ValidateMOSHArguments(args); err != nil {
		return nil, err
	}
	rangeParts := strings.Split(ports, ":")
	if len(rangeParts) > 2 {
		return nil, fmt.Errorf("invalid configured mosh port range")
	}
	previous := int64(0)
	for _, part := range rangeParts {
		port, err := strconv.ParseInt(part, 10, 32)
		if err != nil || port < 1 || port > 65535 || port < previous {
			return nil, fmt.Errorf("invalid configured mosh port range")
		}
		previous = port
	}
	path, err := exec.LookPath("mosh-server")
	if err != nil {
		return nil, err
	}
	command := append([]string{path, "new"}, args...)
	return append(command, "-p", ports, "--"), nil
}
