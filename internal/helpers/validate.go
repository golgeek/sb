package helpers

import (
	"fmt"
	"regexp"
	"strings"
)

// systemNameRegexp constrains the Linux user and group names that sb hands to
// the privileged useradd/usermod/addgroup/deluser/groupmod tools.
//
// The pattern requires a name to start with a lowercase ASCII letter and to
// contain only lowercase letters, digits, underscores and hyphens, for a total
// length of 1 to 31 characters. Two properties matter for the security boundary:
//
//   - Because the first character must be a letter, a name can never begin with
//     '-'. A leading '-' is what makes ARGUMENT INJECTION possible: a name like
//     "-x" or "--shell" would otherwise be parsed by adduser/usermod as a flag
//     instead of as the operand sb intends.
//   - Because the body excludes ',', '/', '.', ':' and whitespace, a name can
//     neither split the comma-separated group lists that system.go builds (e.g.
//     usermod -G bg_x-o,bg_x-gk,...) nor disturb the "/etc/sudoers.d/<group>"
//     path and the sudoers glob assumptions that encode sb's privilege model.
//
// It is deliberately stricter than Linux's own NAME_REGEX (which also allows a
// leading underscore and a trailing '$'): sb never needs those forms, and every
// character class we drop is one fewer thing the security boundary must reason
// about.
var systemNameRegexp = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,30}$`)

// reservedGroupPrefix is the prefix sb reserves for the system groups and group
// users it creates internally (bg_GROUP, bg_GROUP-o, bg_GROUP-gk, bg_GROUP-aclk
// and the bg_GROUP login user). A user-supplied name must not collide with that
// namespace, so it may not start with this prefix.
const reservedGroupPrefix = "bg_"

// reservedSystemNames lists names that satisfy systemNameRegexp but that sb must
// still refuse to manage. "root" is rejected because operating on it through the
// sudoers-whitelisted tools would let a caller target the superuser account.
var reservedSystemNames = map[string]struct{}{
	"root": {},
}

// ValidateSystemName validates a user-supplied Linux user or group name before
// it is passed to any privileged system tool. It returns a descriptive error
// when name is empty, malformed, reserved, or sits in sb's reserved group
// namespace, and nil when the name is safe to use.
//
// This is the single choke point for the input-validation security boundary:
// every system.go helper that shells out to
// adduser/usermod/addgroup/deluser/groupmod runs its name arguments through this
// function first, so a malformed name fails closed before it can reach exec — on
// both the direct command path and the replication apply path.
func ValidateSystemName(name string) error {
	if name == "" {
		return fmt.Errorf("invalid name: must not be empty")
	}
	if !systemNameRegexp.MatchString(name) {
		return fmt.Errorf("invalid name %q: must match %s (a lowercase letter followed by up to 30 lowercase letters, digits, '_' or '-')", name, systemNameRegexp.String())
	}
	if strings.HasPrefix(name, reservedGroupPrefix) {
		return fmt.Errorf("invalid name %q: the %q prefix is reserved for sb-managed groups", name, reservedGroupPrefix)
	}
	if _, reserved := reservedSystemNames[name]; reserved {
		return fmt.Errorf("invalid name %q: this name is reserved and cannot be managed by sb", name)
	}
	return nil
}

// ValidateSystemNames validates several names at once, returning the first
// validation error encountered. It is a convenience wrapper around
// ValidateSystemName for the helpers that accept more than one name (for
// example a group name together with an account name).
func ValidateSystemNames(names ...string) error {
	for _, name := range names {
		if err := ValidateSystemName(name); err != nil {
			return err
		}
	}
	return nil
}
