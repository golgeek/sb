package cmd

import (
	osuser "os/user"
	"testing"

	"github.com/golgeek/sb/internal/commands"
	"github.com/golgeek/sb/internal/models"

	"github.com/stretchr/testify/require"
)

// replicationNameContract is the persisted cross-instance command-name
// contract. A command's canonical name is written into the replication outbox
// as the action identifier, and historical outbox entries may carry the
// camelCase alias the user typed instead — so every canonical name AND every
// alias listed here must resolve through the flat registry forever. Removing
// or renaming an entry breaks replication apply on peers that still hold old
// outbox entries.
//
// This table is intentionally a literal copy of the registered names, not a
// dump of the registry: if a registration changes, this test must fail.
var replicationNameContract = map[string][]string{
	"account create":                     {"createAccount"},
	"account delete":                     {"delAccount"},
	"backup":                             nil,
	"daemon":                             nil,
	"group access add":                   {"groupAddAccess"},
	"group access remove":                {"groupDelAccess"},
	"group accesses list":                {"groupListAccesses"},
	"group acl-keeper add":               {"groupAddACLKeeper"},
	"group acl-keeper remove":            {"groupDelACLKeeper"},
	"group create":                       {"createGroup"},
	"group delete":                       {"delGroup"},
	"group egress-key generate":          {"groupGenerateEgressKey"},
	"group gate-keeper add":              {"groupAddGateKeeper"},
	"group gate-keeper remove":           {"groupDelGateKeeper"},
	"group info":                         {"groupInfo"},
	"group member add":                   {"groupAddMember"},
	"group member remove":                {"groupDelMember"},
	"group owner add":                    {"groupAddOwner"},
	"group owner remove":                 {"groupDelOwner"},
	"groups list":                        {"groupList"},
	"help":                               nil,
	"info":                               nil,
	"interactive":                        nil,
	"restore":                            nil,
	"scp":                                nil,
	"self access add":                    {"selfAddAccess"},
	"self access remove":                 {"selfDelAccess"},
	"self accesses list":                 {"selfListAccesses"},
	"self egress-key generate":           {"selfGenerateEgressKey"},
	"self egress-keys list":              {"selfListEgressKeys"},
	"self hostkey forget":                nil,
	"self ingress-key add":               {"selfAddIngressKey"},
	"self ingress-key delete":            {"selfDelIngressKey"},
	"self ingress-keys list":             {"selfListIngressKeys"},
	"self session gif":                   {"selfGetSessionAsGif"},
	"self session replay":                {"selfPlaySession"},
	"self sessions list":                 {"selfListSessions"},
	"self totp disable":                  {"selfDisableTOTP"},
	"self totp emergency-codes generate": {"selfGenerateTOTPCodes"},
	"self totp enable":                   {"selfEnableTOTP"},
	"setup":                              nil,
	"ttyrec":                             nil,
}

// TestReplicationNameCompatibility asserts every canonical name and alias of
// the contract resolves through the registry lookup used by the
// replication-apply path (cmd/daemon.go). This is the §-critical guarantee
// that lets any peer apply any outbox entry ever persisted, whichever form
// (canonical or alias) it carries.
func TestReplicationNameCompatibility(t *testing.T) {

	for canonical, aliases := range replicationNameContract {
		spec, err := commands.GetSpec(canonical)
		require.NoError(t, err, "canonical name %q must resolve", canonical)
		require.Equal(t, canonical, spec.Name)

		for _, alias := range aliases {
			byAlias, err := commands.GetSpec(alias)
			require.NoError(t, err, "alias %q (of %q) must resolve", alias, canonical)
			require.Same(t, spec, byAlias, "alias %q must resolve to the same spec as %q", alias, canonical)
		}
	}
}

// TestRegistryHasNoUnlistedCommands asserts the inverse direction: every
// registered command is part of the contract table above, so adding a command
// forces a deliberate decision about its replication identity.
func TestRegistryHasNoUnlistedCommands(t *testing.T) {

	registered := commands.Specs()
	require.Len(t, registered, len(replicationNameContract),
		"command registered without updating the replication name contract table")

	for _, spec := range registered {
		aliases, ok := replicationNameContract[spec.Name]
		require.True(t, ok, "registered command %q is missing from the contract table", spec.Name)
		require.ElementsMatch(t, aliases, spec.Aliases,
			"aliases of %q diverged from the contract table", spec.Name)
	}
}

// TestProductionTreeExcludesTrustedCommands builds the real cobra tree from
// the production registry and asserts the trusted commands are absent from
// it: not invocable, not completable, not suggestible. They remain reachable
// only through the flat registry used by the front-end and the
// replication-apply path.
func TestProductionTreeExcludesTrustedCommands(t *testing.T) {

	user := &models.User{User: &osuser.User{Username: "tester", Uid: "1000"}}
	root := BuildRootCommand(&models.Log{}, user)

	present := make(map[string]bool)
	for _, child := range root.Commands() {
		present[child.Name()] = true
	}

	for _, trusted := range []string{"interactive", "ttyrec", "daemon"} {
		require.False(t, present[trusted], "trusted command %q must not appear in the cobra tree", trusted)
	}

	// Sanity check the inverse: ordinary top-level words are present.
	for _, word := range []string{"self", "group", "groups", "account", "info", "scp", "help"} {
		require.True(t, present[word], "expected top-level command word %q in the tree", word)
	}
}
