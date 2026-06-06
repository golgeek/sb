package completer

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// testCommands is a small, fixed command set used across the completer tests so
// the assertions do not depend on sb's real command registry.
func testCommands() []Command {
	return []Command{
		{Name: "account create", Description: "create an account", Args: []Arg{
			{Name: "username", Description: "the username"},
			{Name: "public-key", Description: "the\tpublic\nkey"},
		}},
		{Name: "account delete", Description: "delete an account"},
		{Name: "group create", Description: "create a group"},
	}
}

// TestSuggest is a characterization test for the completion logic. Each case
// asserts only the returned suggestions (sb-level behavior); nothing here
// references the prompt library, so the test stays valid across a swap of that
// library.
func TestSuggest(t *testing.T) {
	cmds := testCommands()

	t.Run("nothing typed yields no suggestions", func(t *testing.T) {
		require.Nil(t, Suggest(cmds, "", "", ""))
	})

	t.Run("command-name prefix suggests matching commands", func(t *testing.T) {
		got := Suggest(cmds, "account", "account", "account")
		require.Equal(t, []Suggestion{
			{Text: "account create", Description: "create an account"},
			{Text: "account delete", Description: "delete an account"},
		}, got)
	})

	t.Run("suggestions are sorted and prefix-filtered", func(t *testing.T) {
		// "group" only matches the single group command.
		got := Suggest(cmds, "group", "group", "group")
		require.Equal(t, []Suggestion{
			{Text: "group create", Description: "create a group"},
		}, got)
	})

	t.Run("after a command and a space, its args are suggested", func(t *testing.T) {
		got := Suggest(cmds, "account create ", "account create ", "")
		// Args are returned sorted by name, with tabs/newlines flattened.
		require.Equal(t, []Suggestion{
			{Text: "--public-key", Description: "the public key"},
			{Text: "--username", Description: "the username"},
		}, got)
	})

	t.Run("already-present args are not suggested again", func(t *testing.T) {
		got := Suggest(cmds, "account create --username bob ", "account create --username bob ", "")
		require.Equal(t, []Suggestion{
			{Text: "--public-key", Description: "the public key"},
		}, got)
	})

	t.Run("arg suggestions are filtered by the word being typed", func(t *testing.T) {
		got := Suggest(cmds, "account create --user", "account create --user", "--user")
		require.Equal(t, []Suggestion{
			{Text: "--username", Description: "the username"},
		}, got)
	})
}
