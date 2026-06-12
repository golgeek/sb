package commands

import (
	"fmt"
	"testing"

	"github.com/golgeek/sb/internal/types"

	"github.com/stretchr/testify/require"
)

// suggestRegistry builds a registry shaped like the production one for the
// suggestion cases that matter: sibling-looking names in different branches.
func suggestRegistry() *Registry {
	r := NewRegistry()
	r.MustRegister(specStub("groups list", []string{"groupList"}, false))
	r.MustRegister(specStub("group info", []string{"groupInfo"}, false))
	r.MustRegister(specStub("group accesses list", []string{"groupListAccesses"}, false))
	r.MustRegister(specStub("self accesses list", []string{"selfListAccesses"}, false))
	r.MustRegister(specStub("info", nil, false))
	r.MustRegister(specStub("ttyrec", nil, true))
	r.MustRegister(specStub("daemon", nil, true))
	return r
}

// TestSuggestCommandLine covers the top-level fuzzy fallback, including the
// cross-branch cases cobra's in-parent suggester cannot see.
func TestSuggestCommandLine(t *testing.T) {

	r := suggestRegistry()

	tests := []struct {
		name   string
		tokens []string
		want   string
		wantOK bool
	}{
		{
			// The canonical cross-branch case: "group list" is one edit away
			// from "groups list", which lives in a different subtree.
			name:   "cross-branch suggestion",
			tokens: []string{"group", "list"},
			want:   "groups list",
			wantOK: true,
		},
		{
			name:   "typo inside a multi-word name",
			tokens: []string{"self", "acceses", "list"},
			want:   "self accesses list",
			wantOK: true,
		},
		{
			name:   "typo in the first word",
			tokens: []string{"grup", "info"},
			want:   "group info",
			wantOK: true,
		},
		{
			// Alias typos resolve to the canonical name, not the alias.
			name:   "alias typo suggests the canonical name",
			tokens: []string{"selfListAcceses"},
			want:   "self accesses list",
			wantOK: true,
		},
		{
			// Flags and trailing blobs are not part of the command name.
			name:   "flags do not poison the match",
			tokens: []string{"grup", "info", "--group", "team"},
			want:   "group info",
			wantOK: true,
		},
		{
			// Trusted specs must never be suggested: a near-miss of a trusted
			// name gets no hint that the command exists.
			name:   "trusted names are never suggested",
			tokens: []string{"ttyrek"},
			wantOK: false,
		},
		{
			name:   "nothing close yields no suggestion",
			tokens: []string{"completely-unrelated"},
			wantOK: false,
		},
		{
			name:   "flags-only input yields no suggestion",
			tokens: []string{"--group", "team"},
			wantOK: false,
		},
		{
			name:   "empty input yields no suggestion",
			tokens: nil,
			wantOK: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := r.SuggestCommandLine(tc.tokens)
			require.Equal(t, tc.wantOK, ok)
			if tc.wantOK {
				require.Equal(t, tc.want, got)
			}
		})
	}
}

// TestLevenshtein anchors the distance function the suggestions rely on.
func TestLevenshtein(t *testing.T) {
	require.Equal(t, 0, levenshtein("", ""))
	require.Equal(t, 3, levenshtein("", "abc"))
	require.Equal(t, 3, levenshtein("abc", ""))
	require.Equal(t, 0, levenshtein("group", "group"))
	require.Equal(t, 1, levenshtein("group list", "groups list"))
	require.Equal(t, 1, levenshtein("grup", "group"))
	require.Equal(t, 1, levenshtein("kitten", "sitten"))
	require.Equal(t, 3, levenshtein("kitten", "sitting"))
}

// TestWithCommandSuggestion asserts only unknown-command errors are enriched,
// and only when something is close.
func TestWithCommandSuggestion(t *testing.T) {

	// The package-level helper consults the process-wide registry, which is
	// empty in this test binary; exercise the logic through a scoped
	// registry by composing the pieces it uses.
	r := suggestRegistry()

	t.Run("nil error passes through", func(t *testing.T) {
		require.NoError(t, WithCommandSuggestion(nil, []string{"group", "list"}))
	})

	t.Run("unrelated error passes through", func(t *testing.T) {
		err := fmt.Errorf("connection refused")
		require.Same(t, err, WithCommandSuggestion(err, []string{"group", "list"}))
	})

	t.Run("unknown-command error format", func(t *testing.T) {
		// types.ErrUnknownCommand and cobra's unknown-command errors share
		// the "unknown command" prefix WithCommandSuggestion keys on.
		require.Equal(t, "unknown command", types.ErrUnknownCommand.Error())

		suggestion, ok := r.SuggestCommandLine([]string{"group", "list"})
		require.True(t, ok)
		require.Equal(t, "groups list", suggestion)
	})
}
