package commands

import (
	"fmt"
	"strings"
)

// suggestionMaxDistance is the maximum Levenshtein distance for a candidate
// to be offered as a "did you mean" suggestion. Two matches cobra's default
// for in-tree suggestions, so the top-level fallback feels consistent.
const suggestionMaxDistance = 2

// SuggestCommandLine fuzzy-matches a typed command line against every
// non-trusted canonical name and alias, returning the canonical name of the
// closest match within the suggestion distance. It exists for the typo cases
// cobra's in-tree suggester cannot see: cobra only compares one path segment
// against the children of one node, while this matcher compares the leading
// words of the typed line against full multi-word names across all branches
// ("group list" → "groups list", "self acceses list" → "self accesses list").
//
// Only the leading non-flag tokens participate: flags and a trailing remote
// command are not part of the command name. Trusted specs are never
// suggested — they must stay invisible to users. The match is
// case-insensitive; ties resolve to the lexicographically smallest canonical
// name so the result is deterministic. The boolean is false when nothing is
// close enough.
func (r *Registry) SuggestCommandLine(tokens []string) (string, bool) {

	// Cut the typed line down to its command-name part: the words before the
	// first flag-looking token.
	words := make([]string, 0, len(tokens))
	for _, tok := range tokens {
		if strings.HasPrefix(tok, "-") {
			break
		}
		words = append(words, tok)
	}
	if len(words) == 0 {
		return "", false
	}

	best := ""
	bestDistance := suggestionMaxDistance + 1

	consider := func(candidate, canonical string) {
		// Compare against the same number of leading typed words as the
		// candidate has, so a trailing remote command ("grup info uptime")
		// does not penalize the match.
		n := len(strings.Fields(candidate))
		if n > len(words) {
			n = len(words)
		}
		typed := strings.ToLower(strings.Join(words[:n], " "))
		d := levenshtein(typed, strings.ToLower(candidate))
		if d < bestDistance || (d == bestDistance && best != "" && canonical < best) {
			// An exact match is not a typo; the dispatcher would have
			// resolved it already.
			if d == 0 {
				return
			}
			best = canonical
			bestDistance = d
		}
	}

	for _, spec := range r.ordered {
		if spec.Trusted {
			continue
		}
		consider(spec.Name, spec.Name)
		for _, alias := range spec.Aliases {
			consider(alias, spec.Name)
		}
	}

	if best == "" {
		return "", false
	}
	return best, true
}

// SuggestCommandLine fuzzy-matches against the process-wide registry (see
// Registry.SuggestCommandLine).
func SuggestCommandLine(tokens []string) (string, bool) {
	return defaultRegistry.SuggestCommandLine(tokens)
}

// WithCommandSuggestion enriches an unknown-command error with a top-level
// "did you mean" suggestion when the typed line is close to a real command.
// Any other error — including nil — is returned unchanged, so callers can
// apply it unconditionally to the dispatch result.
func WithCommandSuggestion(err error, tokens []string) error {
	if err == nil || !strings.HasPrefix(err.Error(), "unknown command") {
		return err
	}
	if suggestion, ok := SuggestCommandLine(tokens); ok {
		return fmt.Errorf("%s — did you mean %q?", err.Error(), suggestion)
	}
	return err
}

// levenshtein returns the edit distance (insertions, deletions,
// substitutions) between two strings, operating on bytes — command names and
// aliases are ASCII. It uses the classic two-row dynamic program, O(len(a))
// memory.
func levenshtein(a, b string) int {

	if a == b {
		return 0
	}

	prev := make([]int, len(a)+1)
	curr := make([]int, len(a)+1)
	for i := range prev {
		prev[i] = i
	}

	for j := 1; j <= len(b); j++ {
		curr[0] = j
		for i := 1; i <= len(a); i++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[i] = min(prev[i]+1, min(curr[i-1]+1, prev[i-1]+cost))
		}
		prev, curr = curr, prev
	}

	return prev[len(a)]
}
