// Package completer holds the interactive prompt's tab-completion logic in a
// form that is independent of any prompt/TUI library. It works purely on plain
// strings and an injected list of commands, so it can be unit-tested in
// isolation and reused regardless of which prompt library drives the REPL.
//
// The interactive command adapts this package to its prompt library: it
// translates the library's document/suggestion types to and from the types
// declared here.
package completer

import (
	"sort"
	"strings"
)

// Arg describes a single named argument of a command for completion purposes.
type Arg struct {
	// Name is the argument name without the leading dashes (e.g. "username").
	Name string
	// Description is the human-readable help text for the argument.
	Description string
}

// Command describes a completable command: its name, its help text and its
// arguments. Callers build this list from whatever command registry they have.
type Command struct {
	// Name is the command name as typed (may contain spaces).
	Name string
	// Description is the human-readable help text shown next to the command.
	Description string
	// Args is the set of arguments the command accepts.
	Args []Arg
}

// Suggestion is a single, library-agnostic completion suggestion.
type Suggestion struct {
	// Text is the value that would be inserted if the suggestion is accepted.
	Text string
	// Description is the help text shown alongside the suggestion.
	Description string
}

// Suggest returns the completion suggestions for the current prompt state.
//
// The three string inputs mirror what every line-prompt exposes:
//   - currentLine is the full text of the line being edited;
//   - textBeforeCursor is the text to the left of the cursor;
//   - wordBeforeCursor is the partial word immediately left of the cursor.
//
// cmds must contain only the commands that should be offered (e.g. the caller is
// expected to have already filtered to public commands).
//
// Behavior mirrors the original prompt completer:
//   - with nothing typed yet, no suggestions are returned;
//   - once the line starts with a known command followed by a space, the
//     command's not-yet-present arguments are suggested (as "--name"), filtered
//     by the word being typed;
//   - otherwise, command names matching the typed prefix are suggested.
//
// Argument and command suggestions are returned in a stable, alphabetical order
// so completion is deterministic.
func Suggest(cmds []Command, currentLine, textBeforeCursor, wordBeforeCursor string) []Suggestion {
	// Nothing typed yet: offer nothing, matching the original behavior.
	if textBeforeCursor == "" {
		return nil
	}

	// If the line already names a command and a space, complete that command's
	// remaining arguments rather than command names.
	for _, cmd := range cmds {
		if !strings.HasPrefix(currentLine, cmd.Name+" ") {
			continue
		}

		var suggestions []Suggestion
		for _, arg := range cmd.Args {
			// Skip arguments already present on the line.
			if strings.Contains(currentLine, "--"+arg.Name) {
				continue
			}

			// Flatten any tabs/newlines in the description so it renders on a
			// single suggestion line.
			desc := strings.ReplaceAll(arg.Description, "\t", " ")
			desc = strings.ReplaceAll(desc, "\n", " ")

			suggestions = append(suggestions, Suggestion{Text: "--" + arg.Name, Description: desc})
		}

		sortSuggestions(suggestions)
		return filterHasPrefix(suggestions, wordBeforeCursor)
	}

	// Otherwise, suggest command names matching the typed prefix.
	var suggestions []Suggestion
	for _, cmd := range cmds {
		if strings.HasPrefix(cmd.Name, textBeforeCursor) {
			suggestions = append(suggestions, Suggestion{Text: cmd.Name, Description: cmd.Description})
		}
	}

	sortSuggestions(suggestions)
	return filterHasPrefix(suggestions, textBeforeCursor)
}

// sortSuggestions orders suggestions alphabetically by their inserted text so
// completion output is deterministic.
func sortSuggestions(s []Suggestion) {
	sort.Slice(s, func(i, j int) bool {
		return s[i].Text < s[j].Text
	})
}

// filterHasPrefix keeps only the suggestions whose Text starts with sub,
// case-insensitively, preserving their order. This matches the prefix filtering
// the original prompt library applied to the suggestion list.
func filterHasPrefix(suggestions []Suggestion, sub string) []Suggestion {
	if sub == "" {
		return suggestions
	}

	lowerSub := strings.ToLower(sub)
	var filtered []Suggestion
	for _, s := range suggestions {
		if strings.HasPrefix(strings.ToLower(s.Text), lowerSub) {
			filtered = append(filtered, s)
		}
	}
	return filtered
}
