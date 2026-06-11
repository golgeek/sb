package commands

import (
	"fmt"
	"sort"
	"strings"

	"github.com/golgeek/sb/internal/helpers"
	"github.com/golgeek/sb/internal/models"
	"github.com/golgeek/sb/internal/types"
)

// CommandSpec is the declarative description of a sb command: its canonical
// name, aliases, rights level, help texts, declared flags, and a constructor
// for the Command implementation. Specs are the single source of truth of the
// command system; every other view (the flat name/alias index used by the
// replication-apply path and the cobra tree used by the human-facing CLI) is
// generated from them, so the two can never drift apart.
type CommandSpec struct {
	// Name is the canonical command name. It may contain spaces (e.g.
	// "self totp emergency-codes generate"); each space-separated word becomes
	// one level of the generated cobra tree. Canonical names are a persisted,
	// cross-instance contract: replication outbox entries carry them as the
	// action identifier and peer daemons resolve them through the flat
	// registry, so an existing command's Name must never change.
	Name string

	// Aliases are alternative single-word names for the command (the
	// historical camelCase forms, e.g. "selfGenerateTOTPCodes"). They resolve
	// through the flat registry only — never through the cobra tree — and must
	// stay resolvable forever: old replication outbox entries persisted the
	// alias the user typed, and a peer daemon must still be able to apply
	// them.
	Aliases []string

	// Rights is the authorization level enforced for the command. Enforcement
	// stays centralized in the dispatch layer (authorize), not in the
	// command's own Checks.
	Rights models.Right

	// Help carries the human-readable header/usage/description used to render
	// help output.
	Help helpers.Helper

	// Args declares the command's flags, keyed by flag name.
	Args map[string]Argument

	// Trusted marks a command that is dispatched only by the sb front-end
	// with trusted arguments (interactive, ttyrec, daemon) and must never be
	// invocable by a user through the CLI tree or the interactive REPL.
	// Trusted specs are resolvable through the flat registry (the front-end
	// and the replication-apply path need them) but are excluded from
	// BuildRootCommand — and therefore from help, completion, and
	// suggestions.
	Trusted bool

	// New constructs a fresh Command instance. A new instance is created for
	// every execution so no state leaks between runs (the interactive REPL
	// executes many commands in one process).
	New func() Command
}

// firstWord returns the first space-separated word of the spec's canonical
// name. It is the token the front-end dispatch matches on to decide whether a
// command line is addressed to the command system or to a distant host.
func (s *CommandSpec) firstWord() string {
	return strings.Fields(s.Name)[0]
}

// Registry holds registered command specs and the flat lookup index derived
// from them. The index is keyed by every canonical name and every alias, so
// programmatic dispatch (replication apply, the REPL completer, the front-end
// "is this a command?" check) is a single O(1) map lookup that never touches
// cobra.
//
// A Registry is not safe for concurrent registration; registration happens
// exclusively from package init functions, which the Go runtime serializes.
type Registry struct {
	// ordered keeps the registered specs sorted by canonical name so every
	// generated view (cobra tree, help, completion) is deterministic.
	ordered []*CommandSpec

	// index maps every canonical name and every alias to its spec.
	index map[string]*CommandSpec

	// firstWords maps the first word of every canonical name to true; it
	// backs the front-end dispatch check (IsCommandToken) without a scan.
	// Trusted specs are deliberately excluded: their names must fall through
	// to the access path so a user can never address them directly.
	firstWords map[string]bool
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{
		index:      make(map[string]*CommandSpec),
		firstWords: make(map[string]bool),
	}
}

// Register validates the spec and adds it to the registry. It returns an
// error when the spec is malformed (empty name, nil constructor, multi-word
// alias) or when any of its names would make lookups ambiguous: a canonical
// name or alias that is already taken, an alias equal to the first word of an
// already-registered command, or a first word equal to an already-registered
// alias. Failing closed on ambiguity at registration time guarantees the
// front-end's first-word dispatch always has exactly one meaning per token.
func (r *Registry) Register(spec CommandSpec) error {

	if strings.TrimSpace(spec.Name) == "" {
		return fmt.Errorf("command spec has an empty name")
	}
	if spec.New == nil {
		return fmt.Errorf("command spec %q has a nil constructor", spec.Name)
	}

	if _, exists := r.index[spec.Name]; exists {
		return fmt.Errorf("command %q is already registered", spec.Name)
	}

	for _, alias := range spec.Aliases {
		if strings.TrimSpace(alias) == "" {
			return fmt.Errorf("command %q declares an empty alias", spec.Name)
		}
		if len(strings.Fields(alias)) != 1 {
			return fmt.Errorf("command %q declares multi-word alias %q; aliases must be a single word", spec.Name, alias)
		}
		if _, exists := r.index[alias]; exists {
			return fmt.Errorf("command %q declares alias %q which is already registered", spec.Name, alias)
		}
		if r.firstWords[alias] {
			return fmt.Errorf("command %q declares alias %q which collides with the first word of another command", spec.Name, alias)
		}
	}

	// The new command's first word must not collide with an existing alias:
	// the dispatch layer could no longer tell whether the token starts a
	// canonical name or names another command entirely.
	first := spec.firstWord()
	if existing, exists := r.index[first]; exists && existing.Name != first {
		return fmt.Errorf("command %q starts with %q which is already an alias of %q", spec.Name, first, existing.Name)
	}

	s := spec
	r.index[s.Name] = &s
	for _, alias := range s.Aliases {
		r.index[alias] = &s
	}
	if !s.Trusted {
		r.firstWords[first] = true
	}

	// Keep ordered sorted by canonical name; registration happens a few dozen
	// times at startup, so the insertion sort cost is irrelevant.
	r.ordered = append(r.ordered, &s)
	sort.Slice(r.ordered, func(i, j int) bool { return r.ordered[i].Name < r.ordered[j].Name })

	return nil
}

// MustRegister registers the spec and panics on error. It is the intended
// entrypoint for cmd/*.go init functions: a malformed or colliding spec is a
// programming error that must abort startup rather than silently produce an
// incomplete command system.
func (r *Registry) MustRegister(spec CommandSpec) {
	if err := r.Register(spec); err != nil {
		panic(err)
	}
}

// Get resolves a canonical name or alias to its spec. It returns
// types.ErrUnknownCommand when nothing matches. This is the lookup used by
// the replication-apply path: both canonical names and aliases must resolve
// here forever (old outbox entries persisted whichever form the user typed).
func (r *Registry) Get(nameOrAlias string) (*CommandSpec, error) {
	if spec, ok := r.index[nameOrAlias]; ok {
		return spec, nil
	}
	return nil, types.ErrUnknownCommand
}

// Specs returns the registered specs sorted by canonical name. The returned
// slice is a copy; the specs it points to are shared.
func (r *Registry) Specs() []*CommandSpec {
	out := make([]*CommandSpec, len(r.ordered))
	copy(out, r.ordered)
	return out
}

// IsCommandToken reports whether token addresses the user-facing command
// system: it is the first word of a non-trusted canonical name, or a
// non-trusted alias. The front-end dispatch uses it to decide between the
// cobra tree and the host-access path. Trusted specs (interactive, ttyrec,
// daemon) deliberately return false so their names fall through to the access
// path exactly as an unknown word would: a user must not be able to invoke
// them directly.
func (r *Registry) IsCommandToken(token string) bool {
	if r.firstWords[token] {
		return true
	}
	if spec, ok := r.index[token]; ok {
		return !spec.Trusted
	}
	return false
}

// CanonicalTokens rewrites a tokenized command line so cobra can walk it: when
// the first token is an alias (or a single-word canonical name) of a
// non-trusted command, it is replaced by the canonical name's words. All other
// token lists are returned unchanged — including trusted-command names, which
// must keep falling through to the access path.
//
// Example: ["selfGenerateTOTPCodes", "--foo", "x"] becomes
// ["self", "totp", "emergency-codes", "generate", "--foo", "x"].
func (r *Registry) CanonicalTokens(tokens []string) []string {
	if len(tokens) == 0 {
		return tokens
	}
	spec, ok := r.index[tokens[0]]
	if !ok || spec.Trusted {
		return tokens
	}
	return append(strings.Fields(spec.Name), tokens[1:]...)
}

// defaultRegistry is the process-wide registry populated by cmd/*.go init
// functions through Register.
var defaultRegistry = NewRegistry()

// Register adds a spec to the process-wide registry, panicking on a malformed
// or colliding spec (see Registry.MustRegister). It is called from cmd/*.go
// init functions.
func Register(spec CommandSpec) {
	defaultRegistry.MustRegister(spec)
}

// GetSpec resolves a canonical name or alias against the process-wide
// registry. It returns types.ErrUnknownCommand when nothing matches.
func GetSpec(nameOrAlias string) (*CommandSpec, error) {
	return defaultRegistry.Get(nameOrAlias)
}

// Specs returns the process-wide registry's specs sorted by canonical name.
func Specs() []*CommandSpec {
	return defaultRegistry.Specs()
}

// IsCommandToken reports whether token addresses a user-facing command in the
// process-wide registry (see Registry.IsCommandToken).
func IsCommandToken(token string) bool {
	return defaultRegistry.IsCommandToken(token)
}

// CanonicalTokens rewrites a tokenized command line against the process-wide
// registry (see Registry.CanonicalTokens).
func CanonicalTokens(tokens []string) []string {
	return defaultRegistry.CanonicalTokens(tokens)
}
