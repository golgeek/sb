---
name: commit-and-pr
description: >-
  How to write commits and open pull requests in the sb repository — commit
  message structure (previous behavior, why it was a problem, what changed, how
  it's tested), branching, and PR conventions. Use whenever you are about to
  commit changes or open a PR.
---

# Committing & opening PRs in `sb`

Pairs with the `task-workflow` skill: one task = one PR. A PR is either a single
commit or a **commit arc** (see below) — but always one cohesive scope. This
skill covers *how* those commits and the PR are written. Only ever commit or
push when the user explicitly asks.

## Branching & worktrees

- Never commit directly to `main`. Each task lives on its own focused,
  descriptively named branch (e.g. `totp-crypto-rand`, `go-version-bump`).
- That branch lives in a dedicated **git worktree** under
  `~/.worktrees/sb-{branch-name}` — see the `task-workflow` skill for how it's
  created (standalone off `main`, or stacked off a parent task's branch). Run
  all commit/PR commands from inside that worktree.
- One branch holds one logical change (a single commit or a cohesive commit
  arc). If you discover an unrelated issue, leave it for a separate branch/PR.

## Commit arcs (multiple commits per PR)

A single PR may contain **multiple commits** as long as they all belong to the
same scope and each commit **builds and passes the test suite independently**.
This lets a reviewer follow the change as a logical progression instead of one
large diff. Split along natural seams, e.g.:

- commit 1 — introduce a new interface;
- commit 2 — implement the interface;
- commit 3 — wire the implementation into the call sites;
- commit 4 — add tests.

Rules for an arc:

- **Every commit is green.** At each commit the tree must `go build ./...` and
  `go test ./...` clean. A later commit may *add* tests, but it must never leave
  an intermediate commit broken or failing — the suite passes at every step.
- **Each commit still follows the message structure below.** Earlier
  scaffolding commits (e.g. "introduce interface") describe what they add and
  why; the "how it's tested" beat can note that tests land later in the arc.
- **Keep the arc cohesive.** If a commit doesn't serve the PR's single scope, it
  belongs in a different PR.

### Folding review fixes back into the arc

When iterating on a multi-commit PR during review, **do not append "address
review" commits**. Instead fold each fix into the commit it logically belongs
to, so the arc stays clean and every commit remains green and self-contained:

```bash
git commit --fixup=<sha-of-the-target-commit>
git rebase -i --autosquash <base>   # non-interactive in this env: see note
```

- Use `git commit --fixup=<sha>` (or `--fixup=amend:<sha>` to also edit the
  message) so the fix is tagged for the right target commit.
- Then `git rebase --autosquash` to squash the fixups into their targets.
- Interactive flags (`-i`) are unavailable in this environment; drive autosquash
  non-interactively, e.g.
  `GIT_SEQUENCE_EDITOR=: git rebase -i --autosquash <base>`.
- After squashing, re-verify each commit still builds and passes tests (the
  fix must not have broken an earlier step). Force-push the rebased branch.

## Commit message structure

A commit message must let a future reader (or auditor — this is a security
product) understand the change without reading the diff. Use:

```
<scope>: <imperative one-line summary>

Previously, <what the behavior was before this change>.
This was problematic because <the concrete risk or bug it caused>.

This patch <what was changed and how it fixes the problem; mention the key
technical decisions, e.g. which API/approach and why>.
<Any follow-on changes made for consistency, e.g. other call sites updated.>

<How the change is tested — unit tests, e2e, mocks, manual verification.>
```

Every commit body must cover, in order:

1. **Previous behavior** — what the code did before.
2. **Why it was a problem** — the concrete bug, risk, or limitation.
3. **What was done to fix it** — the change and the reasoning behind the
   approach, including notable technical choices.
4. **How it is tested** — what tests were added/run and that they pass.

Guidelines:
- Subject line: lowercase `scope:` prefix (the package/area, e.g. `totp`,
  `helpers`, `replication`), imperative mood, no trailing period, ≤ ~72 chars.
- Wrap the body at ~72 columns. Use full sentences; be descriptive.
- Be honest in the testing section — if something was only manually verified or
  a pre-existing test is still red, say so.
- Do not add any tooling/attribution trailer (no `Co-Authored-By`, no "Generated
  with" footer) to commits or PRs.

### Example

```
totp: cryptographically secure recovery codes

Previously, the TOTP recovery codes were using a non-cryptographic RNG.
This was problematic because an attacker who knew when the codes were
generated could predict them.

This patch now reads from crypto/rand via cryptorand.Int (uniform, no
modulo bias) to produce random strings in a cryptographically secure way.
All code paths using randomness were updated to use the new method.

Tests were added and verified.
```

## Pull requests

- Open the PR with `gh` once the branch is pushed (only when the user asks).
- **Title**: same style as the commit subject — `scope: summary`.
- **Body**: mirror the commit structure but at PR altitude — a short summary,
  then the same four beats (previous behavior, why it was a problem, what
  changed, how it's tested). Include a short test plan / checklist a reviewer
  can follow. Describe the *intent* of the change in full; you may consult
  internal scoping docs (e.g. an untracked `MODERNIZATION.md`) to write it, but
  **never reference or link those docs in the PR body** — they are not tracked
  and not public. The PR description must stand on its own.
- Keep the PR scoped to the single task so it is reviewable in one sitting.

## Before committing / opening the PR

- Re-read the diff; confirm it matches the agreed design and nothing unrelated
  snuck in.
- Run `go build ./...` and `go test ./...`; the testing section of the message
  must reflect their real result.
