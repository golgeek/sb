---
name: task-workflow
description: >-
  How to tackle any implementation task in the sb repository — workflow,
  design-first discipline, commit/PR scoping, testing, and code-quality bar.
  Use whenever the user asks you to start working on a task, whether it comes
  from MODERNIZATION.md or any other scoping document. Invoke at the very start,
  BEFORE writing any implementation code.
---

# Task workflow for `sb`

`sb` is a production-ready security product (an SSH bastion / jump host). Treat
every change accordingly. There is no "fast and dirty" path here — correctness,
clarity, and a defensible security boundary always win over speed.

## The golden rule: design before code

When the user asks you to start a specific task, **do not jump into
implementation**. First ask clarifying questions until the design is
*one-shottable* — i.e. you and the user have agreed on an exact outcome and you
could implement it without further guesswork.

Ask about, at minimum:
- **Scope boundaries** — what is explicitly in vs out of this PR.
- **Behavioral contract** — exact inputs/outputs, error semantics, edge cases,
  backward-compatibility requirements.
- **Security implications** — does this touch the sudoers/privilege boundary,
  encryption, authentication, or the egress SSH path? If so, confirm the
  threat-model intent.
- **Interfaces & config** — new config keys, new commands, new exported APIs,
  and how they default (especially for backward compatibility).
- **Testing expectations** — what "done" looks like for tests.

Only once the design is settled, restate it briefly, then implement. If the
design is large or has trade-offs, present options rather than picking silently.

## One task = one commit = one PR

- Each task is tackled **independently** and lands in **its own commit/PR**.
- Never bundle unrelated changes. If you notice a separate issue mid-task, note
  it for a follow-up PR rather than fixing it inline.
- Keep the diff focused and reviewable; a reviewer should be able to hold the
  whole change in their head.
- Only commit or push when the user asks (see the `commit-and-pr` skill for the
  message/PR conventions).

## Set up a worktree before coding

Every task gets its **own git worktree on its own branch**, instead of switching
branches in the main checkout. This keeps multiple features — and stacked PRs —
in flight at once without clobbering each other or the working tree.

- Create the worktree under `~/.worktrees/{repo-name}-{branch-name}` and do all
  of the task's work there. For this repo `{repo-name}` is `sb`.
- Branch off the right base: `main` for a standalone task, or the parent task's
  branch when building a **stacked PR** on top of in-flight work.

```bash
# Standalone task, branched off main:
git worktree add -b totp-crypto-rand ~/.worktrees/sb-totp-crypto-rand main

# Stacked PR, branched off a parent task's branch:
git worktree add -b totp-hash-codes ~/.worktrees/sb-totp-hash-codes totp-crypto-rand
```

- Pick a branch name that describes the task (it appears in the path too).
- When the task is fully merged and no longer needed, remove the worktree:
  `git worktree remove ~/.worktrees/sb-{branch-name}` (and delete the branch).
- Note absolute paths: tool calls run from the worktree directory, so reference
  files by their worktree path, not the original checkout.

## Code quality bar (non-negotiable)

- **Comment everything that matters.** Every function/method gets a doc comment
  describing what it does, its parameters, return values, and error behavior.
  Add inline comments on any non-obvious or complicated code path — explain the
  *why*, not just the *what*. Be verbose and descriptive; this is a security
  product and the next reader needs full context.
- **Best design, no shortcuts.** Choose the correct abstraction even when a hack
  would be faster. Production-ready means: handle errors explicitly (don't
  swallow them), validate inputs, fail closed on the security path.
- Match the surrounding code's idioms, but improve on known anti-patterns rather
  than copying them (see repo `CLAUDE.md` for the catalogue of sharp edges).
- Never weaken the sudoers/privilege model casually. Any change to
  `helpers/system.go` must be paired with the sudoers templates
  (`helpers/templates.go`) and `docs/permissions.md`.

## Testing (heavy, by default)

- Every new feature/PR is **heavily unit- and end-to-end tested**. Untested code
  is not done.
- **Use mocks** to isolate the unit under test (filesystem, exec/sudo, network,
  clock, RNG, storage backends, replication transport).
- **Prefer constructors-with-options over patching internal struct fields in
  tests.** Design the production type so its dependencies are injected through a
  constructor (functional-options pattern or an explicit deps struct), so tests
  wire in fakes cleanly instead of reaching into unexported fields or using
  package-level globals. If a type isn't testable this way, refactor it so it is
  as part of the task.
- Cover the security-critical paths directly with table-driven tests (rights
  enforcement, crypto, input validation).
- Tests must be **hermetic** — no real DNS, network, or system mutation. If the
  code forces non-hermetic tests, that's a design smell to fix.
- Run `go build ./...` and `go test ./...` before declaring done, and report
  results honestly (including pre-existing failures called out in `CLAUDE.md`).

## Before you finish

- Re-read the diff against the agreed design — did you deliver exactly that?
- Confirm tests pass and cover the new behavior.
- Update any docs the change implies (`docs/`, config references, `CLAUDE.md`
  gotchas if you fixed one).
- Summarize what landed and flag any follow-ups you deliberately deferred.
