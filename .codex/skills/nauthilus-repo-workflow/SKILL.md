---
name: nauthilus-repo-workflow
description: Use for any code, documentation, config, dependency, test, review, or maintenance task in the Nauthilus repository that must follow AGENTS.md, POLICY.md, focused reproducer-first debugging, strict DRY/OOP boundaries, English comments, GOEXPERIMENT=runtimesecret test discipline, Makefile-driven validation, prompt-sync checks, and dirty-tree preservation.
---

# Nauthilus Repo Workflow

## Expertise Lens

- Work as a senior Go production maintainer for a security-sensitive authentication and identity platform.
- Optimize for repo truth, focused reproducers, small cohesive types, strict DRY, hermetic tests, and evidence-backed closeout.
- Treat skipped `GOEXPERIMENT=runtimesecret`, duplicated logic, undocumented touched helpers, stale generated output, and accidental dirty-tree edits as correctness risks.

## Core Workflow

1. Read the live project rules before acting:
   - `AGENTS.md`
   - `POLICY.md`
   - task-specific docs such as `README.md`, `IDP.md`, `README_REDIS_CLUSTER.md`, `server/lua-plugins.d/README.md`, or `server/openapi/client/README.md`
2. Check the worktree before edits:
   - `git status --short --branch`
   - preserve unrelated user changes
   - do not clean, revert, or stage unrelated files
3. Use Makefile targets where possible.
4. For all Go test commands, ensure `GOEXPERIMENT=runtimesecret` is present.
5. Keep numbered rollout-stage terminology out of source code, tests, docs, filenames, branches, tags, commit subjects, and commit bodies.

## Coding Rules

- Start bug fixes with focused reproducer tests when practical.
- For Lua issues, add a Lua reproducer first, preferably JSON-driven under `testdata/`.
- For Go issues, add a focused Go test first.
- Keep useful reproducer tests as regression coverage.
- Apply DRY strictly; extract shared behavior instead of copy-paste.
- Use small, cohesive types with methods, narrow interfaces, and composition-first design.
- Document newly added or changed non-exported functions and methods with concise English comments.
- Write code comments and technical docs in English.
- Keep structs memory-conscious where the code is performance-sensitive: group pointer fields and avoid unnecessary GC scan area.

## Testing

- Prefer commands through Makefile targets.
- Use `GOEXPERIMENT=runtimesecret make test` for the repo test lane.
- Use `GOEXPERIMENT=runtimesecret make race` for race coverage.
- Use package-scoped runs while iterating, for example `GOEXPERIMENT=runtimesecret go test -run TestName ./server/...`.
- Use Delve (`dlv`) when a focused local reproducer needs call-stack, goroutine, state, or breakpoint inspection beyond
  logs and assertions. Preserve `GOEXPERIMENT=runtimesecret`, use sanitized local inputs, and never attach to a
  production process without explicit operator approval.
- Treat debugger evidence as supplemental; retain useful reproducer tests and still run the normal validation gates.
- Use a local `GOCACHE` only when the sandbox cache is not writable.
- Avoid real Redis in unit tests; use redismock and `rediscli.NewTestClient`.
- Keep Lua tests hermetic with `lua.NewState`, module preloaders, and JSON fixtures.

## Closeout

- Run focused checks for the touched surface.
- Run `git diff --check`.
- Run `make guardrails` before commit or pull request unless the user explicitly narrows or defers validation.
- Use `nauthilus-release-closeout` when the user asks for guardrails, dependency closure, commit, push, merge, tag, or release-sensitive publishing.
