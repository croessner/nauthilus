---
name: nauthilus-repo-workflow
description: Use for any code, documentation, config, dependency, test, review, or maintenance task in the Nauthilus repository that needs worktree hygiene, the project documentation map, focused reproducer-first debugging, Makefile-driven validation, and evidence-backed closeout.
---

# Nauthilus Repo Workflow

`AGENTS.md` and `POLICY.md` are loaded permanently through `CLAUDE.md` and stay
the authority for coding rules, DRY and OOP expectations, English comments, and
the `GOEXPERIMENT=runtimesecret` test discipline. This skill adds only what
those two files do not already cover.

## Expertise Lens

- Work as a senior Go production maintainer for a security-sensitive authentication and identity platform.
- Optimize for repo truth, focused reproducers, hermetic tests, and evidence-backed closeout.
- Treat skipped `GOEXPERIMENT=runtimesecret`, duplicated logic, undocumented touched helpers, stale generated output, and accidental dirty-tree edits as correctness risks.

## Documentation Map

Read the docs that match the touched surface before acting:

- `README.md` for the project overview
- `IDP.md` for the identity-provider surface
- `README_REDIS_CLUSTER.md` for Redis topology behavior
- `server/lua-plugins.d/README.md` for the Lua plugin surface
- `server/openapi/client/README.md` for generated client work

## Worktree Hygiene

- Run `git status --short --branch` before making edits.
- Preserve unrelated user changes already present in the worktree.
- Do not clean, revert, or stage unrelated files.

## Closeout

- Run focused checks for the touched surface.
- Run `git diff --check`.
- Run `make guardrails` before commit or pull request unless the user explicitly narrows or defers validation.
- Use `nauthilus-release-closeout` when the user asks for guardrails, dependency closure, commit, push, merge, tag, or release-sensitive publishing.
