---
name: nauthilus-release-closeout
description: Use for Nauthilus validation, guardrails, dependency patch refreshes, vendoring, generated-output checks, `make release-guardrails`, govulncheck-sensitive publishing, structured commits, branch/tag choreography, website-doc side effects, and final clean-state reporting.
---

# Nauthilus Release Closeout

## Expertise Lens

- Work as a release manager and CI/quality-gate owner for a security-sensitive Go authentication platform.
- Optimize for exact checkout identity, reproducible generated artifacts, synchronized vendor state, vulnerability gates, structured commit history, and publishing only validated content.
- Treat skipped guardrails, missing `GOEXPERIMENT=runtimesecret`, stale generated outputs, dirty release checkouts, unsynced vendor, and unchecked `govulncheck` as release blockers.

## Decide Closure Depth

Identify whether the user asked for:

- validation only
- dependency refresh
- commit
- push of the current branch
- merge to `main`
- version tag
- release-sensitive publication

Do not commit, push, merge, tag, reset, or publish unless the user asked for that scope.

## Preflight

1. Check:
   - `git status --short --branch`
   - `git branch --show-current`
   - `git remote -v` when multiple repos may be involved
2. Preserve unrelated dirty-tree changes.
3. Keep ignored `temp/`, `.cache/`, local credentials, and generated local artifacts out of commits unless explicitly requested.

## Validation Order

- Run focused package tests first when useful, always with `GOEXPERIMENT=runtimesecret`.
- Run `git diff --check`.
- Run generated checks that match the touched surface:
  - `make sync-prompts-check`
  - `make policy-check`
  - `make generate-vim-syntax-check`
  - `make generate-openapi-bindings-check`
- Run `make guardrails` before commit or pull request.
- Run `make release-guardrails` before publishing `main` or any `v*` tag, or verify an installed pre-push hook ran the equivalent `govulncheck` gate against the exact published commit.

## Dependency Closure

For dependency refreshes:

- prefer patch-level updates when requested
- run `go mod tidy`
- run `go mod vendor`
- check `vendor/modules.txt`
- run guardrails after vendoring

## Commit Format

Use:

```text
Prefix: Concise headline

- Detail the most relevant implementation work
- Mention tests, guardrails, or generated files when relevant
- Call out operator-facing behavior, config, packaging, or dependency changes
```

Allowed prefixes: `Add`, `Change`, `Fix`, `Remove`, `Refactor`, `Test`, `Docs`, `Build`, `Ci`, `Vendor`, `Security`, `Chore`.

Split unrelated work into separate commits.

## Publish Choreography

- Stage only intended tracked files.
- Prefer explicit paths over `git add -A` when ignored scratch artifacts exist.
- Confirm `HEAD` matches the content that was validated before pushing release-sensitive refs.
- If the user asks for branch choreography, commit on the working branch, push it, fast-forward `main` if possible, rerun required gates on `main`, push `main`, tag only after release gates, then return to the requested working branch.

## Final Report

Include:

- validation commands and outcomes
- commit hash when created
- pushed branch or tag when pushed
- final branch
- `git status --short`
- skipped checks with reasons
