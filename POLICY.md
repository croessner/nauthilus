# Engineering Policy (Non-Negotiable)

These rules are mandatory for every coding change.
A task is incomplete if any mandatory rule is not satisfied.

## Must Rules

- MUST: Use focused reproducer tests first when debugging bugs.
- MUST: For Lua issues, create a Lua reproducer test first (prefer JSON fixtures in `testdata/` when applicable).
- MUST: For Go issues, create a focused Go reproducer test first.
- MUST: Keep good reproducer tests in the repository when they add coverage or prevent regressions.
- MUST: Apply DRY strictly; avoid duplicated logic and copy-paste implementations.
- MUST: Follow OOP-oriented design with small responsibilities, clear boundaries, and composition-first structure.
- MUST: Write code comments and technical docs in English.
- MUST (CRITICAL, Go 1.26): Always run Go tests with `GOEXPERIMENT=runtimesecret` as prefix.
    - Required command pattern: `GOEXPERIMENT=runtimesecret go test ...`

## Definition Of Done (Required)

- [ ] Reproducer test added first for bugfixes (or explicit reason documented in PR).
- [ ] DRY check completed; duplicate logic removed or intentionally shared.
- [ ] OOP structure verified; responsibilities are small and cohesive.
- [ ] Comments/docs introduced in this change are English-only.
- [ ] `make guardrails` passes locally and in CI.
