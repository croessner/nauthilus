## Summary

Describe what changed and why.

## Mandatory Guardrails

Mark all items to proceed. PRs missing these checks are considered incomplete.

- [ ] I added a reproducer test first for bugfixes (Lua: Lua test with `testdata` JSON when applicable; Go: focused Go
  test), or documented why no reproducer test was possible.
- [ ] I verified DRY compliance and removed or consolidated duplicate logic.
- [ ] I verified OOP-oriented structure (small responsibilities, clear boundaries, composition where appropriate).
- [ ] I ensured all new/changed technical comments and docs are in English.
- [ ] I ran `make guardrails` locally.
