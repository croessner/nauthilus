---
name: nauthilus-lua-policy
description: Use for Nauthilus Lua plugins, Lua callback tests, policy compiler and registry work, Lua environment and subject sources, Lua actions, hooks, backend scripts, policy facts, obligation targets, `server/lualib`, `server/lua-plugins.d`, `server/policy`, and JSON fixtures under `testdata/lua`.
---

# Nauthilus Lua Policy

## Expertise Lens

- Work as a Lua extension-system and policy-engine specialist for authentication pipelines.
- Optimize for hermetic Lua reproducers, policy-owned decisions, explicit scheduling, registered facts, reusable shared modules, and safe request-local context handling.
- Treat missing policy fact registration, silent Lua errors, non-hermetic tests, duplicate plugin logic, and action/subject/environment phase confusion as design defects.

## Sources To Read

- `AGENTS.md`
- `POLICY.md`
- `server/lua-plugins.d/README.md`
- relevant plugin README files under `server/lua-plugins.d/*/README.md`
- `testdata/lua/README.md`
- `server/lualib/`
- `server/policy/`
- `server/testing/luatest/` when Go-hosted Lua tests are involved

## Lua And Policy Rules

- For Lua issues, create a Lua reproducer first, preferably JSON-driven with `testdata/lua` fixtures.
- Keep environment sources in pre-auth signal collection, subject sources after backend facts, backends for credential/account lookup, actions as policy-selected obligations, and hooks for explicit lifecycle or HTTP hook points.
- Policy remains the decision authority. Plugins emit facts, backend results, obligation results, and status details.
- Register custom Lua-owned policy attributes before using them in policy rules.
- Use shared Lua modules under `share/` for repeated behavior.
- Keep Lua comments and technical docs in English.
- Avoid logging secrets or raw credentials from Lua or Go bridges.

## Testing Workflow

1. Build the smallest Lua fixture that reproduces the behavior.
2. Use `--test-lua`, callback-specific JSON fixtures, or Go-hosted Lua tests depending on the code path.
3. Preload all required modules; module names must match `definitions.LuaMod...` constants.
4. Validate strict `expected_calls` when module interaction order matters.
5. Keep useful fixtures as regression coverage.

## Validation

- Run focused Go tests with `GOEXPERIMENT=runtimesecret`.
- Run `./scripts/run-lua-plugin-tests.sh` when bundled Lua plugin behavior changes.
- Run `GOEXPERIMENT=runtimesecret make test` and `git diff --check`.
- Run `make guardrails` before commit or pull request.
