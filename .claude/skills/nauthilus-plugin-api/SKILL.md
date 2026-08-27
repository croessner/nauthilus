---
name: nauthilus-plugin-api
description: Use for Nauthilus native Go plugin API design or implementation, `pluginapi/v1`, plugin loader, plugin registry, plugin runtime, reload integration, plugin config, extension-point parity with Lua, capability-based host services, lifecycle semantics, and the working draft under `server/docs/go_plugin_api_working_draft.md`.
---

# Nauthilus Plugin API

## Expertise Lens

- Work as a language-runtime boundary and extension-platform architect.
- Optimize for stable public API contracts, trusted-code assumptions, explicit lifecycle, capability-based host services, Lua/Go extension parity, and isolation from server internals.
- Treat accidental exports of `core.AuthState`, raw Gin contexts, raw Viper, Redis internals, LDAP queues, Prometheus registerers, or OpenTelemetry providers as API boundary defects.

## Sources To Read

- `AGENTS.md`
- `POLICY.md`
- `server/docs/go_plugin_api_working_draft.md`
- `pluginapi/v1/`
- `server/pluginloader/`
- `server/pluginregistry/`
- `server/pluginruntime/`
- Lua extension references under `server/lua-plugins.d/` and `server/lualib/`

## Design Rules

- Keep native Go plugins conceptually aligned with Lua extension points: init, environment sources, subject sources, backends, actions, hooks, policy facts, and shared services.
- Keep policy as decision authority; plugins emit facts/results/obligations/status, policy decides.
- Expose stable API-level value objects from `pluginapi/v1`; do not expose server internals.
- Use context-first, cancelable, deadline-aware request APIs.
- Treat loaded Go plugins as trusted in-process code.
- Make lifecycle explicit: register, start, stop, and reconfigure where supported.
- Remember Go `.so` plugins cannot be unloaded; removal or binary replacement normally requires restart.
- Validate module and component names strictly; do not normalize surprising names into collisions.

## Implementation Workflow

1. Start from the working draft and decide whether the task is design-only or implementation.
2. Keep public API changes in `pluginapi/v1` narrow and documented.
3. Keep host services capability-based and minimal.
4. Keep reload behavior explicit and testable.
5. Add import-boundary and contract tests when public API or server boundary rules change.

## Validation

- Run focused plugin API tests with `GOEXPERIMENT=runtimesecret`.
- Run reload/config tests when plugin config or lifecycle changes.
- Run `GOEXPERIMENT=runtimesecret make test` and `git diff --check`.
- Run `make guardrails` before commit or pull request.
