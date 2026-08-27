---
name: nauthilus-redis-runtime
description: Use for Nauthilus Redis client, Redis Cluster/Sentinel/topology behavior, Redis-backed token/session/flow/cache/bruteforce state, Lua Redis scripts, `NOSCRIPT` recovery, script upload/retry behavior, redismock tests, local cache coordination, and fail-closed runtime state changes.
---

# Nauthilus Redis Runtime

## Expertise Lens

- Work as a Redis and distributed-runtime reliability engineer for authentication state.
- Optimize for fail-closed semantics, explicit Redis ownership, cluster-safe key design, Lua script resilience, redismock coverage, and production recovery behavior.
- Treat `NOSCRIPT`, stale script handles, CROSSSLOT hazards, ambiguous Redis errors, real-Redis unit tests, and secret-bearing keys as reliability or security findings.

## Sources To Read

- `AGENTS.md`
- `POLICY.md`
- `README_REDIS_CLUSTER.md`
- `server/rediscli/`
- `server/lualib/redislib/`
- `server/localcache/`
- touched state owners under `server/idp/`, `server/bruteforce/`, `server/core/`, or `server/policy/`

## Redis Rules

- Use Redis as the explicit production state authority only for the state the code owns.
- Keep Redis client initialization centralized in `server/rediscli`.
- Avoid real Redis in unit tests; prefer redismock and `rediscli.NewTestClient`.
- Preserve TLS, auth, Cluster, Sentinel, read/write routing, and timeout behavior when touching client setup.
- For Lua scripts, keep script identity and source available for reload/retry paths.
- On `NOSCRIPT`, re-upload once and retry the intended operation without hiding persistent failures.
- Keep keys, metrics, and errors free of raw secrets.

## Implementation Workflow

1. Add a focused reproducer for the failing Redis or script behavior.
2. Model runtime ambiguity explicitly: decide retry, fail-closed, or fallback based on the owning state semantics.
3. Keep retry and script-upload logic shared instead of copied per command.
4. Add redismock expectations and `ExpectationsWereMet` checks where useful.
5. Consider Cluster hash-slot behavior when Lua scripts touch multiple keys.

## Validation

- Run focused tests with `GOEXPERIMENT=runtimesecret`.
- Run Redis Lua package tests when `server/lualib/redislib` changes.
- Run `GOEXPERIMENT=runtimesecret make test` and `git diff --check`.
- Run `make guardrails` before commit or pull request.
