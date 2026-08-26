# Policy Registry Scripts

This directory contains Lua registry scripts for custom policy attributes emitted by bundled plugins.

## registry.lua

Registers the `lua.plugin.*` attributes emitted through `share/nauthilus_policy_facts.lua`.

Configure it under the `authn` namespace schema contribution:

```yaml
policy:
  namespaces:
    authn:
      schema_contributions:
        lua:
          registry_scripts:
            - "/etc/nauthilus/lua-plugins.d/policy/registry.lua"
```

The registry script is compile-time material. Runtime plugins emit only attributes that were registered in the active
policy snapshot. If an emitting plugin tries to write an unknown attribute, Nauthilus fails that Lua execution instead
of treating the value as a loose fact.

This registry-script path remains part of the authentication integration and is explicitly `authn`-scoped. It is
separate from the generic target-aware provider contract below.

## Generic Lua provider callbacks

A generic provider with `kind: lua` contributes facts and selected host effects through two exact global callback
keys:

```lua
_G["policy.facts.collect"] = function(request)
    return {
        facts = {
            { name = "risk_score", value = { kind = "integer", value = "42" } },
        },
    }
end

_G["policy.effects.execute"] = function(request)
    return { state = "succeeded" }
end
```

The host compiles the configured script once for a candidate generation, verifies each required callback, and creates a
fresh restricted Lua state for every invocation. The state has deterministic base, table, string, and math operations,
but no `io`, `os`, `package`, `require`, file loading, dynamic loading, or legacy Nauthilus modules. It is bound to the
host context so deadlines and cancellation stop Lua execution. State created by one request is closed after that request
and cannot leak globals into the next invocation.

### Fact collection request and result

`policy.facts.collect(request)` is invoked only at the generic fact-collection point for an exact target declared by the
provider. The request table is:

```lua
{
    target = { namespace = "dkim2", action = "sign-message" },
    caller = {
        principal = "mail-gateway",
        client_id = "smtp-edge",
        authentication_kind = "private_key_jwt",
        scopes = { "policy.evaluate" },
    },
    facts = {
        {
            id = "request.header.message_type",
            category = "environment",
            value = { kind = "string", value = "transactional" },
        },
    },
}
```

The caller and fact views are detached and redacted. Mutating the Lua tables cannot mutate trusted provenance or the
active request. The callback returns either `facts` or `error_class`, never both:

```lua
return {
    facts = {
        { name = "risk_score", value = { kind = "integer", value = "42" } },
    },
}

-- Provider-local failure without facts:
return { error_class = "unavailable" }
```

Fact names are local suffixes. For a configured module `reputation`, the host turns local `risk_score` into
`lua.reputation.risk_score`; scripts must not return a `lua.*` or `plugin.*` prefix. The corresponding qualified fact
must have been listed in `produced_facts`, and its category, kind, and bounds must match every exact target schema. The
schema must allow source `lua`. Undeclared or duplicate facts, wrong types or bounds, collisions, foreign
namespace/source/authority claims, and unknown result fields are contract violations and always fail closed as
`indeterminate`, even when the provider uses `failure: continue`.

The closed error classes are `invalid_input`, `unavailable`, `timeout`, and `internal`. A successful callback may return
an empty or omitted `facts` list. It cannot return a decision, abort flag, plan order, target activation, trusted source,
response mutation, retry instruction, or detached work.

### Strict typed values

Every fact and effect parameter uses `{ kind = ..., value = ... }`. The supported encodings are:

| `kind` | Lua `value` |
| --- | --- |
| `string` | UTF-8 string |
| `boolean` | Lua boolean |
| `integer` | base-10 signed int64 string, preserving the full range without Lua-number precision loss |
| `double` | finite Lua number |
| `strings` | dense ordered UTF-8 string array |
| `bytes` | standard Base64 string |
| `timestamp` | UTC RFC 3339 timestamp with optional nanoseconds |

Unknown fields, sparse arrays, invalid encodings, non-finite doubles, and values outside the configured schema bounds are
rejected. Input and output collections also have host-owned count and byte limits.

### Selected effects

`policy.effects.execute(request)` receives only an obligation already selected by policy and validated against the target
and typed effect schema:

```lua
{
    target = { namespace = "dkim2", action = "sign-message" },
    caller = { principal = "mail-gateway", client_id = "smtp-edge",
               authentication_kind = "private_key_jwt", scopes = { "policy.evaluate" } },
    facts = { -- the same strict admitted-fact view as fact collection },
    effect = "dkim2/record-audit",
    parameters = {
        { name = "message", value = { kind = "string", value = "accepted" } },
    },
}
```

The callback returns exactly one of the following closed results:

```lua
return { state = "succeeded" }
return { state = "failed", error_class = "unavailable" }
return { state = "outcome_unknown", error_class = "timeout" }
```

`succeeded` must not include an error class; `failed` and `outcome_unknown` require one. The host never invokes this
callback for an unselected effect, advice, or a `return_only` obligation. Synchronous effects execute before response
finalization. For `host_post_action`, Lua prepares no goroutine or detached task: the host captures the immutable request,
requires supervisor acceptance before finalization, and invokes the callback later under supervisor ownership. Lua never
receives the finalization gate.

Each selected effect ordinal is attempted at most once. Nauthilus does not retry a known failure, timeout, cancellation,
or `outcome_unknown`. A synchronous `outcome_unknown` makes the decision `indeterminate` and remains non-retryable; a
late accepted post-action failure or unknown outcome is reported through bounded host observability and cannot mutate the
already finalized response. Optional domain idempotency belongs inside the provider and is outside this contract.

### Configuration and failure behavior

Generic Lua providers are authored under the namespace that owns their provider and effect definitions:

```yaml
policy:
  namespaces:
    dkim2:
      schema_contributions:
        static:
          sign-message:
            versions:
              v1:
                facts:
                  - attribute: lua.reputation.risk_score
                    category: environment
                    type: integer
                    allowed_sources: [lua]
      providers:
        risk:
          kind: lua
          module: reputation
          script_path: /etc/nauthilus/lua/reputation.lua
          targets: [{action: sign-message}]
          produced_facts: [lua.reputation.risk_score]
          executions: [host_sync]
          failure: indeterminate
          timeout: 100ms
          diagnostics: {public_id: reputation}
      effects:
        record-audit:
          kind: obligation
          provider: dkim2/risk
          targets: [{action: sign-message}]
          execution: host_sync
          parameters:
            message:
              type: string
              max_length: 32
              non_empty: true
              required: true
```

`module` is a canonical lowercase Lua authority. The provider above becomes
`dkim2/lua.reputation.risk`. Targets may be explicit or derived from exact plan/effect bindings; declared facts require at
least one target, one identical schema shape across all targets, and `allowed_sources: [lua]` (possibly alongside other
allowed sources).

Every generic provider declares `failure: indeterminate` or `failure: continue`. `indeterminate` discards the failing
dependency level, cancels unstarted later work, selects no effects, and fails evaluation. Compiler-safe `continue`
contributes no facts, marks `requires` dependents `skipped_dependency`, and allows independent providers to proceed.
Unsafe continuation is rejected during candidate compilation. Schema, provenance, namespace, authority, type, bounds,
and result-contract violations always override `continue` and fail closed.

Candidate preparation owns the compiled scripts, descriptors, definitions, and runtime bindings immutably. Configuration,
script preparation, catalog compilation, provider resolution, parameter validation, or supervisor-acceptance failure is
reported before response finalization; none can leave a partially activated generation.
