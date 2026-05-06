# Nauthilus Policy Decision Layer

**Status:** Implementation-ready specification v0.6
**Date:** 2026-05-06
**Purpose:** align the Policy Decision Layer specification with the current Nauthilus codebase and `config v2` surface, then define a non-legacy target model
**Scope:** authentication decision flow, pre-auth controls, backend/subject-source outcomes, Lua-triggered decisions, auth-FSM integration, decision reporting
**Out of scope:** implementing the layer described here

---

## 1. Executive Summary

This document is a **state-aligned design specification**, not an implementation plan disguised as architecture prose.

Its job is:

1. to describe the **current** Nauthilus configuration and runtime constraints correctly;
2. to define the target Policy Decision Layer in a way that starts from the current `config v2`, current auth flow, current FSM, and current configuration UX;
3. to provide an implementation-ready migration strategy for a large, behavior-preserving refactor.

The target architecture has no separate legacy decision pipeline. Compatibility with current behavior is expressed as a built-in default policy set. If an operator does not define custom policies, Nauthilus still evaluates requests through the policy layer, using that built-in default policy set to reproduce the current external behavior.

The most important target constraints are:

1. the public configuration model is now `runtime`, `observability`, `storage`, `auth`, `identity`;
2. historical roots such as `brute_force`, `realtime_blackhole_lists`, `relay_domains`, `cleartext_networks`, `lua`, `ldap`, and `idp` are **not** the public configuration surface anymore;
3. the policy block must therefore **not** introduce a new top-level root such as `policy_engine`;
4. `brute_force.learning` is still part of the current public model as `auth.controls.brute_force.learning`;
5. brute-force enforcement currently does **not** have a dedicated `AuthResultFeatureBruteForce` or dedicated auth-FSM event, so the target model must add a first-class pre-auth policy/FSM path instead of keeping brute force as an exception;
6. synchronous Lua actions currently execute as mechanism-owned side effects after feature or brute-force triggers, but the target model must make such decision-dependent side effects policy-owned obligations;
7. new configuration in Nauthilus must now integrate with the canonical `mapstructure` schema, structured `ConfigProblem` reporting, and `-d` / `-n` / `-P` config dump behavior.

The central architectural rule of this specification is:

> The target Policy Decision Layer must extend the current `auth` model and current runtime orchestration. It must not regress the public configuration model back to pre-v2 roots. It must become the normal internal decision path, including for the built-in default policy set that preserves current behavior when no custom policy is configured.

---

## 2. Current-State Baseline

### 2.1 Current Public Configuration Surface

The current public configuration model is the `config v2` root layout:

```yaml
runtime:
observability:
storage:
auth:
identity:
```

For the policy/decision topic, the relevant current public paths are:

```yaml
auth:
  request:
    headers:

  backchannel:
    basic_auth:
    oidc_bearer:

  pipeline:
    max_concurrent_requests:
    max_login_attempts:
    wait_delay:
    local_cache_ttl:
    password_history:
      max_entries:
    master_user:

  backends:
    order:
    ldap:
      default:
      pools:
      search:
    lua:
      backend:
        default:
        named_backends:
        search:

  controls:
    enabled:
    tls_encryption:
      allow_cleartext_networks:
    rbl:
      threshold:
      lists:
      ip_allowlist:
    relay_domains:
      static:
      allowlist:
    brute_force:
      protocols:
      ip_allowlist:
      buckets:
      learning:
      custom_tolerations:
      ip_scoping:
      allowlist:
      tolerate_ttl:
      rwp_window:
      rwp_allowed_unique_hashes:
      tolerate_percent:
      min_tolerate_percent:
      max_tolerate_percent:
      scale_factor:
      adaptive_toleration:
      pw_history_for_known_accounts:
    lua:
      hooks:

  policy:
    attribute_sources:
      lua:
        environment:
        subject:
    obligation_targets:
      lua:
        actions:

  services:
    enabled:
    backend_health_checks:
      targets:
```

Important consequences:

1. `auth.controls.rbl` is the public home of the RBL feature.
2. `auth.controls.relay_domains` is the public home of relay-domain checks.
3. `auth.controls.brute_force` is the public home of brute-force configuration.
4. `auth.policy.attribute_sources.lua.environment`, `auth.policy.attribute_sources.lua.subject`, and `auth.policy.obligation_targets.lua.actions` are the public homes of Lua-based auth-time decision logic.
5. `auth.controls.lua.hooks` exists, but hooks are custom HTTP endpoints and are **not** automatically part of the auth decision flow.
6. `auth.services.backend_health_checks` is a background/runtime service, not an auth decision control.

### 2.2 Historical Names Still Exist Only as Internal Materialization

Nauthilus still materializes internal historical sections such as:

- `Server`
- `RBLs`
- `ClearTextList`
- `RelayDomains`
- `BackendServerMonitoring`
- `BruteForce`
- `Lua`
- `LDAP`
- `IDP`

That internal materialization exists to preserve existing runtime call sites while the public configuration surface is already `v2`.

This matters for the spec:

1. the target policy layer may temporarily read from those internal materialized sections in implementation phases;
2. it must **not** treat those sections as the target public configuration model.

### 2.3 Current Configuration UX and Validation Constraints

Nauthilus has a strong config UX contract that the policy layer must preserve.

Current properties:

1. `mapstructure` tags define the canonical external configuration names.
2. unknown keys, decode errors, and validation errors are formatted as structured `ConfigProblem`s.
3. the schema is introspected centrally via the config schema index.
4. canonical dump commands exist:
   - `--config-check`
   - `-d` for canonical defaults
   - `-n` for canonical non-defaults
   - `-P` to print sensitive values in dump output
5. dump output is path-based and stable.
6. sensitive values are redacted by default.

Therefore target policy configuration must:

1. use explicit `mapstructure` tags everywhere;
2. integrate with structured config problem reporting;
3. participate in `-d` / `-n` output;
4. respect redaction for secrets and sensitive report fields;
5. avoid reintroducing implicit naming or historical alias sprawl.

### 2.4 Current Runtime Execution Model

The current auth decision flow is not one monolithic pipeline with one single control abstraction. There are at least two relevant execution surfaces:

1. the classic protection path, where brute force is evaluated early and can directly reject before later feature checks;
2. the auth-backchannel FSM path, where feature results and password results are mapped into auth-FSM events and terminal states.

This distinction matters because all target pre-auth checks must eventually map cleanly into the auth-FSM even though they do not all do that today.

### 2.5 Current Feature Flow

`HandleFeatures` currently evaluates, in order:

1. Lua environment sources
2. TLS enforcement
3. relay domains
4. RBL

It returns current `AuthResult` values such as:

```text
AuthResultOK
AuthResultTempFail
AuthResultUnset
AuthResultFeatureLua
AuthResultFeatureTLS
AuthResultFeatureRelayDomain
AuthResultFeatureRBL
```

`processFeatureAction` currently:

1. sets `Runtime.FeatureName`;
2. checks `auth.controls.brute_force.learning`;
3. calls `UpdateBruteForceBucketsCounter` when learning is enabled for the triggered feature;
4. dispatches the matching Lua action.

This is a current-state fact, not a target ownership rule. In the target model, feature checks must emit facts first. Any synchronous Lua action and related learning update that depends on the selected outcome must be requested by the winning policy decision through registered obligations.

### 2.6 Current Brute-Force Path

Brute force is already a first-class runtime control, but its execution shape is different from the feature-result model above.

Current properties:

1. the current public config is `auth.controls.brute_force`;
2. `auth.controls.brute_force.learning` is part of the public schema;
3. learning names use current feature/control names such as:
   - `lua`
   - `relay_domains`
   - `rbl`
   - `brute_force`
4. the current runtime has `CheckBruteForce(ctx) bool`, not a dedicated `AuthResultFeatureBruteForce`;
5. in the classic path, brute force can directly trigger `AuthFail` without first becoming a feature-stage `AuthResult`;
6. brute force updates also happen after failed backend/password evaluation.

This is one of the most important reality constraints for the target policy-layer design.

The target model must split those responsibilities:

1. brute-force evaluation emits check facts;
2. the selected policy decision chooses the terminal effect and FSM marker;
3. `auth.obligation.brute_force.update` owns counter, toleration, and learning updates;
4. `auth.obligation.lua_action.dispatch` owns synchronous `brute_force` action dispatch when the selected policy requires it;
5. `auth.obligation.lua_post_action.enqueue` owns Lua POST-Action enqueueing when the selected policy requires it.

### 2.7 Current Auth-FSM

The current auth-FSM defines these states:

```text
init
input_parsed
features_checked
password_checked
auth_ok
auth_fail
auth_tempfail
aborted
```

It defines these events:

```text
parse_ok
parse_fail
features_ok
features_fail
features_tempfail
features_unset
password_evaluated
password_ok
password_fail
password_tempfail
password_empty_user
password_empty_pass
basic_auth_ok
basic_auth_fail
abort
```

Current mapping in the auth-backchannel path:

- `AuthResultFeatureTLS` -> `features_tempfail`
- `AuthResultFeatureRelayDomain` -> `features_fail`
- `AuthResultFeatureRBL` -> `features_fail`
- `AuthResultFeatureLua` -> `features_fail`
- `AuthResultUnset` -> `features_unset`
- `AuthResultOK` -> `features_ok`
- `AuthResultTempFail` -> `features_tempfail`

And later:

- `AuthResultOK` -> `password_ok`
- `AuthResultFail` -> `password_fail`
- `AuthResultTempFail` -> `password_tempfail`
- `AuthResultEmptyUsername` -> `password_empty_user`
- `AuthResultEmptyPassword` -> `password_empty_pass`

The current FSM is therefore already a real orchestration boundary for at least one auth flow, and the target decision layer must integrate with it instead of bypassing it.

---

## 3. Target Scope Boundaries

The target policy layer must keep several boundaries explicit.

### 3.1 Outdated Public Config Roots

The target public policy surface must not use root-level examples such as:

```yaml
brute_force:
realtime_blackhole_lists:
relay_domains:
policy_engine:
```

That is no longer aligned with the current public model.

Correct current public paths are:

```yaml
auth.controls.brute_force
auth.controls.rbl
auth.controls.relay_domains
auth.controls.tls_encryption
auth.controls.lua
auth.backends.ldap
auth.backends.lua.backend
```

### 3.2 `policy_engine` as a New Top-Level Root Is Not a Good Fit Anymore

After the `config v2` reorganization, a new top-level `policy_engine` root would work against the current human-facing structure.

The policy/decision topic is clearly an authentication concern and belongs under `auth`, not beside `runtime`, `storage`, or `identity`.

This specification uses:

```yaml
auth:
  policy:
```

as the target placement.

### 3.3 Brute Force Must Not Be Oversimplified

The target model must not treat brute force as if it already fit the same `feature -> AuthResultFeatureX -> features_* event` path as TLS, relay domains, RBL, and Lua environment sources.

That is not true today.

Current reality:

1. brute force has no `AuthResultFeatureBruteForce`;
2. brute force has no dedicated auth-FSM event;
3. brute force is partly a direct early gate, not only a feature-stage result.

So the target policy layer must explicitly introduce a first-class pre-auth decision path for brute force instead of keeping brute force outside the policy/FSM orchestration.

### 3.4 Public Names Must Not Be Mixed With Historical Names

Names that must not appear in the target public policy surface:

1. `realtime_blackhole_lists` as the public config reference name
2. `relay_domains.static_domains` as the public path
3. `lua.features` as the public path
4. `soft_whitelist` as a public allowlist name

Current public names are:

1. `auth.controls.rbl`
2. `auth.controls.relay_domains.static`
3. `auth.policy.attribute_sources.lua.environment`
4. `allowlist`

### 3.5 Hooks Must Not Be Accidentally Treated as Auth Decision Checks

`auth.controls.lua.hooks` are custom HTTP endpoints. They are not equivalent to:

1. Lua environment sources
2. Lua subject sources
3. Lua actions

Hooks can remain in the broader Lua surface, but they are not part of the primary authentication decision layer and must not be modeled as ordinary auth-time checks.

Hooks may still influence later auth decisions indirectly through normal shared storage such as Redis, caches, or external databases. For example, a custom hook may maintain administrative state or reputation data, and a later request-time Lua environment source or Lua subject source may read that state and emit registered policy attributes.

This indirect pattern is allowed only with a request-time check as the policy boundary:

1. the hook updates external state outside the current auth request;
2. a configured request-time check reads that state during the normal policy check plan;
3. the check emits registered attributes into the current `DecisionContext`;
4. YAML policies decide from those attributes.

Hooks must not be modeled as:

1. `require_checks` dependencies;
2. synchronous callbacks inside an active auth request;
3. direct mutators of the current `DecisionContext`;
4. request-time attribute registry mutators;
5. final policy decision makers.

If Nauthilus later needs remote request-time enrichment, it must be introduced as an explicit check type with stage, operation, timeout, error attributes, observe-safety rules, and reporting semantics. It must not be smuggled through Lua hooks.

### 3.6 The Config UX Contract Applies To Policy

The policy layer must assume:

1. canonical config paths from `mapstructure`;
2. structured `ConfigProblem` reporting;
3. schema-index awareness;
4. canonical dump support for defaults and non-defaults;
5. sensitive-value redaction.

---

## 4. Goals

The target Policy Decision Layer must:

1. make existing auth decisions explicit and reportable;
2. preserve current semantics for brute force, TLS enforcement, relay domains, RBL, Lua environment sources, Lua subject sources, backend results, and Lua post actions;
3. integrate with the current auth-FSM where the FSM is already authoritative;
4. represent current pre-auth and auth-stage outcomes as structured check results;
5. allow operator policies to interpret those check results without rewriting the underlying mechanisms;
6. preserve current configuration naming and grouping principles introduced by `config v2`;
7. fit into the current config UX contract: schema index, structured errors, config dump, redaction;
8. support incremental rollout modes such as built-in default, observe, and enforce;
9. keep built-in default behavior reproducible by tests;
10. make decision-dependent side effects, including synchronous Lua action dispatch, explicit and reportable through registered obligations;
11. improve auditability without forcing an immediate rewrite of existing installations.

---

## 5. Non-Goals

The first policy-layer rollout is explicitly **not** intended to:

1. replace the brute-force subsystem;
2. change brute-force Redis semantics or bucket logic;
3. replace LDAP or Lua backends;
4. replace the current Lua environment/subject source execution model;
5. make Lua hooks part of the core auth decision path;
6. introduce a generic top-level policy root outside `auth`;
7. reintroduce historical public root sections;
8. make the auth-FSM transition table admin-editable in YAML;
9. force existing configs to define explicit policies on day one;
10. treat `neutral` as implicit `permit`;
11. keep a separate legacy decision pipeline as part of the target architecture;
12. cover IdP-specific provider policies, client authorization policies, consent decisions, claim-release policies, or protocol-level trust decisions;
13. turn `auth.policy` into a general identity-management or provider-policy framework.

The first phases may preserve synchronous Lua action dispatch as a temporary compatibility adapter. That adapter is not the target architecture. Decision-owned synchronous Lua action dispatch is in scope for a dedicated migration phase.

---

## 6. Design Constraints Imposed by the Current Architecture

### 6.1 Config Placement Constraint

Policy configuration must live under:

```yaml
auth:
  policy:
```

and not under a new top-level root.

### 6.2 Schema Constraint

All policy config structs must:

1. define explicit `mapstructure` tags for every user-facing field;
2. use `mapstructure:"-"` for internal-only fields;
3. participate in the schema index;
4. produce canonical config paths in user-facing errors.

### 6.3 Error UX Constraint

Policy config errors must become standard `ConfigProblem`s:

1. unknown keys -> canonical unknown-key problem
2. decode/type problems -> canonical decode problem
3. invalid policy semantics -> canonical validation problem

### 6.4 Dump Constraint

Policy config must participate in:

1. `nauthilus -d`
2. `nauthilus -n`
3. `nauthilus -P`

That means defaults, non-defaults, and redaction rules must be intentionally defined.

### 6.5 Runtime Constraint

The target policy layer must normalize the current execution paths into one policy-driven decision model.

The current implementation has:

1. the existing auth-backchannel FSM path;
2. the older direct gating flow where brute force can fail before a feature-stage `AuthResult` exists.

The target implementation must not keep that split as a permanent architectural property. The policy layer must become the common decision boundary. Current direct gates, including brute force, must become check evaluators that feed policy decisions and FSM events.

### 6.6 Naming Constraint

Target public config must use current names:

1. `rbl`, not `realtime_blackhole_lists`
2. `allowlist`, not `soft_whitelist`
3. `auth.policy.attribute_sources.lua.environment`, not `lua.features`
4. `auth.backends.lua.backend`, not `lua.config`

Historical names may still appear internally during migration, but not as the target public spec surface.

---

## 7. Target Config Placement

### 7.1 Proposed Placement

The target placement is:

```yaml
auth:
  policy:
    mode:
    default_policy:
    sets:
    report:
    checks:
    policies:
```

Rationale:

1. the concerns are authentication-specific;
2. the current public model groups auth concerns under `auth`;
3. it avoids introducing a new root that would weaken the `config v2` information architecture.

### 7.2 Minimal Target Skeleton

```yaml
auth:
  controls:
    enabled:
      - brute_force
      - tls_encryption
      - relay_domains
      - rbl
      - lua

    brute_force:
      protocols: []
      ip_allowlist: []
      buckets: []
      learning: []

    tls_encryption:
      allow_cleartext_networks: []

    relay_domains:
      static: []

    rbl:
      threshold: 0
      lists: []
      ip_allowlist: []

    lua:
      hooks: []

  policy:
    mode: enforce
    default_policy: standard_auth
    registry_scripts: []
    attribute_sources:
      lua:
        environment: []
        subject: []
    obligation_targets:
      lua:
        actions: []

    sets:
      networks: {}
      time_windows: {}

    report:
      enabled: false
      include_fsm: true
      include_checks: true
      include_attributes: false

    checks: []
    policies: []
```

This keeps the existing mechanism-owning blocks authoritative and lets the policy layer reference them.

If `auth.policy` is omitted, the runtime behaves as if the following policy header had been configured:

```yaml
auth:
  policy:
    mode: enforce
    default_policy: standard_auth
```

`standard_auth` is a built-in policy set that reproduces the current external behavior through the policy engine. It is not a separate legacy pipeline.

### 7.3 Policy Modes

The policy layer supports two runtime modes:

1. `enforce`;
2. `observe`.

In `enforce` mode, the active policy result is authoritative. Enforcement applies the selected decision, FSM event marker, response marker, response message, obligations, and advice from that policy evaluation.

In `observe` mode, the built-in `default_policy` remains authoritative. Custom policy evaluation runs in parallel and produces only comparison data.

Observe-mode rules:

1. the default policy decides the production response;
2. the custom policy must not execute obligations;
3. the custom policy must not enqueue Lua POST-Actions;
4. the custom policy must not dispatch synchronous Lua actions;
5. the custom policy must not update counters, brute-force learning state, or other mutable side-effect state;
6. the custom policy may produce decision reports and logs;
7. mismatch comparison must include effect, selected policy name, outcome marker, FSM event marker, response marker, response-message source, rendered sanitized response message, planned obligations, and terminal state;
8. report configuration may support an option such as `observe_mismatches_only` to reduce log volume;
9. the authoritative default-policy check plan runs normally;
10. the custom policy may reuse attributes and check results produced by the authoritative default-policy check plan;
11. checks that are needed only by the custom policy may run in observe mode only when they are observe-safe;
12. a check is observe-safe when its check-type registry marks it as safe, or when the concrete check configuration explicitly sets `observe_safe: true` for a check type that allows operator assertion;
13. observe-safe checks must not mutate external state, update counters, enqueue POST-Actions, dispatch synchronous Lua actions, alter request-visible state, or depend on irreversible side effects;
14. Lua environment and subject sources are not observe-safe by default, because the engine cannot prove that arbitrary Lua code is side-effect free;
15. custom-only checks that are not observe-safe are not executed in observe mode;
16. attributes that would have been produced only by a non-observe-safe custom-only check are unavailable to the custom policy and must be reported as unavailable;
17. `unavailable` is a decision-report availability state, not a `CheckResult.status` value.

For Lua checks, `observe_safe: true` is an explicit operator assertion. The engine validates that the Lua check type permits such an assertion, but it cannot prove arbitrary Lua code is side-effect free.

During migration, an internal observe-like path may also compare the current implementation against the built-in `standard_auth` policy. That is a temporary migration verification mechanism, not a separate target decision pipeline.

### 7.4 Policy Attribute Boundary

The policy layer must not expose Go enum names, internal struct names, or current implementation details as the stable YAML contract.

The target model therefore uses **Policy Attributes** as the stable XACML-aligned boundary for request-time facts.

The public model is aligned with XACML attributes:

1. a policy attribute has a stable ID;
2. a policy attribute has a phase;
3. a policy attribute has a type;
4. a policy attribute may have typed details;
5. a policy attribute has an English description;
6. a policy attribute may be emitted by built-ins or Lua;
7. a policy attribute is evaluated by policies.

Attribute details may use a compact type-only form or an expanded metadata form. The expanded form is required when a detail is allowed to influence the client-visible response message.

Example built-in attribute definitions:

```yaml
- id: auth.brute_force.triggered
  phase: pre_auth
  operations: [authenticate]
  category: environment
  type: bool
  description: Brute-force protection matched the current request.
  details:
    rule: string
    client_net: cidr
    repeating: bool

- id: auth.rbl.threshold_reached
  phase: pre_auth
  operations: [authenticate, lookup_identity]
  category: environment
  type: bool
  description: RBL evaluation reached the configured rejection threshold.
  details:
    lists: string_list

- id: auth.rbl.error
  phase: pre_auth
  operations: [authenticate, lookup_identity]
  category: environment
  type: bool
  description: RBL evaluation failed due to a technical runtime error.
  details:
    reason_code:
      type: string
      sensitivity: internal
    retryable:
      type: bool
      sensitivity: internal

- id: auth.tls.secure
  phase: pre_auth
  operations: [authenticate, lookup_identity]
  category: environment
  type: bool
  description: The request arrived over an accepted TLS path.

- id: request.time.now
  phase: pre_auth
  operations: [authenticate, lookup_identity, list_accounts]
  category: environment
  type: datetime
  description: The request evaluation timestamp captured once for the current DecisionContext.

- id: auth.lua.environment.geo_block.triggered
  phase: pre_auth
  operations: [authenticate]
  category: environment
  type: bool
  description: The named Lua environment source rejected the current request.
  details:
    status_message:
      type: string
      sensitivity: public
      purpose: response_message
      max_length: 256

- id: auth.lua.environment.geo_block.abort
  phase: pre_auth
  operations: [authenticate]
  category: environment
  type: bool
  description: The named Lua environment source requested that remaining pre-auth checks be skipped.

- id: auth.lua.environment.geo_block.error
  phase: pre_auth
  operations: [authenticate]
  category: environment
  type: bool
  description: The named Lua environment source failed due to a technical runtime error.
  details:
    reason_code:
      type: string
      sensitivity: internal

- id: auth.lua.subject.billing_lock.rejected
  phase: subject_analysis
  operations: [authenticate]
  category: subject
  type: bool
  description: The named Lua subject source rejected an otherwise evaluated request.
  details:
    status_message:
      type: string
      sensitivity: public
      purpose: response_message
      max_length: 256

- id: auth.lua.subject.billing_lock.error
  phase: subject_analysis
  operations: [authenticate]
  category: subject
  type: bool
  description: The named Lua subject source failed due to a technical runtime error.
  details:
    reason_code:
      type: string
      sensitivity: internal

- id: auth.identity.found
  phase: auth_backend
  operations: [lookup_identity]
  category: subject
  type: bool
  description: Backend identity lookup found the requested user without password verification.

- id: auth.backend.tempfail
  phase: auth_backend
  operations: [authenticate, lookup_identity]
  category: resource
  type: bool
  description: Backend evaluation failed due to a temporary technical runtime error.
  details:
    backend:
      type: string
      sensitivity: internal
    reason_code:
      type: string
      sensitivity: internal
    retryable:
      type: bool
      sensitivity: internal

- id: auth.account_provider.completed
  phase: account_provider
  operations: [list_accounts]
  category: resource
  type: bool
  description: Account-provider evaluation completed and produced an account list; the list may be empty.
  details:
    count: number

- id: auth.account_provider.tempfail
  phase: account_provider
  operations: [list_accounts]
  category: resource
  type: bool
  description: Account-provider evaluation failed temporarily.
```

The account list itself is response data. It must not automatically become a policy attribute because that would make policies depend on potentially large or sensitive result payloads.

Lua environment source and Lua subject source check attributes are generated per named script. The target model must not expose only aggregate attributes such as `auth.lua.environment.triggered` or `auth.lua.subject.rejected`, because aggregate attributes hide which script produced the fact and make `require_checks`, `run_if`, and decision reports ambiguous.

Operation scoping rules for attributes:

1. Go built-in attribute definitions must declare a non-empty `operations` list explicitly.
2. Lua registry-script attribute definitions may omit `operations`; omission compiles to `[authenticate]`.
3. Explicit empty `operations: []` is invalid for all attribute definitions.
4. Every listed operation must exist in the operation registry.
5. A request-time emitter may emit an attribute only in one of the attribute's declared operations and only in the declared phase.
6. A policy may reference an attribute only from operations where the attribute can be emitted.

This keeps built-in metadata precise while keeping Lua registration safe and admin-friendly. A Lua-defined attribute intended for `lookup_identity` or `list_accounts` must opt in explicitly.

Expanded detail metadata example:

```yaml
- id: lua.billing.account_locked
  phase: subject_analysis
  category: subject
  type: bool
  description: The account is locked by a local billing policy.
  details:
    reason:
      type: string
      sensitivity: internal
    status_message:
      type: string
      sensitivity: public
      purpose: response_message
      max_length: 256
```

These definitions are not normal operator YAML. Built-in attribute definitions are registered by Go code.

Runtime emissions are values for registered attributes:

```yaml
attributes:
  auth.brute_force.triggered:
    value: true
    details:
      rule: imap_login
      client_net: 203.0.113.0/24
      repeating: true

  auth.rbl.threshold_reached:
    value: true
    details:
      lists: [spamhaus_zen]

  auth.tls.secure:
    value: false

  auth.lua.subject.billing_lock.rejected:
    value: true
    details:
      status_message: "Your account is locked; unpaid invoice"
```

Markers remain useful for policy outputs, not inputs:

1. `outcome_marker`;
2. `fsm_event_marker`;
3. `response_marker`.

These are Nauthilus output markers selected by policy decisions. They are not policy attributes.

Client-visible status messages are also policy outputs. They must either come from a registered response marker or from an explicitly selected public response-message detail. Lua may emit a message candidate as an attribute detail, but Lua does not directly select the final response message in the target model.

### 7.5 Built-In Attribute Registry

Go built-ins must be registered in an internal Policy Attribute Registry.

The registry is authoritative for:

1. built-in attribute IDs;
2. phase ownership;
3. operation ownership;
4. category and type information;
5. detail names and detail types;
6. descriptions;
7. detail metadata such as sensitivity, purpose, and maximum length;
8. the built-in emitter that is allowed to emit the attribute.

Operator YAML must not redefine built-in attributes. YAML policies reference registered attribute IDs only.

The effective registry used for policy validation is:

```text
Go built-in attributes
  + Lua registry-script attributes
  = effective policy attribute registry
```

The effective registry is not a process-global mutable singleton. It is built as part of an immutable policy runtime snapshot.

Request-time code may emit registered attribute values, but it must not register new attributes.

### 7.6 Lua Attribute Registry Scripts

Lua-provided policy attribute definitions must come from a dedicated configurable registry script surface, not from general Lua init scripts.

This keeps lifecycle semantics separate:

1. Lua registry scripts define attribute metadata;
2. Lua environment and subject sources emit registered attributes during request evaluation;
3. general Lua initialization remains for normal runtime setup.

Proposed config placement:

```yaml
auth:
  policy:
    registry_scripts:
      - /etc/nauthilus/policy/attributes.lua
```

The registry script runs during policy runtime snapshot construction after Go built-ins have been registered and before policy validation. This happens at startup and on every policy/config reload. It must not depend on a request context and must not emit request-time values.

Example registry script:

```lua
nauthilus_policy.register_attribute({
  id = "lua.geo.country_blocked",
  phase = "pre_auth",
  category = "environment",
  type = "bool",
  description = "Client country is blocked by local policy",
  details = {
    country = "string",
    source = "string",
  },
})
```

Because this Lua definition omits `operations`, it is compiled as `operations = { "authenticate" }`.

Lua registry scripts may explicitly opt in to other operations:

```lua
nauthilus_policy.register_attribute({
  id = "lua.account_provider.suppressed",
  phase = "account_provider",
  operations = { "list_accounts" },
  category = "resource",
  type = "bool",
  description = "Local Lua policy suppressed account listing",
})
```

Lua registry scripts may also declare response-message hints. A response-message hint is not a decision and is not automatically sent to the client. It is a typed attribute detail that a policy may later select:

```lua
nauthilus_policy.register_attribute({
  id = "lua.billing.account_locked",
  phase = "subject_analysis",
  category = "subject",
  type = "bool",
  description = "The account is locked by a local billing policy",
  details = {
    reason = {
      type = "string",
      sensitivity = "internal",
    },
    status_message = {
      type = "string",
      sensitivity = "public",
      purpose = "response_message",
      max_length = 256,
    },
  },
})
```

Request-time Lua environment or subject sources may then emit registered values:

```lua
nauthilus_policy.emit_attribute("lua.geo.country_blocked", true, {
  country = "RU",
  source = "geoip",
})
```

```lua
nauthilus_policy.emit_attribute("lua.billing.account_locked", true, {
  reason = "unpaid_invoice",
  status_message = "Your account is locked; unpaid invoice",
})
```

Registration must validate:

1. ID uniqueness;
2. phase validity;
3. operation validity;
4. type validity;
5. detail type validity;
6. detail metadata validity;
7. duplicate built-in ID conflicts;
8. whether the declaring registry script is allowed to declare the requested phase and operations.

Policies that reference Lua-defined attributes can only be validated after Lua registry scripts have completed. The implementation therefore needs a policy-validation step that runs after Go built-ins and registry scripts have populated the effective registry for the new snapshot.

### 7.7 Policy Runtime Snapshot and Atomic Reload

The policy layer must use an immutable snapshot model.

Startup and reload use the same build pipeline:

```text
operation registry
  -> Go built-in registry
  -> Lua registry scripts
  -> effective policy attribute registry
  -> policy YAML validation
  -> policy AST
  -> typed stage plans
  -> immutable PolicyRuntimeSnapshot
  -> atomic activation
```

The active snapshot contains:

1. the effective Policy Attribute Registry;
2. compiled stage check plans;
3. compiled policies;
4. response-marker and response-message metadata;
5. obligation and advice definitions;
6. FSM event marker metadata;
7. registered operation metadata;
8. report settings;
9. a monotonically changing version or generation identifier.

Activation rules:

1. a snapshot is immutable after it has been built;
2. request-time evaluation reads exactly one active snapshot;
3. running requests keep using the snapshot they started with;
4. reload builds a complete candidate snapshot without mutating the active one;
5. only a fully valid candidate snapshot may replace the active snapshot;
6. if reload fails, the old snapshot remains active and request handling continues with the old behavior;
7. request-time Lua may emit only attributes registered in the active snapshot;
8. request-time Lua must never register attributes or mutate registry metadata.

This is a hard target requirement, not an optional optimization. It preserves the existing reload expectation: a broken policy or registry change must not partially apply and must not leave the process with a half-valid decision layer.

---

## 8. Proposed Runtime Model

### 8.1 `DecisionContext`

```go
type DecisionContext struct {
    Stage        Stage
    Request      *RequestView
    Auth         *AuthView
    Runtime      *RuntimeView
    FSM          *FSMView

    Attributes   map[string]PolicyAttributeValue
    Checks       map[string]CheckResult
    Decisions    []PolicyDecision

    DefaultPolicy *DefaultPolicyContext
}
```

Intent:

1. expose current request/auth/runtime state to checks and policies;
2. collect structured policy attributes and check results;
3. preserve the built-in default policy context that reproduces current behavior when no custom policy is configured.

### 8.2 `PolicyRuntimeSnapshot`

The request-time policy engine must receive an immutable runtime snapshot rather than reading mutable global configuration.

```go
type PolicyRuntimeSnapshot struct {
    AttributeRegistry *PolicyAttributeRegistry
    StagePlans      map[Stage]CompiledStagePlan
    ResponseRegistry *ResponseRegistry
    ObligationRegistry *ObligationRegistry
    FSMEventRegistry *FSMEventRegistry
    OperationRegistry *OperationRegistry
    Report          ReportConfig
    Generation      uint64
}
```

Runtime use:

1. each request obtains the active snapshot once near the beginning of auth processing;
2. all checks, policy evaluation, response selection, and reporting use that same snapshot;
3. reload publishes a new snapshot atomically;
4. no request observes a partially rebuilt registry or policy plan.

The exact implementation may use `atomic.Value`, `atomic.Pointer`, or an equivalent synchronization primitive, but the semantic contract is immutable snapshot activation.

### 8.3 `ResponseRegistry`

The response registry maps policy response markers to transport-specific rendering profiles.

```go
type ResponseDefinition struct {
    ID             string
    Effect         Decision
    DefaultMessage string
    Profiles       map[ResponseSurface]ResponseProfile
}
```

```go
type ResponseProfile struct {
    Surface      ResponseSurface
    StatusCode   int
    BodyMode     ResponseBodyMode
    HeaderMode   ResponseHeaderMode
    GRPCCode     string
    IDPFlowMode  IDPFlowMode
}
```

The exact field set may evolve during implementation, but the semantic contract is fixed:

1. `response_marker` selects a registered response class;
2. the response registry renders that class for the current response surface;
3. `response_message` may override only the client-visible message within that class;
4. policy YAML must not set raw HTTP headers, raw HTTP status codes, raw gRPC status codes, or IdP protocol fields directly.

Required response surfaces for the first complete implementation:

1. HTTP JSON auth response;
2. HTTP CBOR auth response;
3. Nginx auth-request style response;
4. header-style HTTP auth response;
5. plain HTTP auth response;
6. gRPC AuthService response;
7. HTTP list-accounts response;
8. gRPC ListAccounts response;
9. IdP browser login and MFA flows;
10. IdP OIDC protocol flows;
11. IdP SAML protocol flows;
12. IdP device-code flow.

Normal authentication denials and temporary failures must be rendered as normal auth decisions on these surfaces. They must not become transport-level errors unless the failure is actually a transport, caller-authentication, or internal server error.

### 8.4 `PolicyAttributeDefinition` and `PolicyAttributeValue`

```go
type PolicyAttributeDefinition struct {
    ID          string
    Phase       Stage
    Operations  []Operation
    Category    AttributeCategory
    Type        AttributeType
    Description string
    Details     map[string]AttributeDetailDefinition
    Source      AttributeSource
}
```

```go
type AttributeDetailDefinition struct {
    Type        AttributeType
    Sensitivity AttributeSensitivity
    Purpose     AttributeDetailPurpose
    MaxLength   int
}
```

```go
type PolicyAttributeValue struct {
    ID      string
    Phase   Stage
    Operation Operation
    Value   any
    Details map[string]any
    Source  AttributeSource
}
```

The definition belongs to the registry. The value belongs to one request evaluation.

### 8.5 `CheckResult`

```go
type CheckResult struct {
    Name         string
    Type         string
    Stage        Stage

    Status       CheckStatus
    Matched      bool
    DecisionHint Decision
    Reason       string

    Attributes   map[string]PolicyAttributeValue
    Tags         []string
    Control      CheckControl

    OutcomeMarker string
    Err           error
}
```

Required check status semantics:

1. `ok`: the check ran and completed without a technical runtime error;
2. `skipped`: the compiled scheduler did not run the check because the active operation or the check's own `run_if` guard did not select it;
3. `error`: the check attempted to run and failed due to a technical runtime error.

Observe-mode custom-only checks that are not observe-safe must not add a fourth check status. They are not executed and are reported as unavailable in the observe report. If a custom policy lists such a check in `require_checks`, the required check result is missing for that custom evaluation and the policy is non-applicable.

`skipped` is not a dependency-cascade status. If a check is selected by operation and `run_if`, it must either run and produce `ok`, or fail as `error`.

Technical check errors are normal policy inputs. A check with `Status=error` must also emit one or more registered error attributes when the error belongs to the modeled auth decision flow. Examples include `auth.rbl.error`, `auth.lua.environment.<name>.error`, `auth.backend.tempfail`, and `auth.account_provider.tempfail`.

The policy engine must not silently convert normal check errors into final decisions. The built-in `standard_auth` policy maps these error attributes to the current external tempfail behavior. Custom policies may match the same registered attributes explicitly.

`Err` is internal diagnostic data. Decision reports may include only sanitized reason codes or registered internal details according to the report safety rules; they must not expose raw exception strings, stack traces, connection strings, bind credentials, tokens, or other secrets.

Only failures that prevent the policy engine from producing a valid `CheckResult` or evaluating a compiled plan at all remain engine-core failures. Those failures must fail closed with a tempfail response and an internal reason.

### 8.6 `PolicyDecision`

```go
type PolicyDecision struct {
    PolicyName    string
    Stage         Stage
    Effect        Decision
    Reason        string

    OutcomeMarker  string
    FSMEventMarker string
    ResponseMarker string
    ResponseMessage *ResponseMessageSelection

    Obligations []ObligationRequest
    Advice      []AdviceRequest
    Control     DecisionControl
}
```

```go
type ResponseMessageSelection struct {
    Source       ResponseMessageSource
    Message      string
    AttributeID  string
    Detail       string
    Fallback     string
    FallbackUsed bool
}
```

### 8.7 `DecisionReport`

```go
type DecisionReport struct {
    SessionID   string
    Stage       Stage
    Attributes  map[string]PolicyAttributeValue
    Checks      map[string]CheckResult
    Policies    []PolicyDecision
    Final       FinalDecision
    FSM         *FSMReport
    Observe     *ObserveReport
}
```

The report is a runtime/reporting object, not automatically a public API contract.

In observe mode, `ObserveReport` records custom-policy comparison data and check availability for custom-only facts. A non-observe-safe custom-only check is recorded as unavailable with a sanitized reason such as `not_observe_safe`. This is intentionally separate from `CheckResult.status` so runtime check semantics stay limited to `ok`, `skipped`, and `error`.

### 8.8 Policy AST and Compilation Pipeline

The YAML policy language must not be interpreted directly at request time.

The implementation must use a small internal policy AST and a typed compilation pipeline:

```text
YAML decode
  -> config structs
  -> operation registry
  -> Go built-ins plus Lua registry scripts
  -> effective Policy Attribute Registry
  -> structural validation
  -> policy AST
  -> registry-aware type checking
  -> compiled stage plans
  -> immutable PolicyRuntimeSnapshot
  -> request-time evaluation
```

This keeps the language small while giving Nauthilus compiler-style validation, predictable runtime behavior, and useful decision reports.

#### Config Struct Layer

The config structs must stay close to YAML and preserve config paths for error reporting:

```go
type PolicyRuleConfig struct {
    Name          string          `mapstructure:"name"`
    Stage         string          `mapstructure:"stage"`
    Operations    []string        `mapstructure:"operations"`
    RequireChecks []string        `mapstructure:"require_checks"`
    If            ConditionConfig `mapstructure:"if"`
    Then          ThenConfig      `mapstructure:"then"`
}
```

```go
type PolicyCheckConfig struct {
    Name       string      `mapstructure:"name"`
    Type       string      `mapstructure:"type"`
    Stage      string      `mapstructure:"stage"`
    Operations []string    `mapstructure:"operations"`
    RunIf      RunIfConfig `mapstructure:"run_if"`
    After      []string    `mapstructure:"after"`
    ConfigRef  string      `mapstructure:"config_ref"`
    Output     string      `mapstructure:"output"`
    ObserveSafe *bool      `mapstructure:"observe_safe"`
}
```

```go
type RunIfConfig struct {
    AuthState string `mapstructure:"auth_state"`
}
```

`run_if.auth_state` is the only scheduler dimension in the target model for the initial policy language. Its allowed values are:

1. `authenticated`: run the check only after backend evaluation produced an authenticated request state;
2. `unauthenticated`: run the check only after backend evaluation produced an unauthenticated request state;
3. `any`: run the check regardless of authenticated or unauthenticated request state.

Omitting `run_if.auth_state` is equivalent to `any`. The operation itself must be modeled with `operations`, not with `run_if`. Detailed backend outcomes such as temporary failures, missing identities, locked accounts, or provider-specific states are policy attributes and belong in policy `if` conditions, not in `run_if`.

`operations` scopes checks and policies into compiled operation-specific plans. This is structural orchestration, not a normal policy condition: a check that is not in the active operation plan must not run, and a policy that is not in the active operation plan must not be evaluated.

For checks and policies, omitted `operations` means exactly:

```yaml
operations: [authenticate]
```

This keeps the normal authentication case concise while making `lookup_identity` and `list_accounts` opt-in by explicit configuration. An explicitly empty `operations: []` list is invalid. The request operation may still be exposed as a condition attribute such as `request.operation`, but that attribute must not replace structural operation scoping for check orchestration.

```go
type PolicySetsConfig struct {
    Networks map[string][]string `mapstructure:"networks"`
}
```

This layer must decode YAML and capture source paths. It must not perform request-time evaluation or mutate the active runtime snapshot.

#### AST Layer

The AST must represent the condition tree explicitly:

```go
type Expr interface {
    NodeKind() ExprKind
}
```

```go
type AttributeExpr struct {
    AttributeID string
    Detail      string
    Operator    Operator
    Expected    RawValue
}
```

```go
type AllExpr struct {
    Children []Expr
}
```

```go
type AnyExpr struct {
    Children []Expr
}
```

```go
type NotExpr struct {
    Child Expr
}
```

```go
type AlwaysExpr struct{}
```

The AST must stay intentionally small. The target language is not a general expression language.

Allowed expression node kinds:

1. `attribute`;
2. `all`;
3. `any`;
4. `not`;
5. `always`.

Free-form expression parsers, embedded scripting languages, and string-based boolean expressions must not be introduced for policy YAML.

#### Structural Validation

The AST builder must validate YAML shape before type checking:

1. `if` must contain exactly one expression node;
2. `all` and `any` must contain at least one child;
3. `not` must contain exactly one child;
4. an attribute expression must contain `attribute`;
5. an attribute expression must contain exactly one operator;
6. `detail` may only appear with `attribute`;
7. `always` must not be combined with other condition keys in the same node;
8. `then.response_message` must contain exactly one supported source shape when present.

Errors must point at canonical config paths such as:

```text
auth.policy.policies[2].if.all[1].attribute
auth.policy.policies[2].if.all[1].detail
auth.policy.policies[2].then.fsm_event_marker
```

#### Registry-Aware Type Checking

After Go built-ins and Lua registry scripts have populated the effective Policy Attribute Registry, the compiler must type-check the AST:

1. attribute IDs must exist;
2. detail names must exist on the referenced attribute;
3. the operator must be valid for the selected value type;
4. raw YAML values must convert to typed values before runtime using strict registry-type rules;
5. scalar membership operators must not be used on list-typed values;
6. list membership operators must not be used on scalar values;
7. `matches` must be used only with string attributes or string details;
8. regex patterns must compile during snapshot build;
9. network-set references must resolve to configured policy network sets;
10. every network set entry must compile to a CIDR or IP network value during snapshot build;
11. stage use must be valid for the referenced attribute; a policy may reference attributes emitted in its own stage or an earlier completed stage, but not a future stage;
12. policy operation use must be valid for the referenced attribute and check plan;
13. every `require_checks` entry must resolve to a configured check;
14. same-stage attribute dependencies must have a same-stage `require_checks` entry for the producing check;
15. checks required by a policy must be enabled in the explicit stage check plan for the relevant operation;
16. check names and explicit output names must be unique;
17. `fsm_event_marker` must resolve to a registered FSM event marker;
18. `fsm_event_marker` must be valid for the policy stage;
19. `response_marker` must resolve to a registered response definition;
20. `response_marker` must be compatible with the selected decision effect;
21. every registered response marker used by policy must have profiles for HTTP JSON, HTTP CBOR, Nginx auth-request, header-style HTTP, plain HTTP, HTTP list-accounts, gRPC AuthService, gRPC ListAccounts, and IdP response surfaces;
22. policy conditions must not contain lookup, transform, variable, loop, or scripting constructs;
23. `response_message` attribute references must resolve to a registered attribute detail;
24. `response_message` attribute details must be `string`, `sensitivity: public`, and `purpose: response_message`;
25. response-message literals, fallbacks, and attribute values must satisfy the configured maximum length and response sanitization rules;
26. obligations and advice IDs must resolve to registered built-in enforcement definitions;
27. policy YAML must not define executable obligation logic.

#### Compiled Evaluation Plan

The type checker must produce a compiled policy object that contains no YAML-facing raw values:

```go
type CompiledPolicy struct {
    Name          string
    Stage         Stage
    RequireChecks []string
    Root          CompiledExpr
    Then          DecisionPlan
}
```

```go
type CompiledStagePlan struct {
    Stage    Stage
    Checks   []CompiledCheck
    Policies []CompiledPolicy
}
```

```go
type CompiledPolicySets struct {
    Networks map[string][]CompiledCIDR
}
```

```go
type CompiledCheck struct {
    Name      string
    Type      CheckType
    Stage     Stage
    ConfigRef string
    Output    string
}
```

```go
type CompiledAttributeExpr struct {
    AttributeID string
    Detail      string
    Operator    Operator
    Expected    TypedValue
    ValueType   AttributeType
}
```

```go
type DecisionPlan struct {
    Effect          Decision
    Reason          string
    OutcomeMarker   string
    FSMEventMarker  string
    ResponseMarker  string
    ResponseMessage ResponseMessagePlan
    Obligations     []CompiledObligation
    Advice          []CompiledAdvice
    Control         DecisionControl
}
```

```go
type ResponseMessagePlan struct {
    Source      ResponseMessageSource
    Literal     string
    AttributeID string
    Detail      string
    Fallback    string
    MaxLength   int
}
```

Runtime evaluation must use only the active `PolicyRuntimeSnapshot`, compiled stage plans, and request-time `DecisionContext` values. It must not perform YAML decoding, mapstructure reflection, string parsing, or registry mutation on the hot path.

#### Evaluation Result and Trace

Every expression evaluation must be able to produce a trace node for decision reports:

```go
type ExprTrace struct {
    Kind        ExprKind
    AttributeID string
    Detail      string
    Operator    Operator
    Expected    any
    Actual      any
    Matched     bool
    Missing     bool
    Error       string
    Children    []ExprTrace
}
```

Trace production can be optional at runtime, controlled by report settings, but the evaluator design must make it natural.

Expression evaluation must distinguish runtime states even though policy matching ultimately needs a boolean result:

1. `matched`: expression evaluated to true;
2. `not_matched`: expression evaluated to false;
3. `missing`: the referenced attribute or detail was absent;
4. `error`: an unexpected runtime evaluation problem occurred.

For normal operators, `missing` contributes `false` to boolean composition. For `exists`, missing is the value being tested.

Example report fragment:

```json
{
  "rule": "deny_bruteforce",
  "matched": true,
  "if": {
    "kind": "attribute",
    "attribute": "auth.brute_force.triggered",
    "operator": "is",
    "expected": true,
    "actual": true,
    "matched": true
  }
}
```

Missing-attribute report fragment:

```json
{
  "rule": "deny_country",
  "matched": false,
  "if": {
    "kind": "attribute",
    "attribute": "lua.geo.country_blocked",
    "operator": "is",
    "expected": true,
    "actual": null,
    "matched": false,
    "missing": true
  }
}
```

This is the main reason to prefer an AST over direct YAML interpretation: validation, runtime evaluation, and reporting all share the same typed structure.

---

## 9. Stage Model

### 9.1 Recommended Stages

The target model must normalize current behavior into these stages:

```text
pre_auth
auth_backend
subject_analysis
account_provider
auth_decision
```

### 9.2 Meaning of Each Stage

| Stage | Meaning | Current runtime owner |
|---|---|---|
| `pre_auth` | checks that can block before backend auth | brute force, Lua environment sources, TLS, relay domains, RBL |
| `auth_backend` | password/backend/cache evaluation | current `HandlePassword` path |
| `subject_analysis` | Lua subject sources and result shaping | current `SubjectLua` path |
| `account_provider` | account-list provider evaluation | current `ListUserAccounts` / list-accounts path |
| `auth_decision` | map operation outcome to final decision | current password result mapping and list-accounts response selection |

There is intentionally no `post_decision` stage in the target decision model.

After `auth_decision`, the Policy Enforcement Point applies the selected response marker, response message, and obligations. This is enforcement, not another policy decision phase.

Lua POST-Actions are also not a `post_decision` phase. They are asynchronous follow-up work scheduled from enforcement context after the final decision is known. The request-time policy engine may request such scheduling through an obligation or advice, but the actual Lua POST-Action execution must not change the already selected decision, FSM terminal state, or response.

### 9.3 Operation Model

The policy layer must distinguish the operation being evaluated. The same policy engine handles all operations, but check plans and final decision semantics are operation-aware.

Initial operations:

```text
authenticate
lookup_identity
list_accounts
```

`authenticate` is the normal password-authentication operation.

`lookup_identity` is the policy operation for HTTP `mode=no-auth` and gRPC `LookupIdentity`. It is a trusted identity lookup without password verification. The current implementation already models gRPC `LookupIdentity` as the no-auth path; the policy layer must preserve that semantic boundary.

`list_accounts` is the policy operation for HTTP `mode=list-accounts` and gRPC `ListAccounts`. It is an account-provider listing operation, not password authentication and not a single identity lookup.

`DecisionContext` must expose the operation as a typed value, for example `request.operation`, so policies can explicitly match it when needed.

YAML check and policy entries may declare `operations`. If they omit it, they apply only to `authenticate`. Non-authentication operations such as `lookup_identity` and `list_accounts` must be opted in explicitly.

`lookup_identity` rules:

1. it uses the same policy runtime snapshot as normal authentication;
2. it may run `pre_auth`, `auth_backend`, `subject_analysis`, and `auth_decision` stages, but only with checks enabled for `lookup_identity`;
3. it does not perform password validation or password verification;
4. brute-force checks are not enabled for `lookup_identity` by the built-in default policy;
5. Lua environment and subject sources run only when the policy check plan explicitly opts them into `lookup_identity`;
6. backend evaluation is identity lookup, not credential verification;
7. backend user-found semantics map to lookup success;
8. `auth_decision` means "identity lookup permitted and found", not "password authenticated";
9. gRPC `LookupIdentity` renders normal lookup denials and tempfails as AuthService responses, not transport errors unless the failure is actually transport/caller/internal;
10. HTTP `mode=no-auth`, gRPC `LookupIdentity`, and IdP no-auth lookup use the same operation semantics.

During migration, current no-auth eligibility from old mechanism-local flags must be normalized into generated policy `operations` and `run_if` settings. It must not survive as an independent target scheduler.

`list_accounts` rules:

1. it uses the same policy runtime snapshot as normal authentication;
2. it may run `pre_auth`, `account_provider`, and `auth_decision` stages, but only with checks enabled for `list_accounts`;
3. it does not perform password validation or password verification;
4. brute-force checks are not enabled for `list_accounts` by the built-in default policy;
5. backend evaluation is account-list provider evaluation, not credential verification;
6. `account_provider` produces account-list attributes and provider status;
7. `auth_decision` means "account listing permitted and produced", not "password authenticated";
8. gRPC `ListAccounts` caller authorization and required OIDC scopes remain transport/caller-auth prerequisites;
9. normal account-list denials and tempfails render through the ListAccounts response surface where the transport supports it;
10. transport or caller-authorization failures remain transport errors, not policy denials.

### 9.4 Check Orchestration and `require_checks`

The policy layer uses an explicit stage check plan.

The `auth.policy.checks` block defines which checks are enabled for policy evaluation. It also defines their stage and execution order. Nauthilus must not execute every possible built-in or Lua-capable check just because it exists in the binary or configuration model.

#### Mechanism Eligibility and `run_if`

The target policy model must make the policy check plan the single scheduling authority.

The old mechanism-local flags:

```yaml
when_no_auth
when_authenticated
when_unauthenticated
```

are not part of the target config surface.

Hard-cut rules:

1. `when_no_auth` is replaced by operation scoping, primarily `operations: [lookup_identity]`;
2. `when_authenticated` is replaced by structural check scheduling such as `run_if.auth_state: authenticated`;
3. `when_unauthenticated` is replaced by structural check scheduling such as `run_if.auth_state: unauthenticated`;
4. `run_if` is a check-scheduler guard, not a policy decision condition;
5. `run_if` is the only request-time reason for a check in the active operation/stage plan to be skipped;
6. if `run_if` matches, the check must run or return a technical error;
7. `run_if` must stay small, typed, and registry-validated; it must not become a second expression language;
8. `require_checks` remains dependency validation and must not become scheduling;
9. after the hard cut, old `when_*` keys must be invalid through the existing unknown-key semantics; there must be no special compatibility loader path for them.

`run_if` must not model no-auth, list-account, lookup, provider, temporary-failure, account-lock, or identity-found states. Those dimensions are either operation scope (`operations`) or policy facts (`if` conditions over registered attributes).

This prevents the old mechanism-local scheduler and the new policy check plan from both deciding whether the same check should run.

#### Lua Script Check Granularity

Lua environment and subject sources are individual policy checks in the target model.

Rules:

1. each named Lua environment source script becomes one `lua.environment` policy check;
2. each named Lua subject source script becomes one `lua.subject` policy check;
3. aggregate target checks such as `lua_environments` or `lua_subjects` are not part of the target policy language;
4. `operations`, `run_if`, `require_checks`, reports, and generated Lua result attributes apply to the individual script check;
5. generated Lua result attributes must include script ownership in their attribute ID or equivalent registry metadata;
6. generated Lua result-attribute operation metadata must match the operations where the script check can run;
7. `config_ref` for Lua checks must identify the named script entry, not only the list that contains it;
8. the config conversion tool must generate one policy check per Lua script entry.

This keeps scheduling, reporting, and policy dependencies aligned with the actual script that produced the decision fact.

#### Check Scheduling Dependencies

Checks may declare scheduling dependencies through `after`.

Example:

```yaml
checks:
  - name: lua_subject_context_seed
    type: lua.subject
    stage: subject_analysis
    run_if:
      auth_state: authenticated
    config_ref: auth.policy.attribute_sources.lua.subject.context_seed

  - name: lua_subject_billing_lock
    type: lua.subject
    stage: subject_analysis
    after: [lua_subject_context_seed]
    run_if:
      auth_state: authenticated
    config_ref: auth.policy.attribute_sources.lua.subject.billing_lock
```

`after` is the target replacement for Lua `depends_on`.

Rules:

1. `after` is a check-plan scheduling dependency, not a policy dependency;
2. `after` controls execution order inside the compiled operation/stage check plan;
3. `require_checks` controls policy validation and must not be used for scheduling;
4. a check may use `after` when it needs earlier checks to populate request-local state, including `lualib.Context`;
5. the request-local Lua context remains available to later Lua checks in the same request according to the compiled `after` order;
6. policies must not read `lualib.Context` directly; policies read registered attributes emitted by checks;
7. `after` dependencies must reference checks that can run in the same operation/stage plan;
8. cyclic `after` dependencies are startup or reload errors;
9. `after` dependencies must be scheduler-compatible: whenever a dependent check is selected by operation and `run_if`, its declared dependencies must also be selected;
10. `after` must not create a runtime skip cascade;
11. if a scheduled dependency is unavailable because it failed or did not produce required request-local context, the dependent check must return `CheckResult.status=error`, not `skipped`;
12. a dependent check must not run with a missing request-local context that it declared through `after`;
13. when multiple checks are otherwise unordered, YAML order is the stable tie-breaker.

This preserves the existing Lua script dependency tree without keeping a Lua-internal scheduler beside the policy check plan.

Example:

```yaml
auth:
  policy:
    checks:
      - name: billing_subject_after_success
        type: lua.subject
        stage: subject_analysis
        run_if:
          auth_state: authenticated
        config_ref: auth.policy.attribute_sources.lua.subject.billing_subject

      - name: failed_login_subject
        type: lua.subject
        stage: subject_analysis
        run_if:
          auth_state: unauthenticated
        config_ref: auth.policy.attribute_sources.lua.subject.failed_login

      - name: lookup_subject
        type: lua.subject
        stage: subject_analysis
        operations: [lookup_identity]
        config_ref: auth.policy.attribute_sources.lua.subject.lookup_subject
```

Runtime order for each stage:

1. select the compiled plan for the current operation and stage;
2. select all configured checks that belong to that operation/stage plan;
3. resolve `after` dependencies and execute checks in dependency order, using YAML order as the stable tie-breaker;
4. collect `CheckResult` values and emitted policy attributes in the `DecisionContext`;
5. evaluate policies that belong to the same operation/stage plan with ordered first-match semantics;
6. apply the selected stage decision and control output.

The order above describes a complete stage segment. A compiled stage plan may contain policy checkpoints between check segments. At a checkpoint, the engine evaluates all same-stage policies whose required checks are already available. If that evaluation produces a terminal stage decision, the stage ends and later checks in the same stage are not executed. If the checkpoint result is neutral, execution continues with the next check segment.

Policy checkpoints are part of the compiled policy plan. They are not expressed by injecting synthetic `after` dependencies into unrelated checks. `after` remains only a check scheduling dependency for cases where a later check needs request-local state or attributes produced by an earlier check.

Observe mode uses the same compiled plan model, but it has an additional safety gate for custom-only checks. A custom-only check that is not observe-safe is removed from the custom observe execution plan, its expected attributes are marked unavailable in the observe report, and any custom policy that requires it becomes non-applicable for that observe evaluation.

This means:

1. `checks:` says what facts can be produced;
2. `policies:` says how produced facts are evaluated;
3. `require_checks:` declares the fact sources a policy depends on.

`require_checks` is not a lazy execution mechanism. It must not trigger checks at policy-evaluation time. It is a validation and dependency contract.

Runtime applicability rules:

1. before a policy condition is evaluated, every listed `require_checks` entry is checked against the current `DecisionContext`;
2. a required check with status `ok` satisfies the requirement;
3. a required check with status `error` also satisfies the requirement, because error attributes are normal policy inputs;
4. a required check with status `skipped` does not satisfy the requirement;
5. a missing required check result does not satisfy the requirement;
6. if any required check is missing or `skipped`, the policy is non-applicable for that request and is treated as not matched;
7. non-applicability due to `require_checks` must be recorded in the decision report with the required check name and observed status;
8. `require_checks` must never override operation scoping, `run_if`, or `after`, and must never cause a check to run.

Validation rules:

1. every `require_checks` entry must reference a check defined in `auth.policy.checks`;
2. a `require_checks` entry must reference a check in the same stage or an earlier completed stage for the policy operation;
3. a same-operation `require_checks` entry must reference a check that is enabled for that operation;
4. `run_if` must reference only registered scheduler dimensions and values;
5. `run_if` must not contain arbitrary attribute conditions, lookups, scripting, or policy expressions;
6. `after` dependencies must reference known checks;
7. `after` dependencies must be resolvable inside each compiled operation/stage plan where the dependent check can run;
8. `after` dependencies must be scheduler-compatible with the dependent check's operation and `run_if` scope;
9. `after` dependency cycles are startup or reload errors;
10. Lua check types must be singular `lua.environment` or `lua.subject`;
11. aggregate Lua check types such as `lua.environments` and `lua.subjects` must be rejected;
12. old `when_*` keys must not be accepted in the target config structs;
13. a policy may reference attributes from earlier completed stages if the registry allows that stage use;
14. a policy must not reference attributes from future stages;
15. a policy must not reference attributes that cannot be emitted for any operation where the policy can run;
16. missing or disabled required checks are startup or reload errors;
17. a check name must be unique across the policy check plan;
18. check output names must be unique when they are explicitly configurable;
19. check types that can fail inside the modeled decision flow must register typed error attributes.

For same-stage attribute dependencies, `require_checks` must be mandatory. This avoids hidden coupling where a policy depends on an attribute that is produced only if an unrelated check happens to run.

#### Technical Check Errors

Runtime failures inside a configured check are represented as check results and attributes, not as hidden final decisions.

Rules:

1. a technical check failure sets `CheckResult.status` to `error`;
2. the check emits a registered error attribute when the failure belongs to the modeled decision flow;
3. policy rules match those error attributes like any other attribute;
4. the built-in `standard_auth` policy maps current temporary technical failures to `tempfail`;
5. raw runtime errors remain internal diagnostics and are not client-visible response messages;
6. missing attributes are not technical check errors;
7. skipped checks are not technical check errors;
8. a check selected by operation and `run_if` must not report `skipped`;
9. if a selected check cannot run because an `after` dependency failed or did not provide required request-local context, it must report `error`;
10. an engine failure that prevents construction of a `CheckResult` is outside this normal path and fails closed as an internal tempfail.

Example:

```yaml
policies:
  - name: standard_rbl_error_tempfail
    stage: pre_auth
    require_checks: [rbl]
    if:
      attribute: auth.rbl.error
      is: true
    then:
      decision: tempfail
      outcome_marker: auth.outcome.rbl_error
      fsm_event_marker: auth.fsm.event.pre_auth_tempfail
      response_marker: auth.response.tempfail
```

Example:

```yaml
auth:
  policy:
    checks:
      - name: brute_force
        type: builtin.brute_force
        stage: pre_auth
        config_ref: auth.controls.brute_force

      - name: tls_encryption
        type: builtin.tls_encryption
        stage: pre_auth
        config_ref: auth.controls.tls_encryption

    policies:
      - name: deny_bruteforce
        stage: pre_auth
        require_checks: [brute_force]
        if:
          attribute: auth.brute_force.triggered
          is: true
        then:
          decision: deny
```

In this example, only `brute_force` and `tls_encryption` are part of the `pre_auth` policy check plan. Other possible checks do not run unless they are configured in `auth.policy.checks`.

### 9.5 Enforcement, Obligations, and Advice

The target model must use XACML-style terminology for effects that happen with or after enforcement:

1. **Obligation**: must be fulfilled by Nauthilus enforcement for the associated decision.
2. **Advice**: supplemental instruction or context that may be ignored safely.
3. **Async follow-up**: work enqueued after the decision, such as Lua POST-Actions.

Obligations and advice are registry-backed built-ins. Policy YAML may reference registered obligations and advice, but it must not define new executable obligation logic.

Obligations are not Lua extension points. Lua may be called by an existing built-in obligation, such as dispatching a configured synchronous Lua action or enqueuing an existing Lua POST-Action, but the policy language must not allow operators to register arbitrary Lua-backed obligations.

Built-in obligations:

1. send selected response;
2. update brute-force counters;
3. dispatch a configured synchronous Lua action;
4. enqueue Lua POST-Action;
5. write a decision report;
6. write an audit log entry.

Synchronous Lua action dispatch is a request-time obligation, not a policy condition and not an attribute emitter. Current code dispatches `brute_force`, `lua`, `tls_encryption`, `relay_domains`, and `rbl` Lua actions directly from the mechanism that observed the trigger. That is acceptable only as a temporary compatibility adapter. In the target model, the winning policy decision must select `auth.obligation.lua_action.dispatch` when it wants the configured synchronous Lua action to run.

The registered synchronous action obligation must accept bounded typed arguments:

1. `action`: one of `brute_force`, `lua`, `tls_encryption`, `relay_domains`, or `rbl`;
2. `feature`: optional stable feature or check name used for feature-specific learning and reports;
3. `wait`: optional boolean, default `true`, preserving the current synchronous behavior.

The obligation executor must preserve current action failure, timeout, and learning semantics for the selected action type. It must report the planned and executed obligation using the registered obligation ID and bounded argument values, not arbitrary Lua-provided labels.

Obligation execution rules:

1. mandatory request-time obligations must run before the response is sent;
2. if a mandatory request-time obligation fails before the response is sent, enforcement must fail closed with a `tempfail` response marker and an internal failure reason;
3. if an obligation failure happens after the response has been sent, the already sent response must not change;
4. asynchronous follow-up work is represented by the request-time obligation that enqueues it;
5. the asynchronous worker execution is outside the policy decision lifecycle;
6. Lua POST-Actions must not change the already selected decision, FSM terminal state, response marker, or response message;
7. obligations must not produce additional policy attributes for the same decision;
8. obligations must not trigger another policy evaluation pass;
9. synchronous Lua action obligations must execute only in authoritative enforce mode and never in observe mode.

Advice is non-binding context:

1. advice may be included in logs, decision reports, or POST-Action context;
2. advice may be ignored safely;
3. advice must not be required for the correctness of the final decision;
4. advice failure must not change the already selected decision or response.

### 9.6 Response Message Selection

The policy layer may affect the final client-visible status message, but it must do so through an explicit response-message selection model.

The target model separates four concepts:

1. `decision`: the security decision, such as `permit`, `deny`, `tempfail`, or `neutral`;
2. `reason`: an internal reason for logs, reports, counters, and follow-up work;
3. `response_marker`: the registered response class that selects default transport behavior;
4. `response_message`: an optional final status-message override selected by policy.

`response_marker` is the transport-independent response class. It determines the response profile for each supported surface: HTTP JSON, HTTP CBOR, Nginx auth-request, header-style HTTP, plain HTTP, gRPC AuthService, and IdP flows.

`response_message` may override only the client-visible message inside that response class. It must not change HTTP status codes, gRPC status codes, response body mode, redirect behavior, OIDC/SAML protocol semantics, or IdP flow state.

This separation is important because many real deployments need specific denial messages. Examples include unpaid billing state, administrative account locks, monitored accounts, or other customer-specific subject-source results. These messages are valid operational behavior and must remain expressible.

However, request-time Lua code must not directly mutate the final response after policy evaluation. Lua environment and subject sources may emit response-message candidates as typed policy attribute details. The policy then decides whether that candidate becomes the final status message.

Example Lua-emitted attribute value:

```yaml
attributes:
  lua.billing.account_locked:
    value: true
    details:
      reason: unpaid_invoice
      status_message: "Your account is locked; unpaid invoice"
```

Example policy selection:

```yaml
- name: deny_locked_billing_account
  stage: auth_decision
  if:
    attribute: lua.billing.account_locked
    is: true
  then:
    decision: deny
    reason: billing_locked
    response_marker: auth.response.fail
    response_message:
      from: attribute_detail
      attribute: lua.billing.account_locked
      detail: status_message
      fallback: "Your account is locked"
```

The `response_message` block supports these source modes:

1. omitted or `from: default`: use the message selected by `response_marker`;
2. `from: literal`: use a static message from policy YAML;
3. `from: attribute_detail`: use a public string detail from a registered policy attribute.

Literal example:

```yaml
then:
  decision: deny
  response_marker: auth.response.fail
  response_message:
    from: literal
    text: "Account temporarily locked"
```

Attribute-detail response messages must follow strict validation:

1. the referenced attribute must exist in the effective registry;
2. the referenced detail must exist and have type `string`;
3. the detail must be declared with `purpose: response_message`;
4. the detail must be declared with `sensitivity: public`;
5. the detail must define or inherit a maximum length;
6. the selected value must pass response sanitization before enforcement.

Response sanitization must reject or normalize values that cannot safely be sent in protocol responses:

1. CR or LF characters;
2. NUL bytes and control characters except horizontal tab if a protocol explicitly allows it;
3. strings longer than the configured maximum;
4. invalid encoding for the target transport;
5. transport-specific header injection patterns.

If `from: attribute_detail` is used and the attribute or detail is absent at runtime, enforcement must use the configured `fallback`. If no fallback is configured, the compiled plan must use the `response_marker` default instead.

### 9.6.1 Response Rendering Surfaces

The Policy Enforcement Point renders the selected response through the response profile for the current surface.

The first complete implementation must cover these response surfaces:

| Surface | Rendering responsibility |
|---|---|
| HTTP JSON | render the current JSON auth response shape with the selected decision and message |
| HTTP CBOR | render the current CBOR auth response shape with the selected decision and message |
| Nginx auth-request | render headers such as `Auth-Status`, wait hints, and status code according to the response marker |
| header-style HTTP | render the header-oriented auth response according to the response marker |
| plain HTTP | render the plain text response according to the response marker |
| HTTP list-accounts | render permitted account-list responses and account-list policy failures through content negotiation |
| gRPC AuthService | render normal auth denials and tempfails into the AuthService response message, not as transport errors |
| gRPC ListAccounts | render permitted account lists and normal account-list policy failures through the ListAccounts response surface where representable |
| IdP browser login/MFA | render the selected message into the browser flow without changing the policy decision after the fact |
| IdP OIDC | map auth-policy failures to protocol-correct OIDC behavior for the active flow |
| IdP SAML | map auth-policy failures to protocol-correct SAML behavior for the active flow |
| IdP device code | map auth-policy failures to the device-code response model without leaking internal reasons |

IdP support is required because IdP login and MFA flows consume the same auth decisions. The first policy scope remains request-time authentication decisions; IdP-specific provider policy, client authorization policy, claim-release policy, and consent policy remain outside this specification. However, when an auth-policy decision affects an IdP request, enforcement must render it through the IdP-specific response profile.

gRPC support is required for the same reason. A user authentication denial is a normal auth decision and must be represented in the AuthService response. gRPC status errors remain reserved for caller authentication failures, malformed requests, unavailable services, and internal execution failures.

The built-in default policy set must preserve current external behavior for existing Lua environment and subject source scripts that set a status message. Internally, the migration path must convert the current Lua status-message output into a registered response-message hint attribute and let the built-in default policy select that hint when the corresponding Lua decision denies or tempfails the request.

This conversion is per script. A Lua environment or subject source script becomes one policy check, and the status-message hint belongs to the script-specific generated attribute for that check. The target model must not collapse all Lua environment sources or all Lua subject sources into one aggregate check.

Lua POST-Actions are excluded from this mechanism. They run after the request-time decision and must not change the already selected status message.

### 9.7 Target Auth-FSM Extension

The target model needs explicit pre-auth FSM states and events. This is not optional: the policy layer must not route pre-auth decisions around the FSM.

Target non-terminal states:

```text
init
input_parsed
pre_auth_checked
auth_checked
account_provider_checked
```

Target terminal states:

```text
auth_ok
auth_fail
auth_tempfail
aborted
```

Target events:

```text
parse_ok
parse_fail
pre_auth_ok
pre_auth_deny
pre_auth_tempfail
pre_auth_abort
auth_evaluated
auth_permit
auth_deny
auth_tempfail
auth_empty_user
auth_empty_pass
account_provider_evaluated
basic_auth_ok
basic_auth_fail
abort
```

Allowed target transitions:

| State | Event | Next state |
|---|---|---|
| `init` | `parse_ok` | `input_parsed` |
| `init` | `parse_fail` | `aborted` |
| `input_parsed` | `pre_auth_ok` | `pre_auth_checked` |
| `input_parsed` | `pre_auth_deny` | `auth_fail` |
| `input_parsed` | `pre_auth_tempfail` | `auth_tempfail` |
| `input_parsed` | `pre_auth_abort` | `aborted` |
| `input_parsed` | `basic_auth_ok` | `auth_ok` |
| `input_parsed` | `basic_auth_fail` | `auth_fail` |
| `pre_auth_checked` | `basic_auth_ok` | `auth_ok` |
| `pre_auth_checked` | `basic_auth_fail` | `auth_fail` |
| `pre_auth_checked` | `auth_evaluated` | `auth_checked` |
| `pre_auth_checked` | `account_provider_evaluated` | `account_provider_checked` |
| `auth_checked` | `auth_permit` | `auth_ok` |
| `auth_checked` | `auth_deny` | `auth_fail` |
| `auth_checked` | `auth_tempfail` | `auth_tempfail` |
| `auth_checked` | `auth_empty_user` | `auth_tempfail` |
| `auth_checked` | `auth_empty_pass` | `auth_fail` |
| `account_provider_checked` | `auth_permit` | `auth_ok` |
| `account_provider_checked` | `auth_deny` | `auth_fail` |
| `account_provider_checked` | `auth_tempfail` | `auth_tempfail` |
| any non-terminal state | `abort` | `aborted` |

There must be no outgoing transitions from terminal states.

`pre_auth_checked` replaces the old feature-stage checkpoint in the target model. The current implementation can temporarily translate pre-auth policy markers to current `features_*` events during migration, but the target FSM vocabulary must be `pre_auth_*`.

An operation still reaches the `pre_auth_checked` checkpoint when it has no configured pre-auth checks. In that case the policy engine emits the neutral `auth.fsm.event.pre_auth_ok` marker unless parsing, preprocessing, or a configured pre-auth policy produced a terminal outcome.

`auth_checked` represents that backend and subject-source processing have produced the attributes needed by `auth_decision`. It replaces the current password-oriented checkpoint in the target vocabulary. The current implementation can temporarily translate final auth policy markers to current `password_*` events during migration.

`account_provider_checked` represents that account-provider processing has produced the attributes needed by `auth_decision` for `list_accounts`. It is not a password-authentication checkpoint.

The final `auth_permit`, `auth_deny`, and `auth_tempfail` event markers are operation-terminal decision events. Under `authenticate`, they mean password-authentication outcome. Under `lookup_identity`, they mean identity-lookup outcome. Under `list_accounts`, they mean account-listing outcome.

Policy YAML must reference FSM event markers, not terminal states. Enforcement applies the event to the FSM and then executes the terminal-state handlers selected by the transition result.

FSM migration rules:

1. the target FSM vocabulary is the desired public and internal target;
2. the current `features_*` and `password_*` events may exist only behind a temporary migration adapter;
3. the adapter maps target policy FSM event markers to the current FSM events while current external behavior is still being verified;
4. the adapter must not become a stable extension point, public contract, or compatibility mode;
5. after target-FSM parity is proven, the target FSM becomes authoritative;
6. once the target FSM is authoritative, old `features_*` and `password_*` event names and direct call sites must be removed.

### 9.8 Brute Force Is First-Class

Brute force is currently implemented as an early direct gate. In the target model, that is only an implementation constraint to migrate away from.

The target layer must model brute force as:

1. a `pre_auth` check evaluator;
2. a normal source of `CheckResult` policy attributes;
3. a normal input to policy decisions;
4. a normal source of FSM event markers;
5. a normal source of response, action, and learning requests.

Only the brute-force evaluator remains specialized. Its orchestration must not be special.

---

## 10. Check Catalog Mapped to the Current Codebase

### 10.1 In-Scope Checks

| Target check name | Current public config source | Current runtime owner | Notes |
|---|---|---|---|
| `brute_force` | `auth.controls.brute_force` | `CheckBruteForce`, bucket update logic | first-class pre-auth check |
| `lua_environment.<name>` | `auth.policy.attribute_sources.lua.environment.<name>` | named Lua environment source execution | one target pre-auth check per Lua environment source script |
| `tls_encryption` | `auth.controls.tls_encryption` | `checkTLSEncryptionFeature` | target pre-auth tempfail decision |
| `relay_domains` | `auth.controls.relay_domains` | `checkRelayDomainsFeature` | target pre-auth deny decision |
| `rbl` | `auth.controls.rbl` | `checkRBLFeature` | internal threshold model, policy sees typed attributes |
| `ldap_backend` | `auth.backends.ldap` | backend evaluation path | auth-backend stage |
| `lua_backend` | `auth.backends.lua.backend` | backend evaluation path | auth-backend stage |
| `lua_subject.<name>` | `auth.policy.attribute_sources.lua.subject.<name>` | named Lua subject source execution | one subject-analysis check per Lua subject source script |
| `account_provider` | `auth.backends.*` account-provider settings | `ListUserAccounts` / account-provider backend path | `account_provider` stage for `list_accounts` |

### 10.2 Side-Effect Executors, Not Core Checks

These belong to the broader auth runtime but must not be modeled as primary decision checks:

| Runtime area | Current public config source | Why not a primary decision check |
|---|---|---|
| Lua actions | `auth.policy.obligation_targets.lua.actions` | side effects selected through registered obligations, not fact-producing checks |
| Lua hooks | `auth.controls.lua.hooks` | custom HTTP surface, not part of the core auth pipeline |
| backend health checks | `auth.services.backend_health_checks` | background service, not request-time auth decision |

Lua hooks may populate Redis, caches, or external systems that are later read by request-time checks. That does not make the hook itself a policy check. The request-time check remains the fact-producing boundary that emits registered policy attributes.

Lua actions are also not `require_checks` dependencies. A feature or brute-force check may emit registered facts such as `auth.rbl.threshold_reached` or `auth.brute_force.triggered`. The policy may then select `auth.obligation.lua_action.dispatch` for the matching action type. This keeps decision ownership in the policy while preserving the current synchronous action behavior through an explicit enforcement effect.

Remote request-time enrichment, if needed later, must be a dedicated check type such as `remote_attribute` or `http_attribute`, not a hook callback. Such a check type would need explicit timeout, error, observe-safety, stage, operation, and report semantics before it enters the catalog.

### 10.3 Current Auth Surface Explicitly Left Outside the First Policy Scope

These are current auth-facing config sections, but they must stay outside the first policy-layer check catalog:

| Current public config source | Why it stays outside the first policy scope |
|---|---|
| `auth.backchannel.basic_auth` | transport/backchannel authentication mechanism, not a policy check in the same sense as TLS/RBL/relay/Lua environment sources |
| `auth.backchannel.oidc_bearer` | backchannel API authentication mechanism, not part of the first request-time policy check inventory |

They can later feed policy attributes into the decision context, but they must not be the first check types the policy layer is built around.

---

## 11. Decision Semantics

### 11.1 Effects

The target policy layer must use:

```text
neutral
deny
permit
tempfail
```

### 11.2 Important Rule: `neutral` Is Not `permit`

Examples in current semantics:

1. known relay domain -> `neutral`
2. RBL threshold not reached -> `neutral`
3. TLS present -> `neutral`
4. brute force not triggered -> `neutral`

None of these means the user has authenticated successfully.

### 11.3 `permit` in Pre-Auth Must Stay Restricted

In the current architecture, pre-auth controls mostly block or allow continuation. They do not usually grant final authentication success.

For that reason:

1. `permit` must be forbidden or heavily constrained in `pre_auth`;
2. `permit` must not jump directly to `auth_ok` unless a dedicated later flow explicitly allows it.

### 11.4 Deny-Biased Final Enforcement

The policy model must never fall through to a permissive result.

If no rule produces a final `permit` in `auth_decision`, enforcement must end in `deny`. This can be represented by an explicit final rule such as `standard_default_deny` in the built-in default policy, and by deny-biased enforcement if a custom policy set produces no applicable final decision.

Stage defaults are different:

1. no applicable `pre_auth` rule means `neutral` and processing may continue;
2. no applicable final `auth_decision` rule means `deny`;
3. an indeterminate final decision must not be treated as `permit`.

### 11.5 Ordered First-Match Combining

The first policy language version uses one fixed combining algorithm: ordered first-match.

There is no per-policy-set `combining` selector in the first version. Rule order is part of the policy semantics.

Evaluation rules:

1. policies are evaluated per stage in YAML order;
2. a policy whose `require_checks` are not satisfied is non-applicable and is treated as not matched;
3. a matching rule with a terminal effect stops evaluation for that stage;
4. terminal effects are `deny`, `tempfail`, and, in `auth_decision` only, `permit`;
5. `neutral` is not terminal for the final auth decision and does not mean success;
6. `neutral` may still carry stage control, such as `skip_remaining_stage_checks`;
7. if no `pre_auth` rule produces a terminal decision, the stage result is `neutral` and processing continues;
8. if no `auth_decision` rule produces `permit`, final enforcement denies;
9. an explicit default-deny rule must be the final `auth_decision` rule in built-in and operator-authored policy sets.

The `require_checks` applicability gate is evaluated before the condition AST. A missing or `skipped` required check does not make the condition false; it makes the whole policy non-applicable, so later rules in the same stage can still be considered.

Admin-facing guidance is simple: put more specific rules before broader rules, and keep the default-deny rule last.

---

## 12. Built-In Default Policy Mapping

The target model has no separate legacy-compatible execution path.

Current behavior is represented by a built-in default policy set named `standard_auth`. This policy set is evaluated by the same policy engine as custom policies. It emits stable outcome markers and FSM event markers. During migration, those markers may still be translated to current `AuthResult` values and current FSM events internally, but Go enum names must not become the stable public policy language.

### 12.1 Pre-Auth Mapping Represented by `standard_auth`

Current, externally visible behavior that must be reproduced by the built-in default policy:

| Current outcome | Default effect | Target FSM event marker | Current internal mapping during migration |
|---|---|---|---|
| brute force triggered | `deny` | `auth.fsm.event.pre_auth_deny` | current direct `AuthFail` behavior |
| Lua environment source triggered | `deny` | `auth.fsm.event.pre_auth_deny` | `AuthResultFeatureLua` / `features_fail` |
| TLS enforcement triggered | `tempfail` | `auth.fsm.event.pre_auth_tempfail` | `AuthResultFeatureTLS` / `features_tempfail` |
| relay domain rejected | `deny` | `auth.fsm.event.pre_auth_deny` | `AuthResultFeatureRelayDomain` / `features_fail` |
| RBL threshold exceeded | `deny` | `auth.fsm.event.pre_auth_deny` | `AuthResultFeatureRBL` / `features_fail` |
| no pre-auth control rejected | `neutral` | `auth.fsm.event.pre_auth_ok` | `AuthResultOK` / `features_ok` |
| pre-auth path aborts | `neutral` plus stop control | `auth.fsm.event.pre_auth_abort` | `AuthResultUnset` / `features_unset` |
| pre-auth temporary error | `tempfail` | `auth.fsm.event.pre_auth_tempfail` | `AuthResultTempFail` / `features_tempfail` |

### 12.2 Password/Auth Mapping Represented by `standard_auth`

| Current outcome | Default effect | Target FSM event marker | Current internal mapping during migration |
|---|---|---|---|
| auth success | `permit` | `auth.fsm.event.auth_permit` | `AuthResultOK` / `password_ok` |
| auth reject | `deny` | `auth.fsm.event.auth_deny` | `AuthResultFail` / `password_fail` |
| auth tempfail | `tempfail` | `auth.fsm.event.auth_tempfail` | `AuthResultTempFail` / `password_tempfail` |
| empty username | `tempfail` | `auth.fsm.event.auth_empty_user` | `AuthResultEmptyUsername` / `password_empty_user` |
| empty password | `deny` | `auth.fsm.event.auth_empty_pass` | `AuthResultEmptyPassword` / `password_empty_pass` |
| no final auth decision applies | `deny` | `auth.fsm.event.auth_deny` | default deny |

### 12.3 Operation-Specific Default Mapping

The built-in `standard_auth` policy set must include operation-specific rules. These rules still use the same policy engine, response registry, and FSM event registry, but the meaning of final permit/deny/tempfail depends on the active operation.

`lookup_identity` default mapping:

| Current outcome | Default effect | Target FSM event marker | Meaning |
|---|---|---|---|
| identity lookup found the user | `permit` | `auth.fsm.event.auth_permit` | identity lookup permitted and found |
| identity lookup did not find the user | `deny` | `auth.fsm.event.auth_deny` | identity lookup failed |
| identity lookup tempfail | `tempfail` | `auth.fsm.event.auth_tempfail` | identity lookup could not complete |
| no final lookup decision applies | `deny` | `auth.fsm.event.auth_deny` | default deny |

`list_accounts` default mapping:

| Current outcome | Default effect | Target FSM event marker | Meaning |
|---|---|---|---|
| account provider produced an account list | `permit` | `auth.fsm.event.auth_permit` | account listing permitted and produced; the list may be empty |
| account provider denied or did not produce a usable list | `deny` | `auth.fsm.event.auth_deny` | account listing denied |
| account provider tempfail | `tempfail` | `auth.fsm.event.auth_tempfail` | account listing could not complete |
| no final account-list decision applies | `deny` | `auth.fsm.event.auth_deny` | default deny |

Caller authentication and transport authorization remain prerequisites for operations that require them. For example, gRPC `ListAccounts` still requires valid caller authentication and the `nauthilus:list_accounts` scope before the request-time account-provider policy operation is evaluated. Missing caller credentials or missing caller scopes are transport/caller-authorization failures, not normal account-list policy denials.

### 12.4 Brute Force Must Not Remain an Exception

Current reality:

1. brute force does not return `AuthResultFeatureBruteForce`;
2. brute force does not map through `mapAuthFeatureResultToFSMEvent`;
3. brute force often performs a direct early failure.

Those implementation facts describe the migration starting point only. They are not the target architecture.

The target policy layer must model brute force as:

```text
CheckResult(brute_force)
  -> PolicyDecision(effect=deny, stage=pre_auth)
  -> auth.fsm.event.pre_auth_deny
  -> normal fail response/action/learning handling
```

and not as a direct gate outside the policy engine.

For the built-in `standard_auth` default, the `authenticate`/`pre_auth` plan must still preserve the current early-gate behavior. `brute_force` is the first pre-auth check segment, followed by an immediate policy checkpoint. If that checkpoint selects `standard_brute_force_error_tempfail` or `standard_brute_force_deny`, the stage terminates and later pre-auth checks such as Lua environment sources, TLS, relay-domain checks, and RBL are not invoked for that request.

This default ordering must not be represented as an implicit `after: [brute_force]` on every other pre-auth check. Operators who define custom checks keep explicit scheduling control; Nauthilus must not silently add hidden `after` dependencies to their policy YAML.

### 12.5 TLS Must Preserve Its Tempfail Semantics

TLS enforcement is not a normal reject in the current behavior. It maps to tempfail and eventually to the `TempFailNoTLS` response text.

The target policy layer must preserve that.

---

## 13. Builtin Checks and Current Config References

### 13.1 Brute Force

Current public config:

```yaml
auth:
  controls:
    brute_force:
      protocols:
      ip_allowlist:
      buckets:
      learning:
      custom_tolerations:
      ip_scoping:
      allowlist:
      tolerate_ttl:
      rwp_window:
      rwp_allowed_unique_hashes:
      tolerate_percent:
      min_tolerate_percent:
      max_tolerate_percent:
      scale_factor:
      adaptive_toleration:
      pw_history_for_known_accounts:
```

Current design constraints:

1. keep buckets unchanged;
2. keep Redis state and counters unchanged in early phases;
3. keep learning semantics unchanged;
4. keep external blocking behavior unchanged;
5. route the target blocking decision through policy and FSM instead of preserving a direct gate.

### 13.2 RBL

Current public config:

```yaml
auth:
  controls:
    rbl:
      threshold:
      lists:
      ip_allowlist:
```

Important current semantics:

1. the configured RBL lists remain authoritative;
2. the policy layer must consume typed attributes such as `auth.rbl.threshold_reached`;
3. the public name is `rbl`, not `realtime_blackhole_lists`.

### 13.3 Relay Domains

Current public config:

```yaml
auth:
  controls:
    relay_domains:
      static:
      allowlist:
```

Current semantics:

1. the static domain list remains authoritative;
2. unknown domains trigger the relay-domain rejection path;
3. the public field is `static`, not `static_domains`.

### 13.4 TLS Enforcement

Current public config:

```yaml
auth:
  controls:
    tls_encryption:
      allow_cleartext_networks:
```

Current semantics:

1. TLS is still a built-in control;
2. its auth-FSM mapping is tempfail-oriented;
3. its current external behavior must remain intact through the built-in default policy.

### 13.5 Lua Environment Sources

Current public config:

```yaml
auth:
  policy:
    attribute_sources:
      lua:
        environment:
```

Current semantics:

1. a triggered Lua environment source currently maps to `AuthResultFeatureLua`;
2. `abort_features` semantics already exist and must remain expressible;
3. current learning/action side effects must remain compatible.

### 13.6 Lua Subject Sources

Current public config:

```yaml
auth:
  policy:
    attribute_sources:
      lua:
        subject:
```

Current semantics:

1. Lua subject sources remain in the backend/password result path;
2. they do not currently have a dedicated auth-FSM state;
3. in early phases, their outputs must still be bridged through existing password/auth result handling.

---

## 14. Policy Config and UX Requirements

The `auth.policy` block must satisfy these rules.

### 14.1 Policy vs. Lua/Builtin Boundary

The YAML policy language is for declarative decision composition. It is not a second programming language.

YAML policies may:

1. reference registered policy attributes;
2. use structured boolean composition with `all`, `any`, and `not`;
3. apply typed operators validated against the effective registry;
4. select decisions, outcome markers, FSM event markers, response markers, response messages, obligations, advice, and stage control.

YAML policies must not:

1. query external systems;
2. perform Redis, LDAP, SQL, HTTP, DNS, or filesystem lookups;
3. transform strings or parse application-specific payloads;
4. define variables;
5. define functions;
6. use loops;
7. register attributes dynamically;
8. execute Lua or any other embedded scripting language.

Lua and Go built-ins are the fact-producing layer. They may:

1. gather data;
2. query external systems through the existing runtime mechanisms;
3. execute complex customer or deployment-specific logic;
4. normalize that logic into registered policy attributes;
5. emit those attributes during request evaluation.

Example fact-producing Lua:

```lua
nauthilus_policy.emit_attribute("lua.billing.account_locked", true, {
  reason = "unpaid_invoice",
  status_message = "Your account is locked; unpaid invoice",
})
```

Example decision-composing YAML:

```yaml
if:
  attribute: lua.billing.account_locked
  is: true
then:
  decision: deny
  reason: billing_locked
```

This boundary is mandatory. If a policy needs data that requires computation, lookup, transformation, or side effects, that work belongs in a check implemented by Go or Lua. The YAML policy must consume the resulting attribute.

Request-context decisions remain in scope when they are part of the current auth decision path. For example, Lua may inspect the request IP address, authenticated user, IdP request context, and OIDC client ID, then emit a registered attribute such as `lua.idp.client_block.triggered`. The YAML policy may deny the auth request based on that attribute.

Example request-context Lua:

```lua
local request = nauthilus_context.request()
local auth = nauthilus_context.auth()

if request.client_ip == "203.0.113.10" and auth.username == "alice" and request.oidc_client_id == "oidc_cid_x" then
  nauthilus_policy.emit_attribute("lua.idp.client_block.triggered", true, {
    status_message = "This account is not allowed to use the requested client",
  })
end
```

The exact Lua context accessor names are implementation details. The stable contract is that request-time Lua may read the current request/auth context and emit only attributes that were registered in the active policy runtime snapshot.

Example request-context YAML:

```yaml
- name: deny_lua_idp_client_block
  stage: auth_decision
  operations: [authenticate]
  require_checks: [lua_environment_idp_client_block]
  if:
    attribute: lua.idp.client_block.triggered
    is: true
  then:
    decision: deny
    reason: idp_client_blocked_for_user
    response_marker: auth.response.fail
    response_message:
      from: attribute_detail
      attribute: lua.idp.client_block.triggered
      detail: status_message
      fallback: "Authentication denied"
```

This example assumes `lua.idp.client_block.triggered` and its public `status_message` detail were registered through the policy attribute registry script.

This is still an auth-policy decision for a concrete request. It must not be treated as a general OIDC client-authorization framework, consent policy, claim-release policy, or protocol-trust policy.

### 14.2 Naming and Placement

1. live under `auth.policy`;
2. use current public control names in selectors and references;
3. not expose old root names as preferred user-facing values.

### 14.3 YAML Policy Language

The YAML policy language must be admin-friendly while remaining structured enough for strict validation and later UI support.

It must not use free-form expression strings. Conditions must be YAML objects.

Policies use ordered first-match evaluation. Within a stage, rules are evaluated exactly in YAML order. A matching rule with a terminal decision selects the stage outcome and stops further rule evaluation for that stage.

#### Basic Shape

```yaml
auth:
  policy:
    policies:
      - name: deny_bruteforce
        stage: pre_auth
        if:
          attribute: auth.brute_force.triggered
          is: true
        then:
          decision: deny
```

`if` describes the condition. `then` describes the decision and optional enforcement output.

#### Attribute Conditions

The shortest condition form references one registered policy attribute:

```yaml
if:
  attribute: auth.tls.secure
  is: false
```

Details are referenced explicitly so validation can check the attribute definition:

```yaml
if:
  attribute: auth.brute_force.triggered
  detail: repeating
  is: true
```

The attribute registry must validate:

1. the attribute exists;
2. the detail exists when `detail` is used;
3. the selected operator is valid for the attribute or detail type;
4. the expected value has the correct type.

#### Type and Value Semantics

Policy values are compiled against the effective Policy Attribute Registry. Nauthilus must not use broad or magical YAML coercion.

Rules:

1. booleans must be YAML booleans, not strings such as `"true"` or `"false"`;
2. numeric values must be YAML numbers and must fit the registered numeric type;
3. strings must be YAML strings;
4. lists must be YAML lists and each item must compile to the registered item type;
5. `null` is not a value match; presence tests must use `exists`;
6. no cross-type conversions such as string-to-bool, string-to-number, or number-to-string are allowed;
7. all conversions happen during snapshot build, not during request-time evaluation.

Specialized types are parsed explicitly from YAML strings:

| Registry type | YAML shape | Compile-time parser |
|---|---|---|
| `ip` | string | IP address parser |
| `cidr` | string | CIDR parser |
| `duration` | string | duration parser |
| `datetime` | string | RFC3339 timestamp parser |
| `regex` | string | regular expression compiler |

Examples:

```yaml
if:
  attribute: auth.tls.secure
  is: true
```

```yaml
if:
  attribute: auth.tls.secure
  is: "true"
```

The second example is invalid because the registered value type is `bool` and the YAML value is a string.

CIDR example:

```yaml
if:
  attribute: auth.brute_force.triggered
  detail: client_net
  cidr_contains: "203.0.113.0/24"
```

The CIDR value is a string in YAML but compiles to a typed CIDR value before the snapshot becomes active.

#### Logical Composition

The language must support exactly these boolean composition operators:

```yaml
if:
  all:
    - attribute: auth.relay_domain.present
      is: true
    - attribute: auth.relay_domain.known
      is: false
```

```yaml
if:
  any:
    - attribute: lua.geo.country_blocked
      is: true
    - attribute: lua.account.disabled
      is: true
```

```yaml
if:
  not:
    attribute: auth.tls.secure
    is: true
```

The preferred names are `all`, `any`, and `not`. Do not add aliases such as `and` or `or`.

#### Operators

Supported operators are deliberately small and type-aware.

Common operators:

| Operator | Meaning |
|---|---|
| `is` | boolean or exact scalar equality for simple admin cases |
| `eq` | exact equality |
| `ne` | exact inequality |
| `in` | scalar value is in a configured list |
| `not_in` | scalar value is not in a configured list |
| `matches` | string matches regular expression |
| `exists` | attribute or detail exists |

List operators:

| Operator | Meaning |
|---|---|
| `contains` | list contains one configured value |
| `contains_any` | list contains at least one value from a configured list |
| `contains_all` | list contains all values from a configured list |
| `contains_none` | list contains none of the configured values |

Numeric or comparable operators:

| Operator | Meaning |
|---|---|
| `gt` | greater than |
| `gte` | greater than or equal |
| `lt` | less than |
| `lte` | less than or equal |

Network operators:

| Operator | Meaning |
|---|---|
| `cidr_contains` | CIDR contains IP or narrower CIDR |

Network operators are valid only for compatible attribute/detail types.

Network operator operands may be either:

1. a CIDR or IP literal string;
2. a network-set reference in the form `@network.<name>`.

Network sets live under `auth.policy.sets.networks`:

```yaml
auth:
  policy:
    sets:
      networks:
        trusted:
          - "10.0.0.0/8"
          - "192.168.0.0/16"
          - "2001:db8::/32"
```

Example:

```yaml
if:
  attribute: auth.client.ip
  cidr_contains: "@network.trusted"
```

Network-set rules:

1. network-set names must be unique within `auth.policy.sets.networks`;
2. network-set names must use simple identifier syntax, such as lowercase letters, digits, and underscores;
3. every set entry must compile to a CIDR or IP network during snapshot build;
4. invalid set entries are startup or reload errors;
5. conditions must not reference arbitrary config paths such as `config:auth.controls.tls_encryption.allow_cleartext_networks`;
6. dynamic network decisions must be expressed through emitted policy attributes, not through mutable network sets.

Time window operators:

| Operator | Meaning |
|---|---|
| `within_time_window` | datetime value falls into a configured time window |

Time window operators are valid only for compatible datetime attributes or details. The built-in `request.time.now` attribute is captured once per request in the `DecisionContext`, so all policy stages evaluate the same request timestamp.

Time window operands must be time-window-set references in the form `@time_window.<name>`.

Time window sets live under `auth.policy.sets.time_windows`:

```yaml
auth:
  policy:
    sets:
      time_windows:
        business_hours:
          timezone: Europe/Berlin
          days: [mon, tue, wed, thu, fri]
          intervals:
            - start: "08:00"
              end: "18:00"
```

Example:

```yaml
if:
  attribute: request.time.now
  within_time_window: "@time_window.business_hours"
```

For policies intended to match outside a time window, use `not` instead of a second operator:

```yaml
if:
  not:
    attribute: request.time.now
    within_time_window: "@time_window.business_hours"
```

Time-window rules:

1. time-window names must be unique within `auth.policy.sets.time_windows`;
2. time-window names must use simple identifier syntax, such as lowercase letters, digits, and underscores;
3. `timezone` must be an IANA timezone name such as `Europe/Berlin`;
4. `days` must contain only `mon`, `tue`, `wed`, `thu`, `fri`, `sat`, or `sun`;
5. interval `start` and `end` values must be `HH:MM` strings;
6. every interval must compile during snapshot build;
7. cross-midnight intervals are invalid in the first policy language and must be split into two intervals;
8. invalid time-window definitions are startup or reload errors;
9. no cron syntax, functions, or dynamic config references are allowed in time-window definitions.

Scalar and list semantics must not be mixed implicitly:

1. `in` and `not_in` are valid only when the attribute or detail value is scalar;
2. `contains`, `contains_any`, `contains_all`, and `contains_none` are valid only when the attribute or detail value is list-typed;
3. `eq` and `ne` on list-typed values are advanced exact-list comparisons and are not intended for normal membership checks;
4. exact-list comparison, if supported, must compare the compiled list value exactly, including order;
5. a missing list is not the same as an empty list;
6. presence checks must use `exists`.

Regex semantics:

1. `matches` uses Go regular expression semantics, which are RE2-based;
2. the pattern is interpreted exactly as configured;
3. Nauthilus must not add implicit `^` or `$` anchors;
4. full-string matches must be written explicitly, for example `^admin$`;
5. regex patterns compile during snapshot build;
6. an invalid regex is a startup or reload error;
7. regex matching is valid only for string attributes and string details.

Examples:

```yaml
if:
  attribute: lua.account.risk_level
  in: ["high", "critical"]
```

```yaml
if:
  attribute: auth.user.groups
  contains: "mail-admin"
```

```yaml
if:
  attribute: auth.user.groups
  contains_any: ["mail-admin", "support"]
```

```yaml
if:
  attribute: auth.user.groups
  contains_all: ["employee", "mfa-enrolled"]
```

```yaml
if:
  attribute: auth.user.groups
  contains_none: ["suspended", "disabled"]
```

```yaml
if:
  attribute: auth.brute_force.triggered
  detail: client_net
  cidr_contains: "203.0.113.0/24"
```

```yaml
if:
  attribute: lua.department
  matches: "^admin-"
```

Missing attributes are not silently equal to `false`. Policies that care about presence must use `exists`.

```yaml
if:
  attribute: lua.geo.country_blocked
  exists: true
```

Missing attribute semantics:

1. a normal operator on a missing attribute or missing detail does not match;
2. missing is not a runtime error;
3. missing is not equivalent to `false`, an empty string, zero, or an empty list;
4. `exists: true` matches only when the attribute or detail is present;
5. `exists: false` matches only when the attribute or detail is absent;
6. in `all`, a missing child expression prevents the `all` expression from matching;
7. in `any`, a missing child expression does not prevent another child from matching;
8. in `not`, the boolean result is negated, but the trace still records the missing child;
9. if a required check ran but did not emit an attribute, policy evaluation treats that attribute as missing, not as an engine error.

#### Then Block

The `then` block must always include a `decision`.

```yaml
then:
  decision: deny
```

For normal administrator-authored policies, `decision` plus optional `reason` should usually be enough:

```yaml
then:
  decision: tempfail
  reason: no_tls
```

Nauthilus must derive default `fsm_event_marker`, `response_marker`, and `outcome_marker` values from `stage`, `decision`, and `reason` when the fields are omitted and the mapping is unambiguous.

Advanced policies may set markers explicitly:

```yaml
then:
  decision: deny
  outcome_marker: auth.outcome.brute_force_reject
  fsm_event_marker: auth.fsm.event.pre_auth_deny
  response_marker: auth.response.fail
```

Policies may also select a final status message. If `response_message` is omitted, enforcement uses the default message associated with `response_marker`.

Static message example:

```yaml
then:
  decision: deny
  response_marker: auth.response.fail
  response_message:
    from: literal
    text: "Account temporarily locked"
```

Lua-provided message example:

```yaml
then:
  decision: deny
  reason: billing_locked
  response_marker: auth.response.fail
  response_message:
    from: attribute_detail
    attribute: lua.billing.account_locked
    detail: status_message
    fallback: "Your account is locked"
```

`response_message.from: attribute_detail` is valid only when the referenced attribute detail is registered as a public response-message detail. Lua can emit such a detail, but the policy must explicitly select it before it becomes client-visible.

Policies may request enforcement work through obligations:

```yaml
then:
  decision: deny
  obligations:
    - id: auth.obligation.brute_force.update
    - id: auth.obligation.lua_action.dispatch
      args:
        action: brute_force
    - id: auth.obligation.lua_post_action.enqueue
      args:
        action: brute_force
```

Advice is non-binding context:

```yaml
then:
  decision: deny
  advice:
    - id: auth.advice.audit_reason
      args:
        reason: blocked_country
```

#### Stage Rules

1. `pre_auth` may emit `neutral`, `deny`, `tempfail`, or abort-style outcomes.
2. `pre_auth` must not emit final `permit`.
3. `auth_decision` is the only normal stage that may emit final `permit`.
4. `neutral` does not stop final auth decision evaluation unless it carries explicit stage control;
5. if no `auth_decision` rule emits `permit`, enforcement must deny.

### 14.4 Validation

Validation rules must include:

1. every policy needs `name`, `stage`, `if`, and `then`;
2. every check needs `name`, `type`, and `stage`;
3. every check or policy operation, when explicitly configured, must be one of the registered operations;
4. omitted check or policy `operations` must compile as `[authenticate]`;
5. explicit empty `operations: []` must be rejected;
6. `run_if` must use only registered structural scheduler fields and values;
7. `run_if` must not contain arbitrary policy conditions, lookups, scripting, or expression trees;
8. the initial `run_if` model must support only `auth_state` with `authenticated`, `unauthenticated`, or `any`;
9. omitted `run_if.auth_state` must compile as `any`;
10. `run_if` must not encode operation, lookup, account-provider, error, or business-state semantics;
11. `after` dependencies must reference known checks;
12. `after` dependencies must be resolvable inside each compiled operation/stage plan where the dependent check can run;
13. `after` dependencies must be scheduler-compatible with the dependent check's operation and `run_if` scope;
14. cyclic `after` dependencies must be rejected;
15. `observe_safe: true` must be accepted only for check types whose registry permits operator assertion;
16. check types that are never observe-safe must reject `observe_safe: true`;
17. Lua check types must be singular `lua.environment` or `lua.subject`;
18. aggregate Lua check types such as `lua.environments` and `lua.subjects` must be rejected;
19. `when_no_auth`, `when_authenticated`, and `when_unauthenticated` must not exist in target config structs;
20. old `when_*` keys must fail through the existing unknown-key config semantics;
21. Go built-in policy attributes must declare a non-empty operation list explicitly;
22. omitted Lua policy-attribute `operations` must compile as `[authenticate]`;
23. explicit empty policy-attribute `operations: []` must be rejected;
24. every policy-attribute operation must be one of the registered operations;
25. `require_checks` must reference checks defined in `auth.policy.checks`;
26. `require_checks` runtime applicability must compile so only `ok` and `error` satisfy the requirement, while missing or `skipped` results make the policy non-applicable;
27. same-stage attribute dependencies must declare the producing check in `require_checks`;
28. policies may reference earlier-stage attributes only when registry stage rules allow it;
29. policies may reference operation-specific attributes only for operations where those attributes can be emitted;
30. no policy may use `post_decision` as a stage;
31. `permit` in `pre_auth` must be rejected unless a later explicitly specified flow adds a constrained success transition;
32. referenced policy attributes must exist in the attribute registry;
33. detail references must be valid for the referenced attribute;
34. expected values must compile using strict registry-type rules without broad YAML coercion;
35. scalar membership operators must not be used on list-typed values;
36. list membership operators must not be used on scalar values;
37. regex values for `matches` must compile and must be used only with string attributes or details;
38. `@network.<name>` references must resolve to `auth.policy.sets.networks` entries;
39. network set entries must compile to CIDR or IP network values;
40. `@time_window.<name>` references must resolve to `auth.policy.sets.time_windows` entries;
41. time-window set entries must compile to valid timezone, day, and interval values;
42. cross-midnight time-window intervals must be rejected in the first policy language;
43. `within_time_window` must be used only with datetime attributes or details;
44. conditions must not reference arbitrary config paths for network or time-window operands;
45. `fsm_event_marker` values must resolve to registered FSM event markers;
46. `fsm_event_marker` values must be valid for the policy stage;
47. `fsm_event_marker` values must reference events, not terminal states;
48. `response_marker` values must resolve to registered response definitions;
49. `response_marker` values must be compatible with the selected decision effect;
50. response markers used for account listing must have HTTP list-accounts and gRPC ListAccounts profiles;
51. `response_message` must not set transport details directly;
52. check types that can fail inside the modeled decision flow must register typed error attributes;
53. policy conditions must not contain lookup, transform, variable, loop, or scripting constructs;
54. obligations and advice must reference registered built-in definitions;
55. policy YAML must not define executable obligation logic;
56. check names and output names must be unique;
57. operation-scoped checks and policies must compile into at least one valid operation/stage plan.

### 14.5 Config Problems

Policy config errors must render like existing canonical config errors.

Examples:

```text
field 'auth.policy.policies[0].stage' failed validation rule 'oneof'
field 'auth.policy.checks[2].type' is invalid
field 'auth.policy.policies[1].require_checks[0]' references unknown check 'foo'
```

### 14.6 Dump Integration

Defaults and configured values must appear in:

```bash
nauthilus -d
nauthilus -n --config /path/to/nauthilus.yml
```

Sensitive values must remain redacted unless `-P` is used.

---

## 15. Decision Report Requirements

The decision report must be optional and must follow the current operational guardrails.

### 15.1 Report Goals

1. show which checks ran;
2. show which checks were skipped and why;
3. show which policies matched;
4. show policies that were non-applicable because `require_checks` were missing or skipped;
5. show the policy attributes that were emitted;
6. show the final policy, outcome marker, response marker, response-message source, and FSM marker that were chosen;
7. help compare built-in default policy decisions and custom policy decisions in observe mode.

### 15.2 Report Safety

The report must not expose:

1. passwords;
2. TOTP secrets;
3. recovery codes;
4. OAuth/OIDC tokens;
5. session cookies;
6. LDAP bind secrets;
7. sensitive Lua-returned data;
8. non-public attribute details that were not selected as the client-visible response message.
9. raw runtime error strings, stack traces, backend connection strings, or bind credentials.

Rendered response messages may be included only when they are the sanitized message selected for the client response. Internal reason values and non-public attribute details must remain separate.

Technical check errors may appear in reports only as `CheckResult.status=error`, sanitized reason codes, and registered internal details that pass redaction.

### 15.3 Policy Logging and Debug Module

Policy evaluation needs normal structured logs and debug-module logs, but the two surfaces must stay separate.

Normal structured logging must include only operationally relevant final facts:

1. `policy_mode`;
2. `policy_set`;
3. `policy_name`;
4. `operation`;
5. `stage`;
6. `decision`;
7. `reason`;
8. `response_marker`;
9. `fsm_event_marker`;
10. `snapshot_generation`;
11. `observe_mismatch`.

Normal logs must not dump the expression tree, non-public attribute details, raw check errors, or arbitrary emitted attributes. Those belong in decision reports or debug logs under the existing redaction rules.

The implementation must add one debug module for policy internals:

```text
policy
```

In Go this must be represented as a new `DbgPolicy` value and a `DbgPolicyName = "policy"` mapping, consistent with existing modules such as `auth`, `lua`, `filter`, `rbl`, and `idp`.

`DBGModule policy` logs are for technical diagnosis and may include:

1. check-plan selection;
2. `require_checks` applicability decisions;
3. skipped checks;
4. unavailable observe-mode checks;
5. condition AST evaluation traces;
6. missing attributes;
7. selected response-message source;
8. FSM adapter mappings during migration;
9. target-FSM comparison results;
10. observe-mode default-vs-custom comparison data.

The policy debug module must not be split into many public debug modules. Instead, detailed logs must carry a structured field:

```text
policy_component
```

Allowed component values must include:

1. `compiler`;
2. `snapshot`;
3. `checks`;
4. `eval`;
5. `fsm`;
6. `observe`;
7. `report`.

All policy debug logs must include the request/session correlation fields already used by the auth path where available, especially `guid`, `operation`, `stage`, and `snapshot_generation`. Debug logs must obey the same redaction rules as decision reports.

### 15.4 Policy Metrics and OpenTelemetry

Policy-engine observability is mandatory. The implementation must instrument all relevant policy paths for Prometheus metrics and OpenTelemetry tracing.

This does not mean that Prometheus scraping or OpenTelemetry exporting must always be active. Export and collection remain governed by the existing Nauthilus observability configuration. The policy engine must still expose instrumentation points so disabled observability is a no-op rather than a missing implementation.

Prometheus metrics and OpenTelemetry spans must follow the same redaction and cardinality rules as logs and decision reports.

Required Prometheus instrumentation:

1. snapshot build and reload:
   - build duration;
   - success and failure counters;
   - active snapshot generation as a gauge;
   - reload failures where the previous snapshot remains active;
2. check execution:
   - duration per check;
   - result counters for `ok`, `skipped`, and `error`;
   - technical error counters using sanitized `reason_code` only;
3. policy evaluation:
   - stage evaluation duration;
   - decision counters by mode, operation, stage, and decision;
   - selected policy, response marker, and FSM marker counters where labels are config-bounded;
4. `require_checks` applicability:
   - satisfied, missing, skipped, and non-applicable counters;
5. observe mode:
   - default-vs-custom comparison counters;
   - mismatch counters by mismatch type;
   - unavailable custom-only check counters;
6. FSM:
   - target-FSM transition counters;
   - target-vs-current FSM mismatch counters during migration;
7. response rendering:
   - render duration by response surface;
   - render success and failure counters;
8. obligations and advice:
   - mandatory request-time obligation duration;
   - obligation success and failure counters;
   - async enqueue success and failure counters;
   - advice selection counters.

Allowed metric labels are bounded and must include only stable, low-cardinality values:

1. `mode`;
2. `operation`;
3. `stage`;
4. `decision`;
5. `check`;
6. `check_type`;
7. `policy_name`;
8. `response_marker`;
9. `fsm_event_marker`;
10. `surface`;
11. `status`;
12. `result`;
13. `reason_code`;
14. `mismatch_type`;
15. `obligation`.

Forbidden metric labels:

1. username;
2. client IP;
3. OAuth/OIDC tokens;
4. session cookies;
5. raw error text;
6. response-message text;
7. attribute-detail values;
8. dynamic Lua-returned values;
9. `snapshot_generation`.

`snapshot_generation` must be represented as a gauge value and may appear as a log field or span attribute, but it must not be used as a Prometheus label.

OpenTelemetry tracing requirements:

1. policy tracing must use tracer scope `nauthilus/policy`;
2. spans must be children of the active request span when request context exists;
3. background or reload spans must use the existing runtime/service context;
4. spans must record sanitized errors with the existing OpenTelemetry error/status conventions;
5. spans must not include secrets, raw response messages, non-public attribute details, or dynamic high-cardinality values.

Required OpenTelemetry spans:

1. `policy.snapshot.build`;
2. `policy.registry.lua`;
3. `policy.stage`;
4. `policy.check`;
5. `policy.evaluate`;
6. `policy.fsm.apply`;
7. `policy.response.render`;
8. `policy.observe.compare`;
9. `policy.obligation`.

Recommended span attributes:

1. `policy.mode`;
2. `policy.operation`;
3. `policy.stage`;
4. `policy.name`;
5. `policy.check`;
6. `policy.check_type`;
7. `policy.decision`;
8. `policy.response_marker`;
9. `policy.fsm_event_marker`;
10. `policy.snapshot_generation`;
11. `policy.surface`;
12. `policy.status`;
13. `policy.reason_code`;
14. `policy.mismatch_type`;
15. `policy.component`.

Policy instrumentation must not duplicate existing mechanism metrics unnecessarily. Existing metrics such as auth-FSM transitions, RBL, brute-force, Lua queue, Redis, HTTP, gRPC, and IdP metrics remain authoritative for their mechanism-specific domains. Policy metrics describe policy orchestration, check scheduling, decision evaluation, observe comparison, response rendering, and policy-owned obligations.

### 15.5 Report Example

```json
{
  "stage": "pre_auth",
  "attributes": {
    "auth.rbl.threshold_reached": {
      "value": true,
      "details": {
        "lists": ["spamhaus_zen"]
      }
    }
  },
  "checks": {
    "rbl": {
      "matched": true,
      "decision_hint": "deny",
      "attributes": ["auth.rbl.threshold_reached"]
    }
  },
  "policies": [
    {
      "policy_name": "standard_rbl_reject",
      "effect": "deny",
      "outcome_marker": "auth.outcome.rbl_reject",
      "fsm_event_marker": "auth.fsm.event.pre_auth_deny",
      "response_marker": "auth.response.fail",
      "response_message": {
        "source": "response_marker",
        "rendered": "Invalid login or password"
      }
    }
  ],
  "final": {
    "effect": "deny",
    "outcome_marker": "auth.outcome.rbl_reject",
    "fsm_event_marker": "auth.fsm.event.pre_auth_deny",
    "response_marker": "auth.response.fail",
    "response_message": {
      "source": "response_marker",
      "rendered": "Invalid login or password"
    }
  }
}
```

---

## 16. Recommended Target Configuration

The following is a **target configuration example**, not current implementation.

It intentionally keeps current mechanism-owning blocks where they already live and adds the policy layer under `auth.policy`.

```yaml
auth:
  controls:
    enabled:
      - brute_force
      - tls_encryption
      - relay_domains
      - rbl
      - lua

    brute_force:
      protocols: [imap, smtp, submission]
      ip_allowlist: [127.0.0.0/8, ::1]
      buckets: []
      learning:
        - brute_force
        - lua
        - relay_domains
        - rbl

    tls_encryption:
      allow_cleartext_networks: []

    relay_domains:
      static:
        - example.org
        - example.net

    rbl:
      threshold: 15
      ip_allowlist:
        - 127.0.0.0/8
        - 10.0.0.0/8
      lists:
        - name: spamhaus_zen
          rbl: zen.spamhaus.org
          allow_failure: true
        - name: reputation_allow_signal
          rbl: allow.example.net
          allow_failure: true

  policy:
    mode: enforce
    default_policy: standard_auth
    registry_scripts: []
    attribute_sources:
      lua:
        environment:
          - name: geo_block
            script_path: /etc/nauthilus/lua/environment/geo_block.lua
        subject:
          - name: context_seed
            script_path: /etc/nauthilus/lua/subject/context_seed.lua
          - name: billing_lock
            script_path: /etc/nauthilus/lua/subject/billing_lock.lua
    obligation_targets:
      lua:
        actions: []

    sets:
      networks:
        trusted_clients:
          - 10.0.0.0/8
          - 192.168.0.0/16
      time_windows:
        business_hours:
          timezone: Europe/Berlin
          days: [mon, tue, wed, thu, fri]
          intervals:
            - start: "08:00"
              end: "18:00"

    report:
      enabled: true
      include_fsm: true
      include_checks: true
      include_attributes: false

    checks:
      - name: brute_force
        type: builtin.brute_force
        stage: pre_auth
        config_ref: auth.controls.brute_force
        output: checks.brute_force

      - name: lua_environment_geo_block
        type: lua.environment
        stage: pre_auth
        config_ref: auth.policy.attribute_sources.lua.environment.geo_block
        output: checks.lua_environment_geo_block

      - name: tls_encryption
        type: builtin.tls_encryption
        stage: pre_auth
        config_ref: auth.controls.tls_encryption
        output: checks.tls_encryption

      - name: relay_domains
        type: builtin.relay_domains
        stage: pre_auth
        config_ref: auth.controls.relay_domains
        output: checks.relay_domains

      - name: rbl
        type: builtin.rbl
        stage: pre_auth
        config_ref: auth.controls.rbl
        output: checks.rbl

      - name: ldap_backend
        type: backend.ldap
        stage: auth_backend
        operations: [authenticate, lookup_identity]
        config_ref: auth.backends.ldap
        output: checks.ldap_backend

      - name: lua_backend
        type: backend.lua
        stage: auth_backend
        operations: [authenticate, lookup_identity]
        config_ref: auth.backends.lua.backend
        output: checks.lua_backend

      - name: lua_subject_context_seed
        type: lua.subject
        stage: subject_analysis
        run_if:
          auth_state: authenticated
        config_ref: auth.policy.attribute_sources.lua.subject.context_seed
        output: checks.lua_subject_context_seed

      - name: lua_subject_billing_lock
        type: lua.subject
        stage: subject_analysis
        after: [lua_subject_context_seed]
        run_if:
          auth_state: authenticated
        config_ref: auth.policy.attribute_sources.lua.subject.billing_lock
        output: checks.lua_subject_billing_lock

      - name: account_provider
        type: backend.account_provider
        stage: account_provider
        operations: [list_accounts]
        config_ref: auth.backends
        output: checks.account_provider

    policies:
      - name: standard_brute_force_error_tempfail
        stage: pre_auth
        require_checks: [brute_force]
        if:
          attribute: auth.brute_force.error
          is: true
        then:
          decision: tempfail
          outcome_marker: auth.outcome.brute_force_error
          fsm_event_marker: auth.fsm.event.pre_auth_tempfail
          response_marker: auth.response.tempfail

      - name: standard_brute_force_deny
        stage: pre_auth
        require_checks: [brute_force]
        if:
          attribute: auth.brute_force.triggered
          is: true
        then:
          decision: deny
          outcome_marker: auth.outcome.brute_force_reject
          fsm_event_marker: auth.fsm.event.pre_auth_deny
          response_marker: auth.response.fail
          obligations:
            - id: auth.obligation.brute_force.update
            - id: auth.obligation.lua_action.dispatch
              args:
                action: brute_force
            - id: auth.obligation.lua_post_action.enqueue
              args:
                action: brute_force

      - name: standard_tls_enforcement
        stage: pre_auth
        require_checks: [tls_encryption]
        if:
          attribute: auth.tls.secure
          is: false
        then:
          decision: tempfail
          outcome_marker: auth.outcome.tls_required
          fsm_event_marker: auth.fsm.event.pre_auth_tempfail
          response_marker: auth.response.tempfail.no_tls
          obligations:
            - id: auth.obligation.lua_action.dispatch
              args:
                action: tls_encryption

      - name: standard_relay_domain_error_tempfail
        stage: pre_auth
        require_checks: [relay_domains]
        if:
          attribute: auth.relay_domain.error
          is: true
        then:
          decision: tempfail
          outcome_marker: auth.outcome.relay_domain_error
          fsm_event_marker: auth.fsm.event.pre_auth_tempfail
          response_marker: auth.response.tempfail

      - name: standard_relay_domain_reject
        stage: pre_auth
        require_checks: [relay_domains]
        if:
          all:
            - attribute: auth.relay_domain.present
              is: true
            - attribute: auth.relay_domain.known
              is: false
        then:
          decision: deny
          outcome_marker: auth.outcome.relay_domain_reject
          fsm_event_marker: auth.fsm.event.pre_auth_deny
          response_marker: auth.response.fail
          obligations:
            - id: auth.obligation.lua_action.dispatch
              args:
                action: relay_domains

      - name: standard_rbl_error_tempfail
        stage: pre_auth
        require_checks: [rbl]
        if:
          attribute: auth.rbl.error
          is: true
        then:
          decision: tempfail
          outcome_marker: auth.outcome.rbl_error
          fsm_event_marker: auth.fsm.event.pre_auth_tempfail
          response_marker: auth.response.tempfail

      - name: standard_rbl_reject
        stage: pre_auth
        require_checks: [rbl]
        if:
          attribute: auth.rbl.threshold_reached
          is: true
        then:
          decision: deny
          outcome_marker: auth.outcome.rbl_reject
          fsm_event_marker: auth.fsm.event.pre_auth_deny
          response_marker: auth.response.fail
          obligations:
            - id: auth.obligation.lua_action.dispatch
              args:
                action: rbl

      - name: standard_lua_environment_geo_block_error
        stage: pre_auth
        require_checks: [lua_environment_geo_block]
        if:
          attribute: auth.lua.environment.geo_block.error
          is: true
        then:
          decision: tempfail
          outcome_marker: auth.outcome.lua_environment.geo_block.error
          fsm_event_marker: auth.fsm.event.pre_auth_tempfail
          response_marker: auth.response.tempfail

      - name: standard_lua_environment_geo_block_trigger
        stage: pre_auth
        require_checks: [lua_environment_geo_block]
        if:
          attribute: auth.lua.environment.geo_block.triggered
          is: true
        then:
          decision: deny
          outcome_marker: auth.outcome.lua_environment.geo_block.reject
          fsm_event_marker: auth.fsm.event.pre_auth_deny
          response_marker: auth.response.fail
          response_message:
            from: attribute_detail
            attribute: auth.lua.environment.geo_block.triggered
            detail: status_message
            fallback: "Invalid login or password"
          obligations:
            - id: auth.obligation.lua_action.dispatch
              args:
                action: lua
                feature: lua_environment_geo_block

      - name: standard_lua_environment_geo_block_abort
        stage: pre_auth
        require_checks: [lua_environment_geo_block]
        if:
          attribute: auth.lua.environment.geo_block.abort
          is: true
        then:
          decision: neutral
          outcome_marker: auth.outcome.pre_auth_ok
          fsm_event_marker: auth.fsm.event.pre_auth_ok
          control:
            skip_remaining_stage_checks: true

      - name: standard_backend_tempfail
        stage: auth_decision
        if:
          attribute: auth.backend.tempfail
          is: true
        then:
          decision: tempfail
          outcome_marker: auth.outcome.backend_tempfail
          fsm_event_marker: auth.fsm.event.auth_tempfail
          response_marker: auth.response.tempfail

      - name: standard_empty_username
        stage: auth_decision
        operations: [authenticate, lookup_identity]
        if:
          attribute: auth.backend.empty_username
          is: true
        then:
          decision: tempfail
          outcome_marker: auth.outcome.empty_username
          fsm_event_marker: auth.fsm.event.auth_empty_user
          response_marker: auth.response.tempfail

      - name: standard_empty_password
        stage: auth_decision
        operations: [authenticate]
        if:
          attribute: auth.backend.empty_password
          is: true
        then:
          decision: deny
          outcome_marker: auth.outcome.empty_password
          fsm_event_marker: auth.fsm.event.auth_empty_pass
          response_marker: auth.response.fail

      - name: standard_lua_subject_billing_lock_error
        stage: auth_decision
        require_checks: [lua_subject_billing_lock]
        if:
          attribute: auth.lua.subject.billing_lock.error
          is: true
        then:
          decision: tempfail
          outcome_marker: auth.outcome.lua_subject.billing_lock.error
          fsm_event_marker: auth.fsm.event.auth_tempfail
          response_marker: auth.response.tempfail

      - name: standard_lua_subject_billing_lock_reject
        stage: auth_decision
        require_checks: [lua_subject_billing_lock]
        if:
          attribute: auth.lua.subject.billing_lock.rejected
          is: true
        then:
          decision: deny
          outcome_marker: auth.outcome.lua_subject.billing_lock.reject
          fsm_event_marker: auth.fsm.event.auth_deny
          response_marker: auth.response.fail
          response_message:
            from: attribute_detail
            attribute: auth.lua.subject.billing_lock.rejected
            detail: status_message
            fallback: "Invalid login or password"

      - name: standard_auth_success
        stage: auth_decision
        if:
          attribute: auth.authenticated
          is: true
        then:
          decision: permit
          outcome_marker: auth.outcome.auth_success
          fsm_event_marker: auth.fsm.event.auth_permit
          response_marker: auth.response.ok

      - name: standard_auth_failure
        stage: auth_decision
        if:
          attribute: auth.authenticated
          is: false
        then:
          decision: deny
          outcome_marker: auth.outcome.auth_failure
          fsm_event_marker: auth.fsm.event.auth_deny
          response_marker: auth.response.fail

      - name: standard_lookup_identity_success
        stage: auth_decision
        operations: [lookup_identity]
        if:
          attribute: auth.identity.found
          is: true
        then:
          decision: permit
          outcome_marker: auth.outcome.lookup_identity_success
          fsm_event_marker: auth.fsm.event.auth_permit
          response_marker: auth.response.ok

      - name: standard_lookup_identity_failure
        stage: auth_decision
        operations: [lookup_identity]
        if:
          attribute: auth.identity.found
          is: false
        then:
          decision: deny
          outcome_marker: auth.outcome.lookup_identity_failure
          fsm_event_marker: auth.fsm.event.auth_deny
          response_marker: auth.response.fail

      - name: standard_list_accounts_success
        stage: auth_decision
        operations: [list_accounts]
        require_checks: [account_provider]
        if:
          attribute: auth.account_provider.completed
          is: true
        then:
          decision: permit
          outcome_marker: auth.outcome.list_accounts_success
          fsm_event_marker: auth.fsm.event.auth_permit
          response_marker: auth.response.list_accounts.ok

      - name: standard_list_accounts_tempfail
        stage: auth_decision
        operations: [list_accounts]
        require_checks: [account_provider]
        if:
          attribute: auth.account_provider.tempfail
          is: true
        then:
          decision: tempfail
          outcome_marker: auth.outcome.list_accounts_tempfail
          fsm_event_marker: auth.fsm.event.auth_tempfail
          response_marker: auth.response.tempfail

      - name: standard_list_accounts_failure
        stage: auth_decision
        operations: [list_accounts]
        require_checks: [account_provider]
        if:
          attribute: auth.account_provider.completed
          is: false
        then:
          decision: deny
          outcome_marker: auth.outcome.list_accounts_failure
          fsm_event_marker: auth.fsm.event.auth_deny
          response_marker: auth.response.fail

      - name: standard_default_deny
        stage: auth_decision
        operations: [authenticate, lookup_identity, list_accounts]
        if:
          always: true
        then:
          decision: deny
          outcome_marker: auth.outcome.default_deny
          fsm_event_marker: auth.fsm.event.auth_deny
          response_marker: auth.response.fail
```

Two explicit notes:

1. the target configuration intentionally makes brute force a first-class pre-auth policy input instead of preserving a direct gate as the target model;
2. the target configuration intentionally leaves hooks and backend health checks outside the decision-check list.

---

## 17. Implementation Reference Tables

These tables are implementation checklists. They are not a second policy language and they must not replace the registries described earlier in this specification. If implementation work adds, removes, or renames a registry entry, the relevant table must be updated in the same change.

### 17.1 Check-Type Registry

The check-type registry is built into Go. Lua registry scripts may register attributes, but they do not register new check types.

| Check type | Stage | Operations | Config reference | Minimum emitted attributes | Observe-safe default | Side-effect rule |
|---|---|---|---|---|---|---|
| `builtin.brute_force` | `pre_auth` | `authenticate` | `auth.controls.brute_force` | `auth.brute_force.triggered`, `auth.brute_force.error` | false | Check evaluation must not directly choose the final response; counter and learning updates happen through registered obligations. |
| `builtin.tls_encryption` | `pre_auth` | `authenticate`, `lookup_identity` | `auth.controls.tls_encryption` | `auth.tls.secure` | true | Read-only request inspection. |
| `builtin.relay_domains` | `pre_auth` | `authenticate` | `auth.controls.relay_domains` | `auth.relay_domain.present`, `auth.relay_domain.known`, `auth.relay_domain.error` | true | Read-only request/config inspection. |
| `builtin.rbl` | `pre_auth` | `authenticate`, `lookup_identity` | `auth.controls.rbl` | `auth.rbl.threshold_reached`, `auth.rbl.error` | false | May perform network lookups or cache access; non-observe-safe unless implemented as a provably read-only/cache-only check. |
| `lua.environment` | `pre_auth` | default `authenticate`, explicit opt-in allowed | one named `auth.policy.attribute_sources.lua.environment.<name>` entry | `auth.lua.environment.<name>.triggered`, `auth.lua.environment.<name>.abort`, `auth.lua.environment.<name>.error`, plus registered Lua attributes | false | Arbitrary Lua may have side effects; observe execution requires explicit `observe_safe: true`. |
| `backend.ldap` | `auth_backend` | `authenticate`, `lookup_identity` | `auth.backends.ldap` | `auth.authenticated`, `auth.identity.found`, `auth.backend.tempfail`, `auth.backend.empty_username`, `auth.backend.empty_password` | false | Performs backend I/O and may update backend-local telemetry or caches. |
| `backend.lua` | `auth_backend` | `authenticate`, `lookup_identity` | `auth.backends.lua.backend` | `auth.authenticated`, `auth.identity.found`, `auth.backend.tempfail`, `auth.backend.empty_username`, `auth.backend.empty_password`, plus registered Lua attributes | false | Arbitrary Lua may have side effects; observe execution requires explicit `observe_safe: true`. |
| `lua.subject` | `subject_analysis` | default `authenticate`, explicit opt-in allowed | one named `auth.policy.attribute_sources.lua.subject.<name>` entry | `auth.lua.subject.<name>.rejected`, `auth.lua.subject.<name>.error`, plus registered Lua attributes | false | Arbitrary Lua may have side effects and may depend on `lualib.Context`. |
| `backend.account_provider` | `account_provider` | `list_accounts` | account-provider config under `auth.backends` | `auth.account_provider.completed`, `auth.account_provider.tempfail` | false | Performs backend I/O; the account list is response data and must not become a policy attribute. |

Implicit request-context emitters are not configured as checks. They populate request-scoped attributes such as `request.operation`, `request.time.now`, `request.client.ip`, `request.protocol`, and `auth.tls.secure` before policy evaluation reaches the relevant stage.

### 17.2 Minimum Built-In Attribute Registry

The Go built-in registry must include at least these attributes. Lua-generated script-specific attributes use the same metadata model and must be present in the immutable `PolicyRuntimeSnapshot` before any policy is compiled.

| Attribute | Stage | Operations | Type | Details | Producer |
|---|---|---|---|---|---|
| `request.operation` | `pre_auth` | all | string enum | none | request context |
| `request.time.now` | `pre_auth` | all | datetime | none | request context |
| `request.client.ip` | `pre_auth` | all | ip | none | request context |
| `request.protocol` | `pre_auth` | all | string enum | none | request context |
| `auth.brute_force.triggered` | `pre_auth` | `authenticate` | bool | `rule`, `client_net`, `repeating` | `builtin.brute_force` |
| `auth.brute_force.error` | `pre_auth` | `authenticate` | bool | `reason_code`, `retryable` | `builtin.brute_force` |
| `auth.tls.secure` | `pre_auth` | `authenticate`, `lookup_identity` | bool | none | request context or `builtin.tls_encryption` |
| `auth.relay_domain.present` | `pre_auth` | `authenticate` | bool | `domain` | `builtin.relay_domains` |
| `auth.relay_domain.known` | `pre_auth` | `authenticate` | bool | `domain` | `builtin.relay_domains` |
| `auth.relay_domain.error` | `pre_auth` | `authenticate` | bool | `reason_code`, `retryable` | `builtin.relay_domains` |
| `auth.rbl.threshold_reached` | `pre_auth` | `authenticate`, `lookup_identity` | bool | `lists` | `builtin.rbl` |
| `auth.rbl.error` | `pre_auth` | `authenticate`, `lookup_identity` | bool | `reason_code`, `retryable` | `builtin.rbl` |
| `auth.lua.environment.<name>.triggered` | `pre_auth` | per script definition | bool | optional public `status_message` | `lua.environment` |
| `auth.lua.environment.<name>.abort` | `pre_auth` | per script definition | bool | none | `lua.environment` |
| `auth.lua.environment.<name>.error` | `pre_auth` | per script definition | bool | `reason_code` | `lua.environment` |
| `auth.authenticated` | `auth_backend` | `authenticate` | bool | `backend` | backend checks |
| `auth.identity.found` | `auth_backend` | `lookup_identity` | bool | `backend` | backend checks |
| `auth.backend.tempfail` | `auth_backend` | `authenticate`, `lookup_identity` | bool | `backend`, `reason_code`, `retryable` | backend checks |
| `auth.backend.empty_username` | `auth_backend` | `authenticate`, `lookup_identity` | bool | none | backend checks |
| `auth.backend.empty_password` | `auth_backend` | `authenticate` | bool | none | backend checks |
| `auth.lua.subject.<name>.rejected` | `subject_analysis` | per script definition | bool | optional public `status_message` | `lua.subject` |
| `auth.lua.subject.<name>.error` | `subject_analysis` | per script definition | bool | `reason_code` | `lua.subject` |
| `auth.account_provider.completed` | `account_provider` | `list_accounts` | bool | `count` | `backend.account_provider` |
| `auth.account_provider.tempfail` | `account_provider` | `list_accounts` | bool | `reason_code`, `retryable` | `backend.account_provider` |

The registry may expose additional typed attributes, but the built-in `standard_auth` policy must not depend on attributes outside this minimum set unless this table and the mapping table below are updated together.

### 17.3 FSM Marker Registry

FSM markers are registered by Go. Policy YAML references marker IDs, not Go enum names.

| Marker | Source | Allowed stage | Transition intent |
|---|---|---|---|
| `auth.fsm.event.parse_ok` | parser | internal | `init` to `input_parsed` |
| `auth.fsm.event.parse_fail` | parser | internal | `init` to `aborted` |
| `auth.fsm.event.pre_auth_ok` | policy or stage orchestration | `pre_auth` | continue from `input_parsed` to `pre_auth_checked` |
| `auth.fsm.event.pre_auth_deny` | policy | `pre_auth` | terminate as `auth_fail` |
| `auth.fsm.event.pre_auth_tempfail` | policy | `pre_auth` | terminate as `auth_tempfail` |
| `auth.fsm.event.pre_auth_abort` | policy or stage control | `pre_auth` | terminate as `aborted` |
| `auth.fsm.event.auth_evaluated` | stage orchestration | internal | continue from `pre_auth_checked` to `auth_checked` |
| `auth.fsm.event.account_provider_evaluated` | stage orchestration | internal | continue from `pre_auth_checked` to `account_provider_checked` |
| `auth.fsm.event.auth_permit` | policy | `auth_decision` | terminal permit for the active operation |
| `auth.fsm.event.auth_deny` | policy | `auth_decision` | terminal deny for the active operation |
| `auth.fsm.event.auth_tempfail` | policy | `auth_decision` | terminal temporary failure for the active operation |
| `auth.fsm.event.auth_empty_user` | policy | `auth_decision` | terminal empty-user behavior |
| `auth.fsm.event.auth_empty_pass` | policy | `auth_decision` | terminal empty-password behavior |
| `auth.fsm.event.basic_auth_ok` | caller-auth or backchannel auth | internal | terminal caller-auth success path where applicable |
| `auth.fsm.event.basic_auth_fail` | caller-auth or backchannel auth | internal | terminal caller-auth failure path where applicable |
| `auth.fsm.event.abort` | runtime | internal | abort from any non-terminal state |

Only policy-source markers may be referenced by operator policies. Internal markers are produced by parsing, caller-authentication, or stage orchestration code.

### 17.4 Response Marker Registry

Response markers select transport-specific response profiles. They do not hard-code a single HTTP status, header shape, or gRPC payload in YAML.

| Response marker | Intended decision | Required response profiles |
|---|---|---|
| `auth.response.ok` | `permit` | HTTP JSON, HTTP CBOR, Nginx auth-request, header-style HTTP, plain HTTP, gRPC AuthService, gRPC LookupIdentity, IdP browser/OIDC/SAML/device |
| `auth.response.fail` | `deny` | HTTP JSON, HTTP CBOR, Nginx auth-request, header-style HTTP, plain HTTP, HTTP list-accounts, gRPC AuthService, gRPC LookupIdentity, gRPC ListAccounts, IdP browser/OIDC/SAML/device |
| `auth.response.tempfail` | `tempfail` | HTTP JSON, HTTP CBOR, Nginx auth-request, header-style HTTP, plain HTTP, HTTP list-accounts, gRPC AuthService, gRPC LookupIdentity, gRPC ListAccounts, IdP browser/OIDC/SAML/device |
| `auth.response.tempfail.no_tls` | `tempfail` | same as `auth.response.tempfail`, with the current TLS-required external message preserved |
| `auth.response.list_accounts.ok` | `permit` for `list_accounts` | HTTP list-accounts JSON/CBOR and gRPC ListAccounts |

Every response marker must define a sanitized default message. A policy-selected public `response_message` detail may override that default only when the selected response profile allows a message body or message field.

### 17.5 Obligation and Advice Registry

Obligations and advice are registered built-ins. Policy YAML may reference IDs and typed arguments, but it must not register executable logic.

| ID | Kind | Timing | Side effect | Failure behavior |
|---|---|---|---|---|
| `auth.obligation.brute_force.update` | obligation | request-time enforcement | update brute-force counters, toleration, and learning state according to current semantics | preserve current failure semantics; if the current path tempfails, policy enforcement must tempfail |
| `auth.obligation.lua_action.dispatch` | obligation | request-time enforcement | dispatch an existing configured synchronous Lua action with sanitized decision context | preserve current action failure, timeout, and learning semantics; the action must not change the selected decision, FSM state, response marker, response message, or emit new policy facts |
| `auth.obligation.lua_post_action.enqueue` | obligation | enqueue during enforcement, execute asynchronously after response | enqueue an existing configured Lua POST-Action with sanitized decision context | enqueue failure is logged and metered; actual POST-Action execution never changes the selected decision, FSM state, response marker, or response message |
| `auth.advice.audit_reason` | advice | reporting/logging | include a sanitized audit reason in logs, reports, or POST-Action context | failure or omission must not change the decision or response |

### 17.6 Parity Test Matrix

Phase 0 must freeze the current external behavior for every row in this matrix. Later phases must prove that the built-in `standard_auth` path produces the same externally visible behavior unless a phase explicitly changes the contract.

| Surface | Operation | Success parity | Deny parity | Tempfail parity | Special assertions |
|---|---|---|---|---|---|
| HTTP JSON auth endpoint | `authenticate` | current status, JSON fields, headers, and body | current invalid-credentials response, including Lua public status-message override | current temporary-failure response and retry semantics | response marker, selected message source, FSM terminal state, logs, metrics, and trace attributes match Phase 0 fixtures |
| HTTP CBOR auth endpoint | `authenticate` | current CBOR media type and payload shape | current CBOR deny payload | current CBOR tempfail payload | CBOR and JSON semantics match after decoding; no policy-only fields leak by default |
| Nginx auth-request | `authenticate` | current auth-request success status and headers | current deny status and headers | current tempfail status and headers | status-message behavior matches current header/body rules for this surface |
| Header-style HTTP auth | `authenticate` | current success headers | current deny headers | current tempfail headers | policy response markers render through the existing header profile |
| Plain HTTP auth | `authenticate` | current plain success response | current plain deny response | current plain tempfail response | no structured report data appears in the response |
| HTTP `mode=no-auth` | `lookup_identity` | current identity-found response | current identity-not-found response | current lookup tempfail response | password verification is not executed; brute force is not part of the default check plan unless explicitly configured |
| gRPC `AuthService` authenticate | `authenticate` | current AuthService success payload | current AuthService denial payload | current AuthService temporary-failure payload | normal auth denials are payload decisions, not gRPC status errors |
| gRPC `LookupIdentity` | `lookup_identity` | current lookup success payload | current lookup failure payload | current lookup tempfail payload | caller authentication errors remain gRPC errors outside policy denial |
| HTTP `mode=list-accounts` | `list_accounts` | current account-list response, including empty-list semantics | current account-list denial response | current account-provider tempfail response | caller auth and scope rejection remain prerequisites outside policy denial; account list is not a policy attribute |
| gRPC `ListAccounts` | `list_accounts` | current ListAccounts payload, including empty-list semantics | current ListAccounts denial payload | current ListAccounts tempfail payload | caller auth and scope rejection remain gRPC errors outside policy denial |
| IdP browser login | `authenticate` or `lookup_identity` as flow requires | current successful login continuation | current browser-facing deny page/message | current browser-facing temporary-failure page/message | MFA/session state must not be advanced on policy denial |
| IdP OIDC/SAML/device flows | `authenticate` or `lookup_identity` as flow requires | current protocol-specific success continuation | current protocol-specific denial behavior | current protocol-specific temporary-failure behavior | protocol errors stay protocol errors; auth-policy denial is rendered through the IdP response profile |

Every matrix row must be tested for at least these outcome classes:

1. built-in default success;
2. built-in default deny;
3. built-in default tempfail;
4. Lua environment source deny with public status message;
5. Lua subject source deny with public status message;
6. backend tempfail;
7. default deny when no final policy matches;
8. observe-mode mismatch reporting without side effects.

### 17.7 `standard_auth` Mapping Checklist

The built-in `standard_auth` policy set uses ordered first-match evaluation. The rows below are implementation requirements, not examples. The default-deny row must remain the final `auth_decision` rule.

For `authenticate`/`pre_auth`, rows 10 and 20 are evaluated at the built-in checkpoint immediately after the `brute_force` check. A terminal result from either row stops the remaining pre-auth check plan. Rows 30 and later run only when the brute-force checkpoint is neutral. This preserves current default behavior without injecting implicit `after` dependencies into TLS, relay-domain, RBL, or Lua-control checks.

| Order | Operation | Stage | Rule | Required checks | Condition | Decision | FSM marker | Response marker | Required side effects |
|---:|---|---|---|---|---|---|---|---|---|
| 10 | `authenticate` | `pre_auth` | `standard_brute_force_error_tempfail` | `brute_force` | `auth.brute_force.error is true` | `tempfail` | `auth.fsm.event.pre_auth_tempfail` | `auth.response.tempfail` | none beyond current error accounting |
| 20 | `authenticate` | `pre_auth` | `standard_brute_force_deny` | `brute_force` | `auth.brute_force.triggered is true` | `deny` | `auth.fsm.event.pre_auth_deny` | `auth.response.fail` | `auth.obligation.brute_force.update`; `auth.obligation.lua_action.dispatch(action=brute_force)`; `auth.obligation.lua_post_action.enqueue(action=brute_force)` if configured |
| 30 | `authenticate`, `lookup_identity` | `pre_auth` | `standard_tls_enforcement` | `tls_encryption` | `auth.tls.secure is false` | `tempfail` | `auth.fsm.event.pre_auth_tempfail` | `auth.response.tempfail.no_tls` | `auth.obligation.lua_action.dispatch(action=tls_encryption)` if configured |
| 40 | `authenticate` | `pre_auth` | `standard_relay_domain_error_tempfail` | `relay_domains` | `auth.relay_domain.error is true` | `tempfail` | `auth.fsm.event.pre_auth_tempfail` | `auth.response.tempfail` | none |
| 50 | `authenticate` | `pre_auth` | `standard_relay_domain_reject` | `relay_domains` | `auth.relay_domain.present is true` and `auth.relay_domain.known is false` | `deny` | `auth.fsm.event.pre_auth_deny` | `auth.response.fail` | `auth.obligation.lua_action.dispatch(action=relay_domains)` if configured |
| 60 | `authenticate`, `lookup_identity` | `pre_auth` | `standard_rbl_error_tempfail` | `rbl` | `auth.rbl.error is true` | `tempfail` | `auth.fsm.event.pre_auth_tempfail` | `auth.response.tempfail` | none |
| 70 | `authenticate`, `lookup_identity` | `pre_auth` | `standard_rbl_reject` | `rbl` | `auth.rbl.threshold_reached is true` | `deny` | `auth.fsm.event.pre_auth_deny` | `auth.response.fail` | `auth.obligation.lua_action.dispatch(action=rbl)` if configured |
| 80 | `authenticate` | `pre_auth` | `standard_lua_environment_<name>_error` | named Lua environment source | `auth.lua.environment.<name>.error is true` | `tempfail` | `auth.fsm.event.pre_auth_tempfail` | `auth.response.tempfail` | none |
| 90 | `authenticate` | `pre_auth` | `standard_lua_environment_<name>_trigger` | named Lua environment source | `auth.lua.environment.<name>.triggered is true` | `deny` | `auth.fsm.event.pre_auth_deny` | `auth.response.fail` | select public `status_message` detail if present; `auth.obligation.lua_action.dispatch(action=lua, feature=<check_name>)` if configured |
| 100 | `authenticate` | `pre_auth` | `standard_lua_environment_<name>_abort` | named Lua environment source | `auth.lua.environment.<name>.abort is true` | `neutral` | `auth.fsm.event.pre_auth_ok` | none | `skip_remaining_stage_checks` |
| 110 | all | `pre_auth` | implicit pre-auth pass | active pre-auth plan | no prior first-match terminal result | `neutral` | `auth.fsm.event.pre_auth_ok` | none | continue to the operation-specific next stage |
| 200 | `authenticate`, `lookup_identity` | `auth_decision` | `standard_backend_tempfail` | backend plan | `auth.backend.tempfail is true` | `tempfail` | `auth.fsm.event.auth_tempfail` | `auth.response.tempfail` | none |
| 210 | `authenticate`, `lookup_identity` | `auth_decision` | `standard_empty_username` | backend plan | `auth.backend.empty_username is true` | `tempfail` | `auth.fsm.event.auth_empty_user` | `auth.response.tempfail` | preserve current empty-username accounting |
| 220 | `authenticate` | `auth_decision` | `standard_empty_password` | backend plan | `auth.backend.empty_password is true` | `deny` | `auth.fsm.event.auth_empty_pass` | `auth.response.fail` | preserve current empty-password accounting |
| 230 | `authenticate` | `auth_decision` | `standard_lua_subject_<name>_error` | named Lua subject source | `auth.lua.subject.<name>.error is true` | `tempfail` | `auth.fsm.event.auth_tempfail` | `auth.response.tempfail` | none |
| 240 | `authenticate` | `auth_decision` | `standard_lua_subject_<name>_reject` | named Lua subject source | `auth.lua.subject.<name>.rejected is true` | `deny` | `auth.fsm.event.auth_deny` | `auth.response.fail` | select public `status_message` detail if present |
| 250 | `authenticate` | `auth_decision` | `standard_auth_success` | backend and subject sources | `auth.authenticated is true` | `permit` | `auth.fsm.event.auth_permit` | `auth.response.ok` | enqueue success POST-Actions only through registered obligations if current behavior requires it |
| 260 | `authenticate` | `auth_decision` | `standard_auth_failure` | backend and subject sources | `auth.authenticated is false` | `deny` | `auth.fsm.event.auth_deny` | `auth.response.fail` | preserve current failure accounting |
| 300 | `lookup_identity` | `auth_decision` | `standard_lookup_identity_success` | backend plan | `auth.identity.found is true` | `permit` | `auth.fsm.event.auth_permit` | `auth.response.ok` | none |
| 310 | `lookup_identity` | `auth_decision` | `standard_lookup_identity_failure` | backend plan | `auth.identity.found is false` | `deny` | `auth.fsm.event.auth_deny` | `auth.response.fail` | none |
| 400 | `list_accounts` | `auth_decision` | `standard_list_accounts_tempfail` | `account_provider` | `auth.account_provider.tempfail is true` | `tempfail` | `auth.fsm.event.auth_tempfail` | `auth.response.tempfail` | none |
| 410 | `list_accounts` | `auth_decision` | `standard_list_accounts_success` | `account_provider` | `auth.account_provider.completed is true` | `permit` | `auth.fsm.event.auth_permit` | `auth.response.list_accounts.ok` | none |
| 420 | `list_accounts` | `auth_decision` | `standard_list_accounts_failure` | `account_provider` | `auth.account_provider.completed is false` | `deny` | `auth.fsm.event.auth_deny` | `auth.response.fail` | none |
| 900 | all | `auth_decision` | `standard_default_deny` | none | `always` | `deny` | `auth.fsm.event.auth_deny` | `auth.response.fail` | none |

Caller authentication failures, missing gRPC bearer/basic credentials, insufficient list-account scope, malformed requests, and transport errors are not `standard_auth` denial rows. They remain prerequisites or transport/runtime errors outside policy denial.

---

## 18. Migration Strategy

The migration must be incremental, test-backed, observable, and behavior-preserving until a phase explicitly makes a new path authoritative. Temporary adapters are allowed only as migration tools; they are not part of the target architecture.

### 18.1 Phase Completion Rules

Every implementation phase must satisfy these rules before the next phase starts:

1. focused reproducer or parity tests exist before behavior-changing code is written;
2. current external behavior is unchanged unless the phase explicitly says otherwise;
3. new runtime paths have Prometheus metrics, OpenTelemetry spans, structured logs, and debug-module coverage where applicable;
4. new config paths have `mapstructure` tags, schema-index support, structured config errors, and dump support;
5. new policy reports and logs follow the redaction rules from sections 15.2 through 15.4;
6. new policy code has package-local unit tests and at least one integration or parity test at the auth boundary;
7. reload behavior is atomic: a failed policy snapshot build must leave the previous snapshot active;
8. phase completion includes a short implementation note listing active temporary adapters and the planned phase that removes them.

The phases are intentionally narrower than subsystem boundaries. Large phases may be implemented as PR-sized slices, for example one check type or one response surface at a time, but the next numbered phase must not start until the whole current phase satisfies the completion rules. No phase may combine a new policy compiler surface, an authoritative decision switch, and an authoritative FSM switch.

### Phase 0: Freeze Current Behavior and Parity Corpus

Add or keep regression tests for:

1. brute-force direct block;
2. brute-force learning behavior;
3. Lua environment source trigger;
4. Lua environment source abort;
5. TLS tempfail;
6. relay-domain reject;
7. RBL reject;
8. backend success, failure, and tempfail;
9. Lua subject source reject and Lua-provided status message;
10. auth-FSM feature and password transitions;
11. lookup-identity / no-auth success, failure, and tempfail parity;
12. list-accounts success, scope/caller-auth rejection, and response-media parity;
13. response rendering parity for HTTP JSON, HTTP CBOR, Nginx auth-request, header-style HTTP, plain HTTP, HTTP list-accounts, gRPC AuthService, gRPC ListAccounts, and IdP auth flows.

The phase is complete only when these tests can detect regressions without the policy layer being present.

### Phase 1: Policy Skeleton and Observability Foundation

Add the internal policy package skeleton without changing decisions.

Goals:

1. define core package boundaries for registry, compiler, runtime, reports, metrics, tracing, and enforcement adapters;
2. add `DbgPolicy` and `DbgPolicyName = "policy"`;
3. add policy metric definitions and no-op-safe instrumentation helpers;
4. add the `nauthilus/policy` tracer scope;
5. add empty `DecisionReport` and policy log helpers with redaction tests;
6. do not add user-facing policy config yet;
7. do not alter current auth decisions.

### Phase 2: Registry, AST, Sets, and Snapshot Compiler

Add config structs and compilation without making request-time policy evaluation authoritative.

Implementation requirements:

1. decode `auth.policy` YAML into config structs only;
2. register Go built-in policy attributes;
3. execute Lua registry scripts during snapshot build;
4. compile network sets and time-window sets;
5. build and structurally validate the condition AST;
6. type-check conditions against the effective attribute registry;
7. validate response markers, FSM markers, obligations, advice, `after`, and `require_checks`;
8. build an immutable `PolicyRuntimeSnapshot`;
9. activate snapshots atomically at startup and reload;
10. keep the old snapshot active if reload validation or compilation fails;
11. expose `-d`, `-n`, and config-check output for the new config surface;
12. do not execute policy checks as the production decision path yet.

### Phase 3: CheckResult Collection and Explicit Check Plan Adapters

Wrap current mechanisms so they emit structured `CheckResult` values and registered attributes while current decisions remain authoritative.

Implementation requirements:

1. collect `CheckResult` values for brute force, Lua environment sources, TLS, relay domains, RBL, backends, Lua subject sources, and account providers;
2. create one check result per named Lua environment source and Lua subject source;
3. preserve Lua `lualib.Context` behavior through compiled `after` ordering;
4. validate `run_if`, `operations`, `after`, and `require_checks` against the compiled plan;
5. record missing, skipped, error, and unavailable facts in reports;
6. instrument check execution with policy metrics and OTel spans;
7. do not let collected check results change the production decision yet.

### Phase 4: Built-In `standard_auth` Shadow Evaluation

Evaluate the built-in default policy from collected check results, but keep current decisions authoritative.

Implementation requirements:

1. define the built-in `standard_auth` policy set from current behavior;
2. evaluate ordered first-match policies exactly as defined in section 11.5;
3. derive response markers, response messages, outcome markers, and FSM event markers;
4. compare the policy result with the current production result;
5. compare selected response message and response surface rendering;
6. compare planned obligations without executing shadow obligations;
7. report mismatches through logs, reports, metrics, and OTel spans;
8. keep current output authoritative.

### Phase 5: Config Conversion Tool and Target Config Cut

Update the config conversion tool before target policy config becomes mandatory for migrated installations.

The repository tool is currently:

```text
scripts/convert-config-v1-to-v2.py
```

Conversion requirements:

1. rewrite old `when_no_auth` usage into policy `operations`, normally by adding `lookup_identity` where the old mechanism was enabled for no-auth;
2. rewrite old `when_authenticated` usage into policy check scheduling, normally `run_if.auth_state: authenticated`;
3. rewrite old `when_unauthenticated` usage into policy check scheduling, normally `run_if.auth_state: unauthenticated`;
4. generate one `lua.environment` policy check for each Lua environment source script entry;
5. generate one `lua.subject` policy check for each Lua subject source script entry;
6. do not generate aggregate `lua_environments` or `lua_subjects` policy checks;
7. generate stable check names and script-specific generated attributes from the Lua script name;
8. generate policy check entries rather than preserving old mechanism-local scheduling flags;
9. rewrite old Lua `depends_on` into check-plan `after` dependencies using the generated check names;
10. preserve the Lua dependency tree so scripts can continue to exchange request-local data through `lualib.Context`;
11. preserve current behavior through generated `standard_auth`-equivalent policy checks and policies;
12. preserve Lua script execution order through the generated policy check plan;
13. emit target config that contains no `when_no_auth`, `when_authenticated`, or `when_unauthenticated` keys.

After the hard cut, configs that still contain old `when_*` keys are invalid through the existing unknown-key semantics. They do not need a special compatibility error path.

### Phase 6: Target FSM Adapter and Compare

Introduce target FSM event markers and compare target FSM behavior while current FSM behavior remains authoritative.

Step 1: introduce target event markers and a temporary adapter.

1. policy decisions emit target FSM event markers from section 9.7;
2. the adapter maps target `pre_auth_*` markers to current `features_*` events;
3. the adapter maps target final auth markers to current `password_*` events;
4. `account_provider_checked` and operation-specific terminal semantics are represented in the target marker model even if the current FSM still needs adapter mapping;
5. event-marker validation validates target markers, not current internal event names;
6. the adapter is private implementation code and must not be exposed in YAML, reports as a stable name, registry scripts, or config conversion output.

Step 2: run target FSM comparison.

1. the current FSM remains authoritative for production behavior;
2. the target FSM evaluates the same target event-marker sequence in parallel;
3. comparison reports include current terminal state, target terminal state, current internal event path, target event path, selected policy name, operation, and response marker;
4. mismatches are reportable diagnostics and must not alter the production response;
5. tests cover all allowed and rejected transitions from section 9.7;
6. tests cover terminal states rejecting outgoing transitions;
7. parity tests cover `authenticate`, `lookup_identity`, and `list_accounts`.

### Phase 7: Policy-Owned Runtime Obligations

Move decision-dependent request-time side effects behind registered policy obligations before any policy decision path becomes production-authoritative.

Implementation requirements:

1. register `auth.obligation.brute_force.update`, `auth.obligation.lua_action.dispatch`, and `auth.obligation.lua_post_action.enqueue` with typed argument validation;
2. implement a central obligation executor that receives the selected `PolicyDecision` and executes only the obligations attached to that decision;
3. refactor the existing synchronous Lua action dispatch behavior behind `auth.obligation.lua_action.dispatch` without changing configured Lua action scripts, context objects, timeout handling, or action failure semantics;
4. refactor brute-force counter, toleration, repeating, and learning updates behind `auth.obligation.brute_force.update`;
5. refactor Lua POST-Action enqueueing behind `auth.obligation.lua_post_action.enqueue`;
6. make observe mode report planned obligations but execute none of them;
7. make action and POST-Action reports use registered obligation IDs and bounded argument values;
8. preserve Phase 0 parity for `brute_force`, `lua`, `tls_encryption`, `relay_domains`, and `rbl` action dispatch when the built-in `standard_auth` policy selects the matching decision;
9. add tests proving that a custom policy decision without `auth.obligation.lua_action.dispatch` does not run a synchronous Lua action even when the underlying check emitted a triggering attribute;
10. add tests proving that a custom policy decision with `auth.obligation.lua_action.dispatch` runs the configured synchronous Lua action exactly once;
11. remove mechanism-owned synchronous action dispatch from any path that is already policy-authoritative.

Temporary compatibility adapters may still exist only for non-policy-authoritative paths. Every remaining adapter must be listed in the phase completion note with the cleanup phase that removes it.

### Phase 8: Built-In Policy Becomes Authoritative

Make `standard_auth` the production decision path when no custom policy is configured.

Implementation requirements:

1. current direct decision calls and mechanism-owned action dispatch for in-scope checks are routed through policy orchestration;
2. `standard_auth` applies decisions, response markers, response messages, obligations, advice, and FSM event markers;
3. external behavior remains identical to Phase 0 parity expectations;
4. policy-owned obligations execute only from the authoritative policy decision;
5. shadow comparison against the old direct path remains available only as a temporary migration diagnostic;
6. custom policies are still not authoritative in this phase.

### Phase 9: Target FSM Becomes Authoritative

Make the target FSM from section 9.7 authoritative and remove the temporary FSM adapter.

Implementation requirements:

1. production enforcement applies target event markers directly to the target FSM;
2. old `features_*` and `password_*` event names are removed from the auth decision path;
3. tests assert that policy decisions no longer depend on adapter mappings;
4. no target config, registry, metric, trace, log, or report surface relies on old event names;
5. target-FSM transition metrics replace adapter comparison metrics for production state tracking.

### Phase 10: Custom Policy Observe Mode

Enable custom policies in observe mode.

Implementation requirements:

1. the built-in default policy remains authoritative;
2. custom policy evaluation runs in parallel;
3. custom policy obligations, Lua POST-Action enqueueing, counters, learning updates, and mutable side effects do not execute;
4. custom-only checks run only when observe-safe;
5. non-observe-safe custom-only checks are reported as unavailable;
6. mismatch logs compare effect, selected policy name, outcome marker, FSM marker, response marker, selected response-message source, rendered sanitized response message, and terminal state;
7. observe metrics and OTel spans report mismatch type and unavailable facts.

### Phase 11: Custom Policy Enforce for Pre-Auth

Enable custom policy enforcement first for the pre-auth stage.

Initial enforce scope:

1. brute force;
2. Lua environment sources;
3. TLS;
4. relay domains;
5. RBL.

Completion requirements:

1. all pre-auth checks share the same orchestration model;
2. `permit` remains unavailable as a final pre-auth success decision;
3. default-deny semantics still apply at final auth decision;
4. synchronous Lua actions, brute-force updates, and POST-Action enqueueing run only when selected through registered obligations;
5. selected `response_marker` and `response_message` render correctly across HTTP JSON, HTTP CBOR, Nginx auth-request, header-style HTTP, plain HTTP, gRPC AuthService, and IdP auth flows;
6. policy metrics, OTel spans, reports, and debug logs cover custom-policy decisions.

### Phase 12: Custom Policy Enforce for Backend, Subject Sources, and Status Messages

Extend custom policy enforcement to backend and subject-analysis decisions.

Implementation requirements:

1. backend success, failure, tempfail, empty username, and empty password map through policy attributes and final decisions;
2. Lua subject sources emit script-specific attributes and public response-message details;
3. `run_if.auth_state` controls authenticated and unauthenticated subject-source scheduling;
4. Lua POST-Action enqueueing happens only through registered obligations;
5. final response-message selection preserves current Lua status-message behavior where the built-in default policy is used;
6. response rendering parity covers all configured auth transports.

### Phase 13: Custom Policy Enforce for Lookup and Account Listing

Extend custom policy enforcement to non-password authentication operations.

Implementation requirements:

1. HTTP `mode=no-auth`, gRPC `LookupIdentity`, and IdP lookup flows use `lookup_identity`;
2. HTTP `mode=list-accounts` and gRPC `ListAccounts` use `list_accounts`;
3. `account_provider` stage emits account-list status attributes without exposing the account list as a policy attribute;
4. caller authentication and transport authorization remain prerequisites, not policy denials;
5. response rendering parity covers HTTP list-accounts, gRPC ListAccounts, and IdP-specific response profiles.

### Phase 14: Final Cleanup and Hardening

Remove temporary migration scaffolding and close the target architecture.

Completion requirements:

1. remove old direct-gate and direct-action call sites that bypass policy orchestration;
2. remove temporary old-vs-new decision comparison code that is not part of supported observe mode;
3. remove temporary FSM adapter code and old event-name dependencies;
4. ensure no target config, registry, metric, trace, log, or report surface exposes historical names as stable contract;
5. update user-facing docs, config examples, and conversion-tool tests;
6. run the full policy parity suite, package tests, and guardrails.

---

## 19. Final Position

The idea of a Policy Decision Layer is still sound.

However, after the current Nauthilus changes, the correct starting point is no longer:

1. old root configuration blocks,
2. an independent top-level `policy_engine`,
3. a separate legacy-compatible execution path,
4. or a direct brute-force gate outside policy/FSM orchestration.

The correct starting point is:

1. current `config v2`;
2. current canonical config UX;
3. a built-in default policy set that reproduces current behavior when no custom policy is configured;
4. a target auth-FSM that includes pre-auth decisions;
5. first-class brute-force participation in the policy model;
6. current separation between auth controls, auth backends, auth services, and identity concerns.

That is the baseline this specification establishes.
