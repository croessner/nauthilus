# Change Request: Policy-Controlled Scheduler Guards

## Status

Draft for implementation review.

Date: 2026-05-07

## Goal

Move implicit pre-auth bypass behavior, especially loopback handling, out of
hard-coded auth-control logic and into the Policy Decision Layer.

The target model must let operators explicitly skip selected checks only when a
small, typed, request-only scheduler guard matches. Final authorization
decisions remain normal policy rules. Scheduler guards decide whether a check
adapter runs; they do not decide whether authentication is allowed.

This CR is a hard-cut target. After the migration slice is complete, loopback,
empty client IP, backend health checks, or internal callers must not receive a
hidden Go-code bypass. Any bypass that remains must be visible in policy config,
recorded in reports, and removable by deleting the corresponding policy guard.

Example target configuration:

```yaml
auth:
  policy:
    sets:
      networks:
        pre_auth_exempt_sources:
          - 127.0.0.0/8
          - ::1

      time_windows:
        pre_auth_exempt_windows:
          timezone: Europe/Berlin
          days: [sunday]
          intervals:
            - start: "02:00"
              end: "04:00"

    scheduler_guards:
      pre_auth_exempt_source:
        on_missing_attribute: run
        if:
          all:
            - attribute: request.client.ip.present
              is: true
            - attribute: request.client.ip.trusted
              is: true
            - attribute: request.client.ip
              cidr_contains: "@network.pre_auth_exempt_sources"

      pre_auth_exempt_window:
        on_missing_attribute: run
        if:
          attribute: request.time.now
          within_time_window: "@time_window.pre_auth_exempt_windows"

    checks:
      - name: rbl
        type: builtin.rbl
        stage: pre_auth
        operations: [authenticate]
        skip_if: [pre_auth_exempt_source, pre_auth_exempt_window]
        config_ref: auth.controls.rbl
        output: checks.rbl
```

This is intentionally a scheduler feature, not a new final-decision language.
The example names are purpose-based (`pre_auth_exempt_*`) rather than
mechanism-based (`loopback_*`, `maintenance_*`) so deployments can reuse the
same model for loopback, monitoring sources, maintenance windows, or another
explicit operational exemption.

## Background

Several current pre-auth controls treat loopback, and sometimes an empty client
IP, as an implicit allowlisted condition before policy can make an explicit
decision. Examples include Lua environment sources, TLS enforcement, relay
domains, and RBL control paths.

That behavior was practical before policy enforcement existed, but it is no
longer a good target model:

- loopback is an operational convenience, not a universal security authority;
- an empty client IP must not mean loopback;
- client IP can be derived from different transport sources with different
  trust properties;
- pre-auth check scheduling should be visible in reports;
- operators should be able to reason about and review bypasses in policy config.

The current policy language can already express request IP and time conditions
in normal policy rules:

```yaml
if:
  all:
    - attribute: request.client.ip
      cidr_contains: "@network.internal_clients"
    - attribute: request.time.now
      within_time_window: "@time_window.pre_auth_exempt_windows"
```

However, this is decision evaluation. It does not generically stop a configured
check from running before the check's adapter executes.

## Current Implementation Findings

The current compiler and evaluator already include useful primitives:

- `auth.policy.sets.networks`
- `auth.policy.sets.time_windows`
- `cidr_contains`
- `within_time_window`
- implicit request attributes such as `request.client.ip`,
  `request.time.now`, `request.operation`, and `request.protocol`

The current scheduler boundary is narrower:

- check `run_if` supports only `auth_state`;
- `run_if` is deliberately not a general expression language;
- skipped checks are recorded when operation or `run_if.auth_state` does not
  select them;
- configured pre-auth policy controls can stop remaining pre-auth checks only
  after policy evaluation happens at an existing control boundary.

There is also an implementation gap to fix before IP-set policy conditions can
be relied on:

- `request.client.ip` is registered as an IP attribute;
- current request collection emits the value as a string;
- `cidr_contains` evaluates request-time IP values as typed IP/CIDR values.

The scheduler-guard implementation must make `request.client.ip` a typed
request attribute at collection time.

The current `skip_remaining_stage_checks` control is not enough for this CR.
It is selected after at least one policy rule has matched at a stage boundary.
The target scheduler guard must run before the target check adapter starts.

## Non-Goals

- Do not make client IP a mandatory success criterion for authentication.
- Do not make an absent or untrusted client IP match an allowlist guard.
- Do not treat an empty client IP as loopback.
- Do not trust arbitrary proxy headers, gRPC metadata, or user-controlled
  request values as client IP sources.
- Do not turn `run_if` into a full policy expression language.
- Do not let scheduler guards depend on check-produced attributes.
- Do not add request-time Lua as a scheduler authority.
- Do not change final `auth_decision` rule semantics.
- Do not preserve old loopback behavior as an invisible `standard_auth`
  special case.
- Do not add a broad stage-wide wildcard bypass in the first implementation.

## Target Model

### Request Client Identity Facts

Add explicit request-client metadata so policy can distinguish "known IP" from
"trusted IP":

```text
request.client.ip             ip      typed netip.Addr value when available
request.client.ip.present     bool    true when an IP was parsed
request.client.ip.trusted     bool    true when the selected source is trusted
request.client.ip.source      string  direct_peer, proxy_protocol, trusted_proxy_header, grpc_peer, metadata, unknown
```

Rules:

1. `request.client.ip` must be omitted or marked non-present when parsing fails.
2. `request.client.ip.trusted` defaults to `false`.
3. Direct peer addresses may be trusted only when they come from the actual
   transport peer.
4. Header-derived addresses may be trusted only through configured trusted
   proxy rules.
5. Metadata-derived addresses are not trusted unless the transport and caller
   identity make them trustworthy.
6. Empty IP is not loopback and must not match loopback network sets.

### Request Surface For Scheduler Guards

Scheduler guards need a complete but conservative request surface. The first
implementation should prefer server-derived facts over user-controlled values.

Recommended request facts:

| Attribute                   |     Type | Trust model                                        | Purpose                                                                                                       |
|-----------------------------|---------:|----------------------------------------------------|---------------------------------------------------------------------------------------------------------------|
| `request.operation`         |   string | server-derived                                     | Structural operation (`authenticate`, `lookup_identity`, `list_accounts`).                                    |
| `request.protocol`          |   string | server-derived or normalized from protocol adapter | Mail, IdP, HTTP, or protocol-family scoping.                                                                  |
| `request.time.now`          | datetime | server-derived once per request                    | Time-window guards.                                                                                           |
| `request.client.ip`         |       ip | derived from selected client source                | CIDR guards when present.                                                                                     |
| `request.client.ip.present` |     bool | server-derived                                     | Fail closed when no stable IP exists.                                                                         |
| `request.client.ip.trusted` |     bool | server-derived                                     | Prevent untrusted headers or metadata from skipping checks.                                                   |
| `request.client.ip.source`  |   string | server-derived                                     | Explain whether the IP came from peer, PROXY protocol, trusted proxy header, gRPC peer, metadata, or unknown. |
| `request.caller.ip`         |       ip | transport-derived                                  | Authorize the system that connected to Nauthilus, for example an allowed Dovecot caller.                      |
| `request.caller.ip.present` |     bool | server-derived                                     | Fail closed when Nauthilus cannot parse the caller peer IP.                                                   |
| `request.caller.ip.source`  |   string | server-derived                                     | Explain whether the caller IP came from the direct peer or gRPC peer.                                         |
| `request.local.ip`          |       ip | caller-supplied, validate with caller facts        | Match the local endpoint where the caller accepted the client connection.                                      |
| `request.local.ip.present`  |     bool | derived from caller-supplied data                  | Fail closed when the supplied local endpoint IP is empty or invalid.                                          |
| `request.local.port`        |   string | caller-supplied, validate with caller facts        | Match the local endpoint port where the caller accepted the client connection.                                |
| `request.local.port.present` |    bool | derived from caller-supplied data                  | Fail closed when no local endpoint port was supplied.                                                         |
| `request.transport.kind`    |   string | server-derived                                     | Distinguish HTTP, gRPC, mail protocol, IdP, hook, or internal execution.                                      |
| `request.listener.name`     |   string | configured listener identity                       | Prefer listener identity over IP when deployments have separate internal/external listeners.                  |
| `request.connection.tls`    |     bool | transport-derived                                  | Allow guards to depend on already-known transport security, not on a check result.                            |
| `request.initiator.kind`    |   string | server-derived                                     | Distinguish external user traffic, backend health checks, internal service calls, and unknown callers.        |
| `request.http.route`        |   string | normalized server route only                       | HTTP route scoping without using raw path/query input.                                                        |
| `request.grpc.method`       |   string | gRPC transport-derived                             | gRPC method scoping for service operations.                                                                   |
| `request.idp.client_id`     |   string | parsed request value, not trusted alone            | Optional IdP/OIDC scoping when combined with trusted transport or source facts.                               |
| `request.saml.sp_entity_id` |   string | parsed request value, not trusted alone            | Optional SAML scoping when combined with trusted transport or source facts.                                   |

Allowlisted request headers and gRPC metadata may be exposed as normal policy
attributes, but they must not become trusted scheduler facts by default. A guard
that uses a user-controlled request value must combine it with a trusted
server-derived fact, or the compiler should reject it in the first
implementation.

The `request.local.*` values describe what the caller reports as its local
endpoint. Use them together with `request.caller.*` when the decision depends on
whether a trusted caller, such as Dovecot, accepted the client connection on an
allowed endpoint.

Do not expose these values as scheduler-guard inputs in the first slice:

- password, token, OTP, recovery code, or credential material;
- arbitrary raw headers or raw metadata;
- raw HTTP path, raw query string, cookies, `User-Agent`, or language headers;
- username or account as a standalone bypass criterion;
- check-produced attributes;
- Lua-produced attributes.

### Network And Time Sets

Network and time-window sets remain the central reusable operands:

```yaml
auth:
  policy:
    sets:
      networks:
        pre_auth_exempt_sources:
          - 127.0.0.0/8
          - ::1

        list_account_sources:
          - 192.168.0.2/32

      time_windows:
        pre_auth_exempt_windows:
          timezone: Europe/Berlin
          days: [sunday]
          intervals:
            - start: "02:00"
              end: "04:00"
```

Time windows must use the request-local `request.time.now` captured once for
the request, not repeated wall-clock reads during evaluation.

### Scheduler Guards

Add named scheduler guards under `auth.policy.scheduler_guards`.

Recommended first shape:

```yaml
auth:
  policy:
    scheduler_guards:
      pre_auth_exempt_source:
        on_missing_attribute: run
        if:
          all:
            - attribute: request.client.ip.present
              is: true
            - attribute: request.client.ip.trusted
              is: true
            - attribute: request.client.ip
              cidr_contains: "@network.pre_auth_exempt_sources"

      pre_auth_exempt_window:
        on_missing_attribute: run
        if:
          attribute: request.time.now
          within_time_window: "@time_window.pre_auth_exempt_windows"
```

Allowed condition inputs:

- implicit request-context attributes;
- allowlisted request header or metadata attributes that are available before
  pre-auth checks;
- `request.time.now`;
- no check-produced attributes;
- no Lua-produced attributes.

Allowed operators should initially reuse the existing typed condition compiler:

- boolean/string scalar operators;
- `cidr_contains`;
- `within_time_window`;
- `exists`.

`on_missing_attribute` defaults to `run`. This fail-closed default matters for
client-IP stability: a missing or untrusted IP must not suppress security
checks.

### Check-Level Skip References

Add a check-level field:

```yaml
skip_if:
  - pre_auth_exempt_source
  - pre_auth_exempt_window
```

Semantics:

1. `operations` and `run_if.auth_state` select the active structural plan.
2. Before executing a selected check adapter, the scheduler evaluates the
   referenced guards for that check.
3. Guards listed in `skip_if` are OR-combined.
4. If any guard matches, the check adapter is not called. This is the precise
   meaning of a scheduler-level "allowlist" or exemption.
5. The report records the check as:

```json
{
  "status": "skipped",
  "reason": "scheduler_guard:pre_auth_exempt_source"
}
```

6. A skipped check does not satisfy `require_checks`.
7. A policy rule that requires a skipped check is non-applicable, not false.
   Later rules in the same stage may still match.
8. A skipped check remains non-technical; it must not be reported as an adapter
   error.
9. Reports and metrics must distinguish `run_if` skips from scheduler-guard
   skips.

### Dependency Rules

`after` dependency handling must stay deterministic.

For the first implementation, use a conservative compiler rule:

- if check `B` declares `after: [A]`;
- and check `A` has `skip_if: [guard_x]`;
- then check `B` must also include `guard_x`, or the compiler rejects the
  configuration.

This avoids a runtime dependency-skip cascade and keeps the current policy
report model simple.

### Stage-Wide Bypasses

Do not add a broad wildcard such as "skip all pre_auth checks" in the first
implementation.

Operators can assign the same named guard to specific checks. YAML anchors can
reduce repetition in deployment config, but the compiled model should remain
explicit. A broad stage-level bypass can be reconsidered later if real
configurations become too noisy.

### `standard_auth` Hard Cut

The final target must not keep a second hidden bypass path inside
`standard_auth`.

Hard-cut rules:

1. `standard_auth` uses the same scheduler, check, report, and
   `require_checks` semantics as operator-authored policy.
2. Loopback, empty IP, backend health checks, internal service callers, and
   monitoring sources are not special in Go code.
3. If a deployment wants those requests to skip selected checks, it must
   configure named scheduler guards and attach them with `skip_if`.
4. If no guard is configured, loopback and internal-looking requests run the
   configured checks like any other request.
5. Packaged examples may include opt-in scheduler guards, but the product
   runtime must not silently inject them.
6. Empty or untrusted client IP is fail-closed: checks run.

During migration, temporary compatibility code may coexist with explicit
guards, but the CR is not complete until the hard-coded bypass branches are
removed and tests prove the behavior is policy-owned.

### Usage Guidance

Scheduler guards intentionally reduce check coverage. They should be used only
when there is a concrete operational need, such as:

- avoiding DNS/RBL work for trusted local health probes;
- skipping TLS enforcement for a trusted internal listener;
- suppressing expensive checks during a documented maintenance window;
- keeping service-to-service list-account traffic narrow and auditable.

Every guard should have a purpose-based name, a short comment in deployment
configuration, and a report reason that allows operators to see why a check did
not run.

## Example: Loopback Without Hard-Coded Freibrief

```yaml
auth:
  policy:
    sets:
      networks:
        pre_auth_exempt_sources:
          - 127.0.0.0/8
          - ::1

    scheduler_guards:
      pre_auth_exempt_source:
        on_missing_attribute: run
        if:
          all:
            - attribute: request.client.ip.present
              is: true
            - attribute: request.client.ip.trusted
              is: true
            - attribute: request.client.ip
              cidr_contains: "@network.pre_auth_exempt_sources"

    checks:
      - name: lua_environment_test_context_chain
        type: lua.environment
        stage: pre_auth
        operations: [authenticate, lookup_identity]
        skip_if: [pre_auth_exempt_source]
        config_ref: auth.policy.attribute_sources.lua.environment.test_context_chain
        output: checks.lua_environment_test_context_chain

      - name: tls_encryption
        type: builtin.tls_encryption
        stage: pre_auth
        operations: [authenticate]
        skip_if: [pre_auth_exempt_source]
        config_ref: auth.controls.tls_encryption
        output: checks.tls_encryption

      - name: rbl
        type: builtin.rbl
        stage: pre_auth
        operations: [authenticate]
        skip_if: [pre_auth_exempt_source]
        config_ref: auth.controls.rbl
        output: checks.rbl
```

The bypass is now visible, named, auditable, reloadable, and removable.

The same guard name can later contain a different network set, such as
monitoring or internal service sources. The important part is the operational
purpose: this source is allowed to skip the attached pre-auth checks.

## Example: Time-Bounded Skip

```yaml
auth:
  policy:
    sets:
      time_windows:
        pre_auth_exempt_windows:
          timezone: Europe/Berlin
          days: [sunday]
          intervals:
            - start: "02:00"
              end: "04:00"

    scheduler_guards:
      pre_auth_exempt_window:
        on_missing_attribute: run
        if:
          attribute: request.time.now
          within_time_window: "@time_window.pre_auth_exempt_windows"

    checks:
      - name: rbl
        type: builtin.rbl
        stage: pre_auth
        operations: [authenticate]
        skip_if: [pre_auth_exempt_window]
        config_ref: auth.controls.rbl
        output: checks.rbl
```

This uses the existing time-window model but applies it before the check
adapter runs.

## Implementation Plan

### Slice 1: Typed Request Context Attributes

- Emit `request.client.ip` as a typed IP value.
- Add `request.client.ip.present`, `request.client.ip.trusted`, and
  `request.client.ip.source`.
- Add the complete first-slice request surface needed by scheduler guards:
  `request.transport.kind`, `request.listener.name`,
  `request.connection.tls`, `request.initiator.kind`, normalized HTTP route,
  normalized gRPC method, and optional IdP/SAML client identifiers where they
  are available before pre-auth scheduling.
- Add focused tests for direct peer, empty IP, invalid IP, loopback, trusted
  proxy, and untrusted metadata/header cases.
- Keep existing policy decision behavior unchanged.

### Slice 2: Compiler Surface

- Add `auth.policy.scheduler_guards`.
- Add `skip_if` to `PolicyCheckConfig`.
- Compile guard conditions with a restricted attribute registry view.
- Reject guard conditions that reference check-produced or Lua-produced facts.
- Reject guard conditions that use user-controlled values as the only bypass
  criterion.
- Reject unknown guard references.
- Validate `after` guard compatibility.

### Slice 3: Request-Time Scheduler

- Evaluate check `skip_if` before `BeginCheck` calls the adapter.
- Record skipped check status with a stable reason.
- Preserve `require_checks` semantics: skipped required checks make a rule
  non-applicable.
- Preserve observe/enforce behavior.
- Ensure reports and metrics distinguish `run_if` skips from scheduler-guard
  skips.
- Do not call check adapters when a scheduler guard matches.

### Slice 4: Remove Hard-Coded Loopback Bypasses

- Remove hard-coded loopback and empty-IP bypasses from Lua environment, TLS,
  relay-domain, and RBL current adapters.
- Replace deployment behavior with explicit policy guard configuration.
- Empty IP must run checks unless a deployment intentionally configures another
  explicit guard.
- Keep tests proving loopback behavior comes from policy, not Go branching.
- Ensure `standard_auth` does not inject hidden scheduler guards.

### Slice 5: Documentation And Migration

- Document loopback and monitoring-client examples in website docs.
- Document the trust model for request client IP sources.
- Document request-surface attributes and which values are safe for scheduler
  guards.
- Document that scheduler guards are not final authorization decisions.
- Provide migration examples from old implicit loopback behavior to explicit
  policy guard config.

## Test Requirements

Follow the project reproducer rule:

- add focused Go reproducer tests before implementation changes;
- always run Go tests with `GOEXPERIMENT=runtimesecret`.

Required coverage:

- compiler accepts valid network and time-window scheduler guards;
- compiler rejects unknown guard names;
- compiler rejects guard conditions over check-produced facts;
- compiler rejects dependency graphs where a dependency can be skipped by a
  guard the dependent check does not share;
- scheduler skips a check when a trusted loopback guard matches;
- scheduler runs the check when IP is missing, empty, invalid, or untrusted;
- scheduler runs the check outside a configured time window;
- skipped checks do not satisfy `require_checks`;
- rules requiring a skipped check are non-applicable and later rules can still
  match;
- reports contain `reason: scheduler_guard:<name>`;
- standard auth behavior changes only through explicit configured guards after
  the hard cut;
- removing hard-coded loopback branches does not change behavior when an
  equivalent policy guard is configured;
- loopback behavior disappears when the guard is removed.

## Compatibility And Migration

The change should be introduced in a way that lets deployments migrate safely,
but the final state is a hard cut:

1. implement guards while keeping existing hard-coded bypasses;
2. add explicit guard examples to test and live configuration;
3. validate reports show policy-controlled skips;
4. remove hard-coded bypasses in a separate CR-backed implementation slice.

This avoids silently widening or narrowing production behavior during rollout,
while still ending with one policy-owned scheduler.

Website documentation belongs in the sibling `nauthilus-website` repository
under `docs/` after implementation. It must document the feature as opt-in and
need-based, with examples that explain both the operational benefit and the
reduced check coverage.

## Open Questions

- Should direct Unix-socket or in-process health-check traffic get its own
  `request.client.channel` attribute instead of overloading client IP?
- Which proxy sources should set `request.client.ip.trusted=true` for HTTP and
  gRPC?
- Should scheduler guards be allowed for `auth_backend` and `subject_analysis`
  in the first implementation, or only `pre_auth`?
- Do deployments need a later stage-level shorthand once explicit per-check
  guards prove too verbose?
- Should `request.listener.name` become the preferred example over client IP
  whenever deployments have separate internal and external listeners?
