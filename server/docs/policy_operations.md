# Policy Decision Service operations

This guide is the production runbook for the generic unary Policy Decision
Service. The configuration field authority and breaking migration contract
remain in [Policy configuration hard cut](policy_configuration_migration.md).
The HTTP OpenAPI document and `api/policy/v1/policy.proto` remain the public
wire authorities.

## Invocation and credentials

Each request evaluates exactly one resource against one qualified target and
one schema version. A list or record-list value is structured fact data inside
that resource; it is not a batch of requests. Record predicates select a field
and apply the configured `any` or `all` quantifier to the bounded records.
Empty, missing, malformed, and schema-incompatible collections do not become a
vacuous permit.

Policy credentials are separate from management and backchannel credentials:

- a Bearer token has the exact audience `nauthilus:policy`, the
  `nauthilus:policy_evaluate` scope, and one issuer-owned `client_id` matching
  an admitted profile;
- requesting diagnostics additionally requires
  `nauthilus:policy_diagnostics` and profile permission;
- Policy-Basic uses a dedicated enabled Policy client profile over the
  protected transport boundary. It has no OAuth scope and never falls back to
  management Basic.

Use separate tokens for Policy and backchannel calls. The placeholders below
must be supplied through the caller's secret store and must never be committed:

```sh
curl --fail-with-body \
  --request POST \
  --header "Authorization: Bearer ${POLICY_ACCESS_TOKEN}" \
  --header "Content-Type: application/json" \
  --data @policy-request.json \
  https://nauthilus.example/api/v1/policy/decisions
```

```sh
curl --fail-with-body \
  --request POST \
  --user "${POLICY_BASIC_USERNAME}:${POLICY_BASIC_PASSWORD}" \
  --header "Content-Type: application/json" \
  --data @policy-request.json \
  https://nauthilus.example/api/v1/policy/decisions
```

Supported Go callers use `PolicyBearerToken` or `PolicyBasicCredentials` from
`server/openapi/client`. They are deliberately not assignable to backchannel
authentication types. gRPC applies the same admission and Decision Service
generation as HTTP.

## Bounded execution

Configure global and per-client admission limits before enabling a route. The
runtime enforces request bytes, fact count, scalar/string/list/value bounds,
aggregate fact bytes, record-list count, fields per record, record bytes,
effect counts and parameter bytes, diagnostics, reports, rate, concurrency,
provider timeouts, and total evaluation timeout. A client's effective request,
fact, rate, and concurrency bounds cannot widen the global limits.

Target schemas are authoritative for each fact's type, source, sensitivity,
and tighter value or collection bounds. Provider descriptors and the prepared
generation fix provider outputs. A provider enriches only the admitted request
and may emit only its declared facts; clients cannot submit provider-owned
facts. The scheduler owns dependencies, timeouts, collision handling, and
failure policy.

The example in [policy_api.yml](examples/policy_api.yml) shows route switches,
global limits, per-client limits, separate credential profiles, target/schema
grants, attribute allowlists, and diagnostics permission.

## Diagnostics and data minimization

Diagnostics are off unless the request opts in, the credential has diagnostics
authority, and the admitted client profile permits them. Public entries use
configured aliases and fixed reason classes, and are bounded by entry, string,
byte, and collection limits. Record lists may expose only an authorized summary
such as alias, count, schema, or status; arbitrary record fields are never
flattened.

Normal logs, controlled audit, traces, reports, diagnostics, metrics, and error
bodies must not contain credentials, raw mail or envelope content, exact Recipe
payloads, SMTP peer IPs, signer domains, provider-only record fields, or cache
state. Request and Decision IDs are correlation values, not public idempotency
keys. Every successful HTTP and gRPC decision response includes both values.
The returned Request ID is the effective internal correlation: it either
preserves the admitted caller value or reports the value generated when the
request omitted one.

## Logs, audit, metrics, and tracing

Every evaluation that reaches the shared service path uses stable correlation
fields in the response, structured log, controlled audit, and OpenTelemetry
span:

- `nauthilus.policy.request_id`
- `nauthilus.policy.decision_id`

The Decision ID is empty when failure precedes decision construction. The span
name is `nauthilus.policy.evaluate`. Normal logs add only bounded route/result
fields. Controlled audit additionally records authentication kind, admitted
principal, selected policy, admission state, and whether diagnostics were
requested and released. Export and retention of controlled audit remain
operator-owned.

`nauthilus_policy_service_decisions_total` uses only the bounded labels
`namespace`, `action`, `transport`, `effect`, `status_code`, and
`result_class`. Request IDs, Decision IDs, principals, IPs, domains, dynamic
facts, generations, provider text, and payload data are forbidden metric
labels. Runtime generation is available in logs and spans and in existing
gauges, not as a metric label.

## Effect and failure interpretation

The public effect and status are authoritative for the synchronous response:

| Condition | Public interpretation | Operator action |
|---|---|---|
| authentication or admission failure | request rejected before policy evaluation | correct credentials, grants, schema, or bounds; do not retry blindly |
| provider or evaluation temporary failure | `indeterminate` with the published `retryable` value | follow the caller's protocol mapping and retry policy |
| synchronous effect failure | Decision is not reported as successful | inspect the bounded effect class and provider health |
| post-action acceptance failure | response finalization fails before acceptance | repair supervisor capacity or shutdown state |
| accepted post-action later fails | original response is immutable; failure is operational | reconcile the external system from audit and provider evidence |
| partial effect execution | completed ordinals stay completed; remaining work is not replayed | reconcile externally, preserving original order evidence |
| `outcome_unknown` | an external dispatch may have happened | reconcile before another domain action; never assume absence |

The host attempts each selected effect ordinal at most once. It provides no
automatic retry, replay, deduplication, or outcome API. It also provides no
Decision cache. HTTP responses use `Cache-Control: no-store`. Any provider or
caller that needs domain idempotency must use its own stable domain identifier
and document its reconciliation procedure.

## Provider-author checklist

Before enabling a Lua or native provider:

1. Register one stable module/component identity and exact target actions.
2. Declare every produced fact, source, type, bounds, and execution class.
3. Keep provider facts generation-bound and reject undeclared or mismatched
   output rather than coercing it.
4. Honor the supplied context and deadline; do not start detached work.
5. Return bounded error classes, never secrets or raw dependency responses.
6. Treat effect calls as at-most-once attempts and reserve `outcome_unknown`
   for an ambiguous external dispatch.
7. Supply hermetic contract, timeout, cancellation, panic, redaction, and
   empty-collection tests.
8. Document restart requirements for native module changes and external
   reconciliation for effects.

Native API details are in [Go plugin developer API](go_plugin_developer_api.md)
and Lua callbacks are in `server/lua-plugins.d/policy/README.md`.

## Deployment and reconciliation

Use `prepare -> validate -> commit` for startup and reload. A failed candidate
must leave the prior complete generation and route state active. Validate
strict configuration, exact client/target/schema grants, provider/effect
bindings, canonical redacted output, generated artifacts, and focused tests
before publication. Native module binary or capability changes require a
process restart; a configuration reload cannot unload or replace a Go module.

After publication, verify both enabled transports, authentication isolation, a
permit and a deny, diagnostics denial and authorized release, bounded metrics,
correlated logs/audit/spans, and provider/effect failure mapping. For an
ambiguous or late effect failure, stop automated replay and reconcile using the
Decision ID, audit record, provider-owned domain identity, and external
destination state.

Troubleshooting order:

1. Correlate the caller Request ID with the response Decision ID.
2. Classify authentication, admission, provider/evaluation, synchronous effect,
   acceptance, late, partial, or `outcome_unknown` failure.
3. Check the active generation and exact target/schema/client/provider binding.
4. Check rate, concurrency, byte/count, and deadline exhaustion without raising
   limits until the input and workload are understood.
5. Inspect sanitized diagnostics only when authorized; use controlled audit and
   provider telemetry for protected details.
6. Reconcile external side effects before submitting a new domain operation.

## DKIM2 Rspamd verifier

The versioned contract is
[DKIM2 Rspamd verifier Policy contract](policy-layer/dkim2_rspamd_policy_contract.md),
with a tracked wire example and an executable operator configuration beside it.
The Rspamd normal filter owns DKIM2 verification and invokes Policy only for a
validated applicable PASS/current or PASS/chain result whose existing local
disposition is `accept` or `continue`. Existing reject or temporary-failure
results never enter Policy and cannot be widened.

Rspamd sends local nested keys (`dkim2.*` resource attributes and `rspamd.*`
environment attributes); admission normalizes them to qualified facts. The
canonical SMTP peer IP is mandatory input because peer reputation and contract
binding are policy material. It remains protected data and must not appear in
diagnostics, reports, normal logs, traces, metrics, or error bodies.

The complete bounded hop list, immutable verifier result, normalized Recipe
descriptors, flags, change classes, recipient classes, and correlation bindings
are input. Exact Recipe payload and raw message or envelope content are
excluded. The native `dkim2/plugin.dkim2_reputation.assessment` provider owns
semantic validation and emits `plugin.dkim2_reputation.assessed_chain`. Policy
controls every hop: PASS can still be denied, and incomplete, reordered,
mismatched, or non-permittable chains fail closed.

Rspamd maps the final Policy result to the documented permanent or temporary
SMTP action. It owns the external projection, immediate Redis result cache,
greylist replay behavior, post-filter, and final Milter handoff. This cache is
not a Nauthilus Decision cache. Operators must monitor the crash window between
an external side effect and recorded completion and reconcile it explicitly.
Outbound signing remains deferred and is not part of this verifier contract.
