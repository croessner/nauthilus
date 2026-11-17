# ClickHouse Diagnostic Data Contract

Status: implemented on the `features` branch (not released, not rolled out). Independently reviewed before
implementation; the final diff review is recorded in the task report. Production data before a rollout of this
contract is legacy (`contract_version = 0`). This document defines what the native ClickHouse plugin records, when,
from which host producer, and how missing evidence is represented. Historical search and interpretation APIs build on
this contract; they must not invent identifiers, stages, or causes that this contract does not define.

## 1. Scope and non-goals

- ClickHouse is the only durable history store. Nauthilus stays operable without ClickHouse; historical diagnosis is
  then unavailable, not degraded into a Redis or in-memory fallback.
- The `nauthilus.logins` table remains the authentication-request projection. It is extended additively.
- A new, purpose-bound `nauthilus.auth_events` table records step events that are not authentication requests, first of
  all second-factor verifications. It never duplicates login rows.
- Analytics is not a complete attempt history: success deduplication, buffer overflow, process loss, and the one-week
  TTL remove rows. A login row exists only when the selected Policy rule carries `authn/plugin.clickhouse.post_action`;
  tempfails decided without a selected presentation (`finalizeUnselected`), effect-acceptance failures, panics, and
  operations whose rules select no analytics effect produce no row. "No row" never means "no request". Every row carries enough version information for clients to tell legacy rows from rows that follow
  this contract.
- No history query API, MCP surface, or admin console is part of this contract. The read-only support history
  API built on it is documented in `server/docs/support_authentication_history.md`.

## 2. Writers

| Writer | Status | Contract |
|---|---|---|
| Native plugin `contrib/plugins/clickhouse` (`authn/plugin.clickhouse.post_action`) | Active in production | This document |
| Lua `server/lua-plugins.d/actions/clickhouse.lua` | Retired, reference only, not configurable as Policy action | Legacy columns only; writes `contract_version = 0` implicitly (column default). No new columns. |

## 3. Field matrix for `nauthilus.logins`

Classification: **active** = filled whenever its producer runs; **conditional** = empty by design unless a specific
producer or input exists; **legacy** = no active producer in the current host; **defect** = projection was wrong;
**unproven** = producer exists but no positive live evidence yet.

Timing note: the snapshot is captured when the selected Policy rule's effects are prepared (inside
`session.Evaluate`), which is before `finalize()` applies status message, tempfail cause, and the client response. The
post-action work itself only runs after the response commit (`effectsupervisor` finalization gate). Fields that depend
on the terminal result must therefore be bound at execution time, not at capture time (see section 4).

| Column(s) | Meaning | Producer / time | Null/default semantics | Class |
|---|---|---|---|---|
| `ts` | Enqueue time (UTC, ms) after response commit | plugin clock | always set | active |
| `session` | Per-request correlation ID (`Runtime.GUID`, KSUID); not a flow ID, not authorizing | logging middleware | always set | active |
| `service`, `proto`, `method` | Auth endpoint service, protocol, auth method | request parsing | empty when caller sent none | active |
| `deployment`, `instance` | Writer separation | plugin config | empty when not configured | active (missing in repo schema before this change) |
| `decision_sources` | Comma list of controls that fired (see section 5) | exchange markers + policy facts at capture | empty = no control fired | defect (relay_domains, tls_encryption missing) |
| `rbl_lists` | Lists that listed the IP, also below threshold | RBL control | `[]` when none | active |
| `client_ip`, `client_port`, `local_ip`, `local_port` | Transport addresses | request headers | empty when not supplied | active |
| `client_net` | Brute-force network | brute-force path | empty when brute force did not run | conditional |
| `client_id`, `user_agent` | Client identifiers supplied by the caller | request | empty when not supplied | conditional |
| `hostname` | Client host | caller or reverse DNS | empty when DNS lookup disabled and caller sent none | conditional |
| `username` | Login name as sent | request | always set for auth rows | active |
| `account`, `display_name` | Resolved account | backend / account provider | empty for unknown users | conditional |
| `password_hash` | 8-hex prefix of the host password digest | capability-gated | empty without password | active; must not be exposed by history APIs |
| `pwnd_info` | HIBP prefix/count | HIBP exchange | empty when HIBP not active | conditional |
| `brute_force_bucket`, `brute_force_counter` | Bucket that went over limit; counter | brute-force setter | bucket empty when no bucket triggered; counter 0 | active; bucket is also set when toleration suppressed the block (section 5.3) |
| `oidc_cid`, `saml_entity_id`, `grant_type` | IdP context | IdP request context | empty outside IdP | conditional |
| `mfa_method` | Second factor completed for this request | IdP token/assertion issuance (`canonical_oidc_authorization.go`, `canonical_saml.go`, `canonical_oidc_device.go`) | empty for password logins, because the authn post-action runs before any step-up; filled only when a token/assertion lookup selects the analytics post-action | conditional, unproven live; MFA verification history lives in `auth_events` |
| `failed_login_count`, `failed_login_rank`, `failed_login_recognized` | Failed-login hotspot details | `plugin.exchange.failed_login_hotspot` | NULL when no producer | conditional (prod has producer, shadow not) |
| `geoip_*` (location, ASN) | GeoIP evidence | `plugin.geoip.*` facts / exchange | NULL / empty when lookup missed; city empty with country DB | active |
| `geoip_privacy_*`, `geoip_is_*` | Privacy intelligence | GeoIP privacy facts | NULL when no evidence; arrays `[]` | active (positive paths unproven live) |
| `geoip_guid` | Legacy exchange GUID | no active producer | empty | legacy |
| `reputation_score` … `reputation_decision` (10) | Legacy GeoIP reputation map | removed Lua producer; no current producer | NULL / empty | legacy, intentionally unbound (section 6) |
| `gp_*`, `prot_*`, `dyn_*` | Global pattern, account protection, dynamic response exchange maps | no active producer found | NULL / empty | legacy |
| `ssl_fingerprint` | Client TLS fingerprint header | request | empty unless proxy sends it | conditional |
| `xssl_protocol`, `xssl_cipher` | TLS metadata from proxy | request | empty without TLS context | active |
| `repeating`, `rwp` | Brute-force repeat / repeated-wrong-password hints | brute-force path, capture time | false when brute force did not run (non-null bool; not evidence) | active, weak semantics |
| `user_found`, `account`, `display_name` | Account resolved | backend, capture time | false/empty also when lookup did not run yet (pre-auth rules) | active, capture-time semantics |
| `authenticated` | `Runtime.Authenticated` at capture | auth core | false for fail **and** tempfail; a capture-time value that a later guard can still overturn | defect as outcome carrier; superseded by `outcome` |
| `latency` | ms from request start to capture | host clock | 0 when unknown | active, capture-time |
| `http_status` | Host status code selected for the terminal decision (configured OK/Fail/InternalError code; nginx 200) | **was** derived from `Authenticated` at capture; now the late-bound terminal outcome | 0 when the outcome is unknown | defect fixed: reported 403 for a 500 tempfail |
| `status_msg` | Client status text of the terminal decision | **was** capture-time text with credential-failure fallback; now late-bound | empty when the outcome is unknown | defect fixed: reported "Invalid login or password" for a tempfail |

## 4. Terminal outcome contract (additive `logins` columns)

### 4.1 Late binding

The request snapshot is captured while Policy prepares the selected effects, before `finalize()`. The post-action work
runs only after the finalization gate opened (HTTP: after `WriteHeaderNow` in the completion middleware; gRPC: after
the unary handler returned). This is structural: `effectsupervisor.NewPlan` rejects a missing gate and
`prepareAuthnCandidateExecution` refuses to run without one.

A request-scoped **outcome cell** is installed in the request context together with the gate:

1. the authn application seals the terminal outcome into the cell after `runCheckpointPlan` returns (decision,
   operation, presented Policy markers, tempfail cause, FSM state, status message, host status code);
2. the HTTP completion middleware records the committed writer status and transport `http` immediately before
   `gate.Complete()`; the gRPC interceptor records transport `grpc`;
3. the post-action work resolves the cell when it executes and attaches the result as
   `pluginapi.PostActionRequest.Outcome`. It also refreshes `Snapshot.Diagnostics.HTTPStatus` and `StatusMessage` from
   the sealed outcome, so every public post-action consumer sees the answered values. The cell is not part of the
   bound-checked request and is released with the work.

`Outcome.Known = false` (`outcome = 'unknown'`) is written when the cell was never sealed: the application returned an
error after the effect was accepted, or the client cancelled before the outcome was sealed. A panic never opens the
gate, so no row is written at all.

### 4.2 Columns

| Column | Type | Values | Source |
|---|---|---|---|
| `contract_version` | `UInt16 DEFAULT 0` | `0` legacy row, `1` this contract | plugin constant |
| `event_id` | `String DEFAULT ''` | random 128-bit hex per produced row; stable across requeue because rows are stored encoded | plugin at encode |
| `operation` | `LowCardinality(String) DEFAULT ''` | `authenticate`, `lookup_identity`, `list_accounts` | Policy operation |
| `outcome` | `LowCardinality(String) DEFAULT ''` | `ok`, `fail`, `tempfail`, `unknown` | sealed terminal decision |
| `outcome_stage` | `LowCardinality(String) DEFAULT ''` | Policy stage of the presenting rule (`pre_auth`, `auth_decision`, …); empty without a presenting rule | presented `report.FinalDecision.Stage` |
| `outcome_marker` | `LowCardinality(String) DEFAULT ''` | Policy outcome markers, e.g. `auth.outcome.tls_required`, `auth.outcome.relay_domain_reject`, `auth.outcome.auth_failure`, `auth.outcome.backend_tempfail`, `auth.outcome.evaluation_failure` | presented `FinalDecision.OutcomeMarker` |
| `response_marker` | `LowCardinality(String) DEFAULT ''` | `auth.response.ok`, `auth.response.fail`, `auth.response.tempfail`, `auth.response.tempfail.no_tls`, … | presented `FinalDecision.ResponseMarker` |
| `policy_rule` | `LowCardinality(String) DEFAULT ''` | presenting rule name | presented `FinalDecision.PolicyName` / tempfail cause |
| `tempfail_reason` | `LowCardinality(String) DEFAULT ''` | `policy_indeterminate`, `backend_tempfail`, `auth_fsm_guard`, `brute_force_error`, `environment_tempfail`; empty unless `outcome = 'tempfail'` | `authTempFailCause.reason` (same as log key `tempfail_reason`) |
| `tempfail_checkpoint` | `LowCardinality(String) DEFAULT ''` | checkpoint where the indeterminate result surfaced | `authTempFailCause.checkpoint` |
| `policy_status` | `LowCardinality(String) DEFAULT ''` | decision status code, e.g. `evaluation_failed`, `provider_unavailable` | `authTempFailCause.statusCode` |
| `fsm_state` | `LowCardinality(String) DEFAULT ''` | terminal auth FSM state | `Runtime.AuthFSMTerminalState` |
| `transport` | `LowCardinality(String) DEFAULT ''` | `http`, `grpc`, empty when unknown | gate boundary |
| `transport_status` | `Nullable(UInt16)` | committed HTTP writer status; NULL for gRPC or unknown | completion middleware |
| `flow_ref` | `String DEFAULT ''` | derived IdP flow correlation (section 7.3); empty outside IdP browser flows | IdP request context |
| `brute_force_tolerated` | `Nullable(Bool)` | true when toleration suppressed a triggered bucket; NULL when no bucket name was set | brute-force toleration fact |
| `reputation_assessments` | `Array(Tuple(...))` | section 6 | public reputation decision records |
| `reputation_truncated` | `Bool DEFAULT false` | true when the host or plugin dropped assessment records to stay within bounds | host trim flag / plugin cap |

### 4.3 Rules

- The stable cause of a terminal result is the triple `outcome_marker` + `response_marker` + `tempfail_reason`;
  `tempfail_reason = 'policy_indeterminate'` alone covers both a rule that deliberately answers tempfail (TLS required)
  and a provider failure, which `policy_status` and `outcome_marker` separate.
- `outcome` is the transport-independent result. `transport_status` is only the committed HTTP status: header/nginx
  modes commit HTTP 200 for rejections, and IdP browser logins commit the login page status (200/302) also for
  fail-latched failures. Never derive the result from `transport_status`.
- `http_status` keeps its legacy meaning (host status code configured for the decision) and is now taken from the
  sealed outcome instead of the capture-time `Authenticated` flag. For gRPC rows it remains the configured code.
- `status_msg` becomes the final client text. Dashboard panels that filter on `status_msg = 'Invalid login or
  password'` stop counting tempfails as credential failures; this is the intended correction.
- `authenticated`, `user_found`, `account`, `latency`, and the brute-force columns are capture-time values. A row of a
  post-action selected on a non-terminal `pre_auth` rule describes the request state at that rule.
- A pre-auth environment deny (relay domain, RBL, blocklist) and a credential failure both read `outcome = 'fail'` and
  `response_marker = 'auth.response.fail'`; they differ in `outcome_stage`, `outcome_marker`, `policy_rule`, and
  `decision_sources`. An unknown user and a wrong password are both credential failures and differ only in the weak
  `user_found`/`account` columns.
- A technical backend failure reads `outcome = 'tempfail'`, `tempfail_reason = 'backend_tempfail'`.
- For `outcome = 'unknown'` the plugin writes `http_status = 0`, empty `status_msg`, NULL `transport_status`, and the
  capture-time flags; it never substitutes a credential-failure default.

## 5. Decision sources

### 5.1 Meaning

`decision_sources` lists controls that **fired** (detected a condition that contributes to rejection or tempfail),
not every check that ran. A control that fired is listed even when Policy still lets the request continue. Allowlisted,
soft-allowlisted, tolerated, skipped, and technically failed checks publish no source. Order is deterministic and
deduplicated; query membership, not exact strings.

### 5.2 Built-in vocabulary

| Source | Fires when | Producer |
|---|---|---|
| `tls_encryption` | Request without TLS context, not dev mode, client not in cleartext networks | `ControlTLSEncryption` (new marker) |
| `relay_domains` | Username has a domain part that is not a configured relay domain and the request is not soft-allowlisted | `ControlRelayDomains` (new marker) |
| `rbl` | RBL score reached the threshold | RBL control |
| `brute_force` | A bucket triggered newly or an existing ban was found (`alreadyTriggered`) | brute-force path |
| `blocklist` | `lua.plugin.blocklist.matched` fact true | Lua environment plugin |
| `failed_login_hotspot` | hotspot fact or exchange `triggered` | Lua environment plugin |
| `geoip_policyd`, `account_protection`, `geoip_reputation`, … | existing exchange/fact derivations | unchanged |

Missing domain part, configured static match, and soft allowlist do not publish `relay_domains`. Relay domains have no
error path. Brute-force soft allowlists, IP allowlists, and toleration publish no `brute_force` source. The retired
Lua writer already wrote `tls_encryption` and `relay_domains`, so adding them restores the
historical vocabulary; existing Grafana panels use generic `arrayJoin` or substring checks for other names and are
unaffected.

### 5.3 Brute-force bucket without source

The toleration branch produces rows with `brute_force_bucket != ''`, empty sources, and `repeating = true`:
`server/bruteforce/bruteforce.go` registers `defer setter()` before `blockSuppressedByToleration()` returns **true**
and the trigger is suppressed, so the bucket name is copied although no block happened, and the core publishes no
marker. This is correct for `decision_sources` (brute force did not reject). The row now carries
`brute_force_tolerated = true` (new public `RequestDiagnostics.BruteForceTolerated`, taken from
`Runtime.BruteForceToleration.SuppressedBlock`), so the bucket reads as "over limit but tolerated". The bucket stays,
because it is the evidence of the suppressed trigger. The ban-write failure branch also sets the bucket but ends with
`tempfail_reason = 'brute_force_error'`.

Correction: toleration could not become active on v4.x before this change. Its positive/negative counters were only
written by the auth FSM dispatch that the Policy authority cutover (commit `f0233a5b3`, before v4.0.0) took out of the
production path; commit `28a9db8a0` later removed the dead dispatch. Toleration and the
reputation-scaled bucket limits require a positive count. The 13 production rows of 2026-11-16 therefore do not come
from the toleration branch; their path stays unexplained on the legacy data (the ban-write failure branch is a
candidate whose rows were projected as credential failures by the old terminal projection). Rows of contract version 1
tell both apart through `outcome`, `tempfail_reason`, and `brute_force_tolerated`. The accounting is restored in
`server/core/authn_toleration_accounting.go`: an answered success backed by a verified credential is positive, an
answered failure backed by a rejected credential is negative; tempfails, pre-auth rejections, lookups, and no-auth
requests are not accounted.

## 6. Reputation projection

The native reputation plugin publishes `DecisionValueKindRecords` facts `plugin.<module>.<output_fact>` and the three
profile views `<output_fact>_fast|_operational|_baseline`. Each record describes one subject:

`role, kind (ip|network|asn|dns_domain|account|service), state (fresh|stale|not_found|unavailable), profile,
band (unknown|trusted|positive|neutral|suspicious|blocked|unavailable), override (none|trusted|neutral|blocked),
risk_score, trust_score, confidence, samples, source_diversity, age_seconds` (measured fields only for fresh/stale).

Defect: the host passed record facts to public plugins as the server-internal `decision.RecordList`, which public
plugins cannot decode. The internal/public value converter moves from `server/pluginruntime` into the leaf package
`server/policy/decision/pluginvalue` (no import cycle with `server/core`), and `authnNativePublicFacts` converts record
values to `pluginapi.DecisionRecordList`. This applies to obligation, subject-source, and post-action requests alike.

Bounds: every post-action request is validated against `effectsupervisor.DefaultWorkBounds()` (4096 elements,
256 KiB) during preparation, and a preparation error turns the decision indeterminate. Record facts are large (four
profile views per reputation binding), so a request with many subjects could exceed the bound and tempfail the login.
Measured on the public record shape, four profile views exceed the bound from five subjects on, one view from 20
subjects on (production binds one subject). When the full post-action request exceeds the bound, the host drops the
record-valued fact with the most records, sets `PostActionRequest.FactsTrimmed`, and validates again until the request
fits; scalar facts are kept, and only a request that still exceeds the bound without record facts fails as before.
Analytics evidence must not change an authentication decision. The trim also applies to other post-action consumers of
record facts; it replaces the previous behaviour of failing the whole decision. The latent risk already existed on
v4.0.9, where the internal record type was counted against the same bound.

Recognition: the plugin projects every record-valued fact whose records decode as reputation assessments
(`reputationview` shape: string `role`, `kind`, `state`, `profile`, `band`, `override`); other record facts are
ignored. Catalog correlation fields appended to records are not projected.

Projection: one tuple per (fact, record) in

```sql
reputation_assessments Array(Tuple(
  fact LowCardinality(String), role LowCardinality(String), kind LowCardinality(String),
  state LowCardinality(String), profile LowCardinality(String), band LowCardinality(String),
  override LowCardinality(String), risk_score Nullable(Float64), trust_score Nullable(Float64),
  confidence Nullable(Float64), samples Nullable(Float64), source_diversity Nullable(Int64),
  age_seconds Nullable(Int64)))
```

- No reduction to one score; profiles and subjects stay separate. The decision-profile fact duplicates one profile
  view by design; it is kept because Policy rules read it.
- The plugin caps the projection at 64 tuples and sets `reputation_truncated`; in practice the host bound trims first.
- Measured fields are NULL for `not_found`/`unavailable`, never 0.
- No decision, model, or config version exists in the record; none is invented. A future model fingerprint needs a
  new column because a tuple's element set cannot be extended in place.
- The 10 legacy `reputation_*` columns stay NULL; they describe the removed GeoIP reputation map.

## 7. Second-factor events (`nauthilus.auth_events`)

### 7.1 Host extension point

No existing extension fits (hooks are HTTP endpoints; post-actions need a Policy decision and a supervisor plan). A
new minimal extension point `pluginapi.AuthEventSink` (`Registrar.RegisterAuthEventSink`) receives host-observed step
events:

- The host dispatcher owns one bounded queue (capacity 1024) and one delivery goroutine per process. Emitting never
  blocks a request; a full queue drops the event and increments `plugin_auth_events_total{outcome="dropped"}`
  (`queued`, `delivered`, `failed` complete the outcome set). Emitting reads the dispatcher without the runner lock.
- `ObserveAuthEvent(ctx, AuthEvent) error` must only enqueue. Errors and panics are contained and counted.
- The sink set is fixed for the process lifetime, like every registered plugin component: adding or removing a module
  requires a restart, while SIGHUP reconfigures the plugin in place. On shutdown the dispatcher drains the queue
  within the stop timeout before sinks stop.
- Events are emitted only by the canonical IdP MFA handlers (`server/handler/frontend/idp/canonical_mfa_events.go`),
  next to the existing metric/log call or at the step-up state transitions, never inside `core.LogIDPMFAuthResult` or
  the core WebAuthn helpers, which log separately. Verification is never re-run to produce an event.
- The dispatcher is owned by the native plugin runner: it starts with the runner and drains before sinks lose readiness
  on shutdown. The plugin API registration is the additive `pluginapi.AuthEventRegistrar`.

### 7.2 Event schema (version 1)

| Column | Type | Meaning |
|---|---|---|
| `ts` | `DateTime64(3, 'UTC')` | host observation time |
| `event_id` | `String` | host-generated random 128-bit hex; idempotency key |
| `event_type` | `LowCardinality(String)` | `mfa.verification` |
| `event_version` | `UInt16` | `1` |
| `deployment`, `instance` | `LowCardinality(String)` | writer separation |
| `request_id` | `String` | `Runtime.GUID` of the observing request; joins `logins.session` only for the same request |
| `flow_ref` | `String` | derived flow correlation (7.3); joins `logins.flow_ref` of the password request; empty for self-service step-ups |
| `protocol` | `LowCardinality(String)` | `oidc`, `saml`, or `account` for self-service step-ups |
| `client_id`, `saml_entity_id` | `LowCardinality(String)` | relying party |
| `account` | `LowCardinality(String)` | pending identity account (the MFA selection knows no login name) |
| `client_ip` | `String` | browser client IP |
| `factor_role` | `LowCardinality(String)` | `second_factor` |
| `method` | `LowCardinality(String)` | `totp`, `recovery_codes`, `webauthn` |
| `result` | `LowCardinality(String)` | `success`, `invalid`, `error`, `rate_limited`, `rejected` |
| `reason` | `LowCardinality(String)` | stable code (7.4) |
| `fail_latched` | `Bool` | the primary step had already failed; a correct factor does not authenticate |
| `flow_effect` | `LowCardinality(String)` | `step_up_completed`, `primary_failure_kept`, `none` |

No passwords, hashes, OTP values, recovery codes, tokens, session/step-up/ceremony handles, or WebAuthn payloads are
part of an event. `fail_latched = true` with `result = 'success'` means the factor was right while the password was
wrong; history APIs must treat it as operator-only information.

### 7.3 Correlation

`flow_ref = hex(sha256("nauthilus.flow_ref.v1\x00" + flow_id))[0:32]` (`flow.DiagnosticFlowRef`). The flow ID is a
random 256-bit capability handle; the domain-separated, truncated digest is no storage key and cannot resume a flow.
The IdP frontend computes it before the value enters `IDPRequestContext`, so neither plugins nor Lua see the raw
handle. The password login row and every MFA event of the same flow carry the same value. Self-service step-ups have no parent flow and an empty `flow_ref`; the step-up handle (an
authorizing URL ticket) is never used as a fallback. Session cookies, login tickets, step-up handles, and ceremony
handles are never exported.

### 7.4 Observable MFA outcomes

| Handler path | result | reason | flow_effect |
|---|---|---|---|
| Factor verified and `CompleteStepUp` succeeded | `success` | `verified` | `step_up_completed` |
| Factor verified on a fail-latched flow, step-up consumed (HTTP 401) | `success` | `verified` | `primary_failure_kept` (`fail_latched = true`) |
| Wrong TOTP code, unknown or reused recovery code | `invalid` | `invalid_code` | `none` |
| WebAuthn assertion helper failed, mostly a rejected verification or sign-count rollback (`core.ErrWebAuthnAssertionRejected`; see known limits) | `invalid` | `assertion_rejected` | `none` |
| WebAuthn ceremony missing, consumed, expired, or foreign (`core.ErrWebAuthnCeremonyUnavailable`) | `invalid` | `ceremony_unavailable` | `none` |
| Verifier, backend lookup, or WebAuthn state failure (HTTP 503/500) | `error` | `verifier_error` | `none` |
| Attempt budget exhausted (HTTP 429) | `rate_limited` | `attempt_limit` | `none` |
| Attempt budget store error (HTTP 503) | `error` | `attempt_store_error` | `none` |
| Step-up binding/revision conflict (HTTP 409); on the fail-latched path also a consumed step-up | `rejected` | `step_up_conflict` | `none` |
| Step-up expired (HTTP 409) | `rejected` | `step_up_expired` | `none` |
| Step-up or anchor store error after a verified factor, or step-up not found outside the fail-latched path (HTTP 503) | `error` | `state_error` | `none` |
| Continuation conflict after the step-up was completed (HTTP 409) | `rejected` | `resume_conflict` | `step_up_completed` |
| Selection conflict (409), missing code or ceremony parameter (400), browser abort | no event | — | — |

The HTTP answers of all paths are unchanged; the typed WebAuthn errors only classify events. The browser smoke of
`contrib/identity-proxy-e2e` observed the success, invalid, rate-limited, and fail-latched rows for all three methods
and `assertion_rejected` for the WebAuthn tamper, wrong-challenge, wrong-origin, unknown-credential, and sign-count
cases. The technical error, conflict, expiry, resume-conflict, and `ceremony_unavailable` rows are covered by handler
tests (`canonical_mfa_events_test.go`); `attempt_store_error` and the non-latched `CompleteStepUp` call site are covered
only through the shared mapping, not by a fault-injected request.

Known limits: the local TOTP verifier folds validation errors into "invalid", so local `invalid_code` can include a
verifier error; a recovery code typed into the TOTP form is reported as method `totp`; recovery-code reuse is not
distinguishable from an unknown code; any failure inside the WebAuthn assertion helper is reported as
`assertion_rejected`, also when it is not a verification failure. A failed factor attempt is never a terminal flow failure; later attempts and a
success are separate events. WebAuthn as a primary, passwordless login does not exist in the IdP today; the
`factor_role` value `primary` is reserved and never written.

### 7.5 Table

```sql
CREATE TABLE IF NOT EXISTS nauthilus.auth_events ( ...columns above... )
ENGINE = ReplacingMergeTree
ORDER BY (event_type, ts, event_id)
TTL toDateTime(ts) + INTERVAL 1 WEEK DELETE;
```

`ReplacingMergeTree` collapses replays of the same `event_id` eventually; exact queries use `LIMIT 1 BY event_id` or
`FINAL`. Different attempts always have different `event_id`s. `logins` stays a plain `MergeTree`, so its duplicates
are identifiable by `event_id` but not collapsed.

## 8. Delivery semantics

- Login rows and events use separate bounded in-memory streams in the plugin (separate cache keys, buffer limits,
  insert URLs, insert gates, retry pauses). Buffer overflow drops rows and is counted per stream. No Redis buffer.
- The event stream is enabled by `events_insert_url` and always runs a flush worker: `events_flush_interval` defaults
  to `10s` and must be positive. Event delivery delay is therefore bounded by that interval plus one insert while
  ClickHouse is healthy. Login rows keep `flush_interval` (production `60s`).
- Login deduplication selects its switch from the late-bound outcome: `ok` uses `dedup_success`, `fail` uses
  `dedup_failure`, `tempfail` and `unknown` are never deduplicated. The key includes the outcome, markers, and
  `flow_ref` (key prefix `v3`), so the password row of every IdP flow survives for the MFA join. Events are never
  deduplicated.
- Requeued rows keep their `event_id`; an ambiguous insert failure can produce duplicates that `event_id` identifies.
  No exactly-once claim.
- Storage failures never change an authentication decision. The size-triggered inline flush of login rows runs inside
  the post-action `Enqueue` after the gate, so it occupies a supervisor worker, not the request. Event sinks never
  flush inline.

## 9. Migration and versions

1. Apply the additive `ALTER TABLE nauthilus.logins ADD COLUMN IF NOT EXISTS …` statements and `CREATE TABLE IF NOT
   EXISTS nauthilus.auth_events` before deploying a writer of this contract. `CREATE TABLE IF NOT EXISTS` never migrates
   an existing table.
2. ClickHouse 25.8 defaults to `input_format_skip_unknown_fields = 1` (verified against the image used in
   production): a new writer against an old schema silently drops the new fields instead of failing. Verify the
   columns with `system.columns` before the rollout. After the migration, operators may append
   `&input_format_skip_unknown_fields=0` to both insert URLs to turn future schema drift into visible insert errors
   (failed inserts are requeued, then dropped and counted at the buffer limit).
3. An old writer keeps working against the new schema; its rows read `contract_version = 0` and empty outcome columns.
   Existing rows are not reinterpreted, rewritten, or deleted.
4. Clients filter `contract_version >= 1` for outcome-based interpretation; the first `ts` with version 1 per
   `deployment`/`instance` is the cutover boundary (reported by the history task).
5. The repository `schema.sql` gains the `deployment` and `instance` columns that the writer has always emitted and that
   the Kubernetes mirror already has; both files carry the same statements.

## 10. Verification

Executed locally on 2026-11-16 (see the task report for the exact commands and outputs):

| Area | Test | Evidence |
|---|---|---|
| TLS-required and backend tempfail, credential failure, success through the real authn application | `server/app/policyfx` `TestNativePostActionSeesAnsweredTerminalOutcome` | bound `PostActionRequest.Outcome` equals `testdata/diagnostic_contract/terminal_outcomes.json` exactly |
| Outcome cell, unknown outcome, committed HTTP status | `server/core` `TestPostActionOutcomeBinding*`, `TestAuthnTerminalOutcomeCellSealsOnce`, `TestPostActionCompletionMiddlewareRecordsCommittedStatus` | unit |
| Relay domains / TLS decision sources | `server/core` `TestRelayDomainControlPublishesDecisionSourceOnlyOnRejection`, `TestTriggeredBuiltinControlsPublishDecisionSources` | unit |
| Brute-force toleration branch | `server/bruteforce` `TestTolerationSuppressedTriggerKeepsBucketNameWithoutBlock` | redismock |
| Record facts as public type, staged trim | `server/core` `TestAuthnNativePublicFactsExposePublicRecordLists`, `TestAuthnNativePostActionBounds*` | unit |
| MFA events per handler path | `server/handler/frontend/idp` `TestCanonicalFailLatchedRecovery*Event*`, `TestCanonicalWebAuthnFinishFailuresEmitTypedEvents`, `TestCanonicalStepUpFailuresKeepStatusAndEmitTypedEvents` | real handlers and canonical session state |
| `flow_ref` plumbing into the post-action snapshot | `server/core` `TestApplyAuthIDPContextKeepsFlowRefWithoutOtherProtocolFacts`, `server/pluginruntime` `TestRequestSnapshotCarriesIDPFlowRef`, `server` `TestFrontendHandlerDepsCarryPluginRunner` | unit; the logins-to-events join itself is proven in real ClickHouse, the E2E stack writes events only |
| Bounded event dispatch | `server/pluginruntime` `TestAuthEventDispatcher*` (race detector) | unit |
| Stored ClickHouse rows, migration, fresh/migrated equivalence, replay, schema drift, dashboard queries | `contrib/plugins/clickhouse` build tag `clickhouse_integration` (`contrib/clickhouse-kubernetes/run-integration-tests.sh`) | real ClickHouse 25.8 |
| Browser MFA flows into ClickHouse | `contrib/identity-proxy-e2e/scripts/run.sh clickhouse-events` after the browser smoke | Playwright, virtual WebAuthn authenticator, real ClickHouse |

## 11. Handover to the history task

- Query only ClickHouse. Treat `contract_version = 0` rows as legacy: never derive a cause from `authenticated`,
  `http_status`, or `status_msg` there.
- Primary result: `outcome`; stable cause: `outcome_marker` + `response_marker` + `tempfail_reason` (+ `policy_status`,
  `tempfail_checkpoint`); presenting rule: `policy_rule`; stage: `outcome_stage`; transport facts: `transport`,
  `transport_status`.
- Join MFA events to the password request with `flow_ref` (non-empty), never with `session`; deduplicate events with
  `FINAL` or `LIMIT 1 BY event_id`, and login rows with `LIMIT 1 BY event_id`.
- Report the cutover boundary (first `contract_version = 1` per `deployment`/`instance`), the TTL window (one week),
  the export delay (`flush_interval`, `events_flush_interval`), success deduplication, and the coverage gaps of
  section 1 to support users. "No row" never proves "no request".
- Do not expose `password_hash`, `client_port`, raw `user_agent`, or operator-only semantics such as
  `fail_latched = true` with `result = 'success'` to end-user-facing history views.
- Fixtures: `testdata/diagnostic_contract/terminal_outcomes.json` (terminal outcomes as bound by the host), the
  event set in `clickhouse_contract_integration_test.go` (`contractEvents`), and
  `testdata/diagnostic_contract/bruteforce_events.json` (shared-IP ban scenario as emitted by the host, with stable
  IDs and times).
- Ban questions follow the read contract of section 13.5 on `bruteforce_lifecycle`, `bruteforce_attempts`, and
  `bruteforce_attempt_summary`; the queries in `clickhouse_bruteforce_integration_test.go` are the reference for
  contributions, hits, and the completeness status. Never infer a ban cause from `logins` rows, shared IPs, or time
  proximity.

## 12. Cluster smoke plan (only after a separately authorized rollout)

Preconditions: the migration of section 9 is applied and verified with `system.columns`; a release containing this
contract runs on shadow first; the operator approved the smoke window. Nothing below may use real user accounts,
real customer IPs, or production Redis maintenance commands.

1. Test identity: a dedicated synthetic account (for example `ch-contract-smoke@<test domain>`) in the test backend,
   with one TOTP factor provisioned only for this smoke, and a dedicated OIDC test client. Correlation marker: a
   unique username suffix or `X-Client-ID: ch-contract-smoke-<UTC timestamp>`.
2. Backchannel request without end-user TLS context (synthetic, as on 2026-11-16) → client HTTP 500; expect one row with
   `outcome = 'tempfail'`, `outcome_marker = 'auth.outcome.tls_required'`, `response_marker =
   'auth.response.tempfail.no_tls'`, `http_status = 500`, `status_msg = 'TLS transport encryption required'`,
   `decision_sources` containing `tls_encryption`.
3. Same request with TLS context and a wrong password → HTTP 403; expect `outcome = 'fail'`, `outcome_marker =
   'auth.outcome.auth_failure'`.
4. OIDC browser login of the test account: correct password, one wrong TOTP code, then the correct code → expect one
   login row with a 32-character `flow_ref`, and two `auth_events` rows with the same `flow_ref`:
   `invalid/invalid_code/none`, then `success/verified/step_up_completed`. Prove the join with
   `SELECT l.session, e.result FROM nauthilus.logins AS l INNER JOIN nauthilus.auth_events AS e ON l.flow_ref =
   e.flow_ref WHERE l.flow_ref != '' AND l.ts >= <window start>` (the logins row exists only when the selected
   password rule carries `authn/plugin.clickhouse.post_action`).
5. Query window: from one minute before the first request to `flush_interval + 30s` after the last one (production:
   60 s login flush, 10 s event flush); filter by `deployment`, `instance`, and the correlation marker.
6. Allowed side effects: analytics rows, brute-force counters of the synthetic identity below every bucket threshold
   (at most two failed attempts per source), one consumed MFA attempt budget entry of the test account. Stop on any
   unexpected ban, lockout, or error rate change; no unlocks or data deletion are part of the smoke.

## 13. Brute-force evidence

Goal: answer later, from ClickHouse only, which rule banned which network when, which attempts the counter really
counted, which counted increment crossed the limit, which later requests only hit the existing ban, and what can no
longer be said. Login names are claims: they never identify a person or device, and a public IP never identifies a
customer. The request that writes a ban is rejected before credential verification; behind NAT it can be an uninvolved
user, so it is never the culprit.

### 13.1 Observed semantics (current code)

- Counting happens only in `updateBruteForceBucketsCounter` (core). Sources: failed credential check
  (`applyBackendResult`, before the Policy answer), legacy pre-auth brute-force reject, protected endpoints, and the
  `authn/brute_force_update` obligation (also selected for RBL / relay-domain / Lua environment learning). Every matching
  rule is incremented by exactly 1 in one pipeline; rules with a shorter period than an already matched rule are skipped.
- Not counted: success, tempfail, no-auth, list-accounts, disabled protocol, hard IP allowlist, RWP-repeated wrong
  password of a known account, RWP storage error (then tempfail). Counted although the check was skipped:
  soft-allowlisted failures (the update path tests only the hard allowlist).
- The counter key is the bucket: `period:cidr:failed_requests:ipfamily:network` plus the request protocol / OIDC client
  when the rule filters on them and the value is listed. One rule can therefore own several buckets per network, and
  rules with identical bucket parameters share one bucket.
- Windows are epoch-aligned: `total = cur + prev * weight`, `weight = 1 - (now % period) / period`; contributions reach
  back up to two periods, weighted. The limit is `failed_requests - 1`, scaled by positive reputation. `exceeded = total
  > limit`. Totals decay between requests and limits move with reputation, so a limit can be crossed several times, also
  while a ban is active, and a ban can follow without a crossing.
- The ban is written by a later request whose pre-check reads `exceeded` for the first matching rule in config order:
  `SETNX bf:ban:<network> = <rule> EX <ban_time>`. Only the winner creates the ban; an errored SETNX with an existing
  key is an unconfirmed activation. A ban is never extended. Rules with the same CIDR share one ban key, and the ban key
  ignores protocol / OIDC scope.
- Requests that hit an existing ban (Redis EXISTS, or the 300 ms L1 cache that a flush does not invalidate) are
  rejected and are still counted on the legacy path; on the Policy-owned path a repeated password of a known account is
  not counted (see 13.7).
- Toleration suppresses only new triggers; an existing ban is never tolerated. Nothing is written to Redis.
- Administrative flushes delete ban keys and also unlink bucket counters and toleration keys.

### 13.2 Public API and host lanes

`pluginapi.BruteForceEvent` (`event_version = 1`) with its own sink (`BruteForceEventSink`, registered through the
additive `BruteForceEventRegistrar`). The runner owns three bounded brute-force queues on the shared generic dispatcher
(the MFA lane stays separate): `bruteforce_lifecycle` (1024), `bruteforce_counted` (8192, counted and tolerated), and
`bruteforce_hits` (4096). The ClickHouse plugin writes each lane through its own stream buffer, so a hammered banned
network cannot evict counted contributions, and no volume flood can evict lifecycle or MFA events. Drops are counted per
lane in `plugin_auth_events_total{outcome, lane}`.

| Kind | Lane | Emitted at | Meaning |
|---|---|---|---|
| `counted` | counted | after the counter pipeline, one per (request, bucket increment) | the increment the counter really applied |
| `threshold_tolerated` | counted | `blockSuppressedByToleration` true | over limit, ban suppressed; never a ban |
| `ban_hit` | hits | existing ban found (`redis`, `l1`) or SETNX lost (`activation_race`) | rejected by an existing ban |
| `ban_activated` | lifecycle | SETNX winner | new ban instance; `ban_ref` = its `event_id`; carries the pre-check `bucket_id`, `window_index`, `window_current`, `window_previous`, `total`, `effective_limit` of the activating rule |
| `ban_activation_unconfirmed` | lifecycle | SETNX error but key present | a ban exists whose creator is unknown |
| `ban_released` | lifecycle | administrative flush deleted a ban key | release with operator reference |
| `counters_reset` | lifecycle | administrative flush unlinked bucket counters | earlier counted rows no longer feed the counter |

Fields (NULL when unknown): `event_id`, `ts`, `kind`, `deployment`/`instance`, `request_id`, `client_ip` (volume lane
only), `network`,
`ip_family`, `cidr`, `rule`, `rule_fingerprint` (sha256 over name, period, cidr, failed_requests, IP families, sorted
filters, effective ban time), `bucket_id` (sha256 over the window-less bucket key), `bucket_protocol`,
`bucket_oidc_client`, `period_seconds`, `ban_time_seconds`, `failed_requests`, `window_index`, `weight`,
`window_current`, `window_previous`, `total`, `effective_limit`, `crossed` (`total - 1 <= effective_limit < total`
for this increment; a heuristic per increment, not a unique cause), `count_source` (`backend_failure`, `pre_auth_reject`, `protected_endpoint`,
`policy_update:<feature>`), `ban_active` (tri-state: the request itself hit an existing ban; NULL when the check was
skipped), `claimed_username` (volume lane only), `account` and `account_known` (tri-state; NULL when no mapping was
consulted), `protocol`, `oidc_client_id`, `hit_source`, `stored_rule` (only on lifecycle rows; hits carry the first
matching candidate rule, which can differ from the activating rule; on `ban_released` rows of a wildcard flush `rule` is
the first configured rule sharing the ban key and is not authoritative), `expires_at`, `release_source` (`admin_flush`,
`user_flush`), `operator_client_id`, `operator_auth_method`, `keys_removed`. No password, password hash, RWP, or PW_HIST
value is exported.

### 13.3 Storage and retention

| Table | Content | Engine and keys | Retention |
|---|---|---|---|
| `bruteforce_lifecycle` | lifecycle kinds, no claimed names | `ReplacingMergeTree`, `PARTITION BY toYYYYMM(ts)`, `ORDER BY (deployment, network, ts, kind, event_id)` | 400 days |
| `bruteforce_attempts` | volume kinds, raw | `ReplacingMergeTree`, `PARTITION BY toDate(ts)`, `ORDER BY (deployment, network, bucket_id, ts, event_id)`, bloom on `client_ip`, `request_id`; `ttl_only_drop_parts` | 14 days |
| `bruteforce_attempt_summary` | materialized hourly aggregate of attempts per `(deployment, network, bucket_id, kind, window_index, hour, rule)`: count, ban-active count, min/max `window_current`, min/max ts, `uniq` states of claimed names and accounts (no raw names) | `AggregatingMergeTree`, `PARTITION BY toYYYYMM(hour)` | 400 days |

The lifecycle table keeps no client address: the activating request can be an uninvolved user behind the banned
network, and `network` already identifies the ban. Its `request_id` is kept as an opaque join key to the 14-day attempt
rows and the login row of the same request; after their retention it identifies nothing. The `uniq` states hold hashes,
not names, but a reader can test a guessed name against a small set, so the summary is access-protected like the raw
rows.

Raw attempts cover two periods only for rules up to seven days; longer windows are explained by the summary, marked as
aggregate. Replays inside the 14-day raw window are removed with `LIMIT 1 BY event_id`; summary counts are upper bounds
under replay, while min/max `window_current` stay exact. Hits and tolerated rows carry no window counts when the
pre-check did not read the counters (an existing ban skips that read).

### 13.4 Attribution and completeness

- A ban instance is the `ban_activated` (or unconfirmed) row of a `(deployment, network)`; it lasts until `expires_at`
  or the next `ban_released` of that network. Hits are attributed to the instance whose interval contains the hit, with
  a 1 s grace for L1 lag and clock skew; hits without an instance are reported as orphan. A later `ban_activated` of
  the same network ends any earlier instance whose end was not recorded (end reason unknown).
- A flush that fails after deleting some keys still reports the keys it removed; only keys whose removal Redis
  confirmed produce `ban_released` or `counters_reset` rows.
- Contributions of an instance are `counted` rows of the single activating `bucket_id` in the windows
  `window_index - 1` (up to the activation's `window_previous`) and `window_index` (up to its `window_current`),
  after the latest `counters_reset` of that bucket before the activation and before the first one after it: a reset
  restarts the window counter at 1, so later increments of a re-ban would otherwise fall into the closed set.
- `window_current` increases by one per counted increment of a bucket window across all instances of a deployment. The
  activation carries the pre-check `window_current` (and `window_previous` for the earlier window), so
  `1..window_current` is the closed set
  of increments that fed the decision: all present means `complete`, a gap or a duplicate `window_current` without a
  `counters_reset` row means `loss_detected` (replays share `event_id` and are removed first). Outside raw retention the
  summary compares `events` with `max_current - min_current + 1` per bucket window (`aggregate_only`).
- The crossing candidate is the latest `crossed = true` row of the bucket before activation, labelled a heuristic.

### 13.5 Read contract for the history task

Input: IP or network, deployment, time window of at most 31 days (server-enforced), optionally `ban_ref`. No account
filter is required. Candidate networks are computed from the prefix lengths of the configured rules (or the distinct
`cidr` values of the lifecycle table), never by scanning. The service also reads the latest activation of each
candidate network before the window start, so a ban that started earlier is found. Queries use the primary key, the
partition bound, `max_rows_to_read`, `max_execution_time`, and `(ts, event_id)` paging. Answer per ban: activating rule
and time, planned end or release, contributions with status `complete`, `loss_detected`, `aggregate_only`, or
`expired`, the crossing candidate, hits, orphan hits, and unknown parts. Support roles see counts and distinct-name
counts; claimed names and accounts of other customers behind the same IP need a released detail role. The schema
defines no views, grants, or row policies for these roles; the history service must enforce them, and direct
ClickHouse access to the brute-force tables stays limited to operators.

### 13.6 Configuration and verification

The ClickHouse plugin enables the streams with `bruteforce_lifecycle_insert_url` and `bruteforce_attempts_insert_url`
(apply `migrations/bruteforce-evidence.sql` first, then append `&input_format_skip_unknown_fields=0`); optional
`bruteforce_lifecycle_cache_key`, `bruteforce_counted_cache_key`, `bruteforce_hits_cache_key`, and
`bruteforce_flush_interval` (default `10s`, must be positive). Counted and hit streams also flush inline from their
own host lane goroutine once a stream holds `batch_size` rows; that goroutine is never a request. The inline flush
stays inside the host delivery deadline (2 s), keeps failed rows for the ticker worker, and reports the admitted
event as delivered. The ClickHouse plugin registers its sink whenever it is loaded, so enabling the insert URLs by
reload starts the export; the emitter set is fixed per process like every native plugin registration. Metrics:
`clickhouse_bruteforce_{lifecycle,counted,hits}_{queued_rows_total,flush_batches_total,flush_duration_seconds}` and
host `plugin_auth_events_total{lane="bruteforce_*"}`.

Tests: `server/core` `TestBruteForceEvents*` (shared IP with unknown claimed name, ban by a later request, affected
request, RWP and allowlist not counted, release and re-ban, partial flush, IPv6 /64, multiple rules and protocol scope, toleration
with the restored accounting), `server/bruteforce` `TestConcurrentThresholdRequestsCreateOneBanInstance`,
`server/pluginruntime` `TestBruteForceLanesKeepLifecycleUnderVolumeFlood`, the plugin unit test
`TestBruteForceInlineFlushFailureKeepsRowsAndAdmitsEvent`, and the `clickhouse_integration` tests
`TestClickHouseBruteForceEvidence*` that replay `testdata/diagnostic_contract/bruteforce_events.json` into a real
ClickHouse and answer the ban questions, including replay removal and loss detection. The browser E2E stack does not
exercise brute-force bans.

### 13.7 Findings outside the capture

- Policy-owned brute-force rejects do not set the environment-rejected marker, so the RWP window stores the unverified
  password and a repeated password of a known account is not counted while banned. Behaviour change; reported, not
  changed.
- Soft-allowlisted failures still feed the shared network bucket. Reported, not changed.
- Lua scripts can write or delete ban keys without events; such bans appear as orphan hits. Redis eviction, restart,
  or failover can end a ban without any event as well.
- Restoring toleration accounting activates toleration and reputation-scaled limits for the first time on v4.x; this
  needs a release note: networks with recent successful logins get higher limits and suppressed bans.
- The user cache flush reports only the removed keys of the last IP of the account history
  (`removedIPKeys = currentRemovedIPKeys` in `flushUserBruteForceIPKeys`); the brute-force events are emitted per IP
  and are not affected. Reported, not changed.
- The brute-force list endpoint derives `banned_at` from the current configured ban time and the remaining TTL, which
  is wrong after a `ban_time` change; `bruteforce_lifecycle` keeps the real activation time. Reported, not changed.
