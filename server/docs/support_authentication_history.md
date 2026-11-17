# Support authentication history API

Status: implemented on the `features` branch, locally tested; not released and not rolled out.

This read-only management API answers, from recorded ClickHouse evidence only: *why could a user not log in at a
past attempt* – were the primary credentials rejected, did a second factor fail, did a control such as a brute-force
ban reject the request before the credential check, or was there a technical error – and what cannot be said.

It is a separate area from the current-state support inspection: it never reads today's ban, GeoIP, reputation, or
configuration state, and today's state never explains a past failure. The data contract it reads is
[`contrib/plugins/clickhouse/DIAGNOSTIC_CONTRACT.md`](../../contrib/plugins/clickhouse/DIAGNOSTIC_CONTRACT.md); the
machine contract is the `SupportHistory` tag of [`server/openapi/openapi.yaml`](../openapi/openapi.yaml).

## 1. Architecture

| Layer | Package | Responsibility |
|---|---|---|
| Application service | `server/supporthistory` | Authorization, shared limits, concurrency gate, correlation, interpretation, projection, coverage, audit. Transport-independent. |
| ClickHouse reader | `server/supporthistory/clickhousestore` | Bounded read-only queries over the HTTP interface with typed parameters, per-query budgets, self-terminating `FORMAT JSON`, reader self-check. |
| HTTP adapter | `server/handler/support` | Bearer facts → verified credential, strict JSON bodies, `Cache-Control: no-store`, fixed error codes. No diagnosis logic. |

The process owns one `Service`. A later MCP adapter authenticates its own transport, builds a
`supporthistory.VerifiedCredential` from verified facts (client id, subject, scopes), and calls the same methods; it
gets the same permission mapping, limits, gate, projection, and error codes. Trust boundary: only a transport adapter
that verified the credential itself may construct a `VerifiedCredential`; nothing in it comes from request bodies or
client-supplied headers. The zero `Caller` has no permission, so an internal call never gets rights implicitly.

## 2. Permissions

| Bearer scope | Projection | Grants |
|---|---|---|
| `nauthilus:history_read` | `support` | Attempt search and detail of a **named** subject, ban search with counts and distinct-name counts. |
| `nauthilus:history_detail` | `detail` | Everything above, plus other people's claimed names, accounts, and client IPs behind shared addresses, operator ids of ban releases, the individual factor events of fail-latched flows, and detail lookups without a subject. Implies `history_read`. |

`nauthilus:admin`, `nauthilus:security`, and Basic credentials grant **no** history access (403 `FORBIDDEN`). The
base `nauthilus:authenticate` scope of the backchannel API is still required, because the whole `/api/v1` group demands
it. A console token therefore can also call the authentication endpoints; whether `/api/v1/support` should be exempt
from that base scope is an open maintainer decision (least privilege) and is not changed here. Register the console as an OIDC
client with `client_credentials` and the history scopes in `identity.oidc.clients[].scopes`; tokens must target the
backchannel audience.

Authorization is checked before any data access (including Redis identity mappings and the reader self-check) and
for every page and every attempt id. A guessed or foreign attempt id answers exactly like an unknown one
(`attempt: null`).

## 3. Configuration and reader account

```yaml
storage:
  history:
    clickhouse:
      url: "http://clickhouse.nauthilus.svc:8123/"   # empty disables the capability (HTTP 503 HISTORY_NOT_CONFIGURED)
      database: nauthilus
      username: nauthilus_history
      password: "${NAUTHILUS_HISTORY_CLICKHOUSE_PASSWORD}"
      deployment: prod                               # writer label of the ClickHouse plugin; the data boundary
      budget_mode: query_settings                    # query_settings (readonly=2 profile) | profile (readonly=1)
      timeout: 15s                                   # time budget of one operation
      max_execution_time: 8s                         # per query; must be shorter than timeout
      max_rows_to_read: 5000000
      max_bytes_to_read: 2147483648
      max_response_bytes: 8388608
```

Provision a dedicated account with [`contrib/clickhouse-kubernetes/history-reader.sql`](../../contrib/clickhouse-kubernetes/history-reader.sql):
`readonly = 2 CONST`, a `MAX` constraint on every budget, overflow modes `CONST 'throw'`, and `SELECT` on the five
diagnostic tables only. Do not reuse the Grafana account: it could not set `max_rows_to_read`, and it must not hold
the brute-force tables (claimed login names). With `budget_mode: profile` the account uses `readonly = 1` and the
service sends no settings; it verifies the effective profile values instead.

Before reading, the service runs a cached self-check (`getSetting`): it refuses a writable account (`readonly = 0`),
any overflow mode other than `throw` (silent truncation), and in `profile` mode any missing or larger-than-configured
budget. A refused reader answers 503 `HISTORY_READER_UNSAFE`. The configuration and the configured rule prefixes are
read at startup; changing them needs a restart (recorded prefixes still cover older rules).

## 4. Endpoints

All operations are `POST` with a JSON body (`Content-Type: application/json`, at most 16 KiB, unknown fields and
query parameters rejected) and `schema_version: "1"`. Times are RFC 3339; windows are `[from, until)` in event time,
at most 31 days.

| Path | Purpose |
|---|---|
| `/api/v1/support/authentication-attempts/search` | Attempts of one subject (`login` or `account`), optional `client_ip`, `protocol`, `oidc_client_id`, `saml_entity_id`. Page limit 1–50 (default 20). |
| `/api/v1/support/authentication-attempts/detail` | All events of one `attempt_id`; `around` is any instant of the attempt (use `started_at` from a search). |
| `/api/v1/support/bruteforce-bans/search` | Bans of one `ip` or `network`, optional `ban_ref`; `subject` only for the detail role. Page limit 1–20 (default 10). |

Optional `audit_reference` (`^[A-Za-z0-9._:/-]{1,64}$`) is an unverified ticket annotation for the audit log.

```json
{"schema_version": "1", "subject": {"login": "anna@example.org"},
 "filter": {"client_ip": "203.0.113.42", "protocol": "oidc",
            "from": "2026-11-16T08:55:00Z", "until": "2026-11-16T09:05:00Z"},
 "page": {"limit": 20}}
```

## 5. HTTP status versus evidence

| Status | Code | Meaning |
|---|---|---|
| 200 | – | Processed. Read `history` and `result_basis`; evidence may be partial or empty. A failed login in the data is **not** an error. |
| 400 | `INVALID_REQUEST`, `WINDOW_TOO_LARGE`, `INVALID_CURSOR`, `INVALID_ATTEMPT_ID` | Fix the request. A cursor is bound to the same query and projection. |
| 401 | – | Missing or invalid backchannel token (middleware body `{"error": …}`). |
| 403 | `FORBIDDEN` | Missing history scope, Basic or admin-only credential, or a ban-search subject without the detail role. |
| 422 | `QUERY_TOO_BROAD` | Read or response-size budget exceeded even with the smallest scan slice; narrow the window, add filters, or lower `page.limit`. |
| 429 | `HISTORY_BUSY` | Shared concurrency gate full (4 per process, 2 per client); retry later. |
| 503 | `HISTORY_NOT_CONFIGURED`, `HISTORY_SOURCE_UNAVAILABLE`, `HISTORY_READER_UNSAFE`, `HISTORY_TIMEOUT` | History unavailable. Never shown as "no attempts". A failed or truncated `logins` read is always 503. |
| 500 | `INTERNAL_ERROR` | Unexpected. |

Error bodies are `{"schema_version":"1","error":{"code":"…","message":"…"}}`; `message` is a fixed English text per
code and must not be parsed or shown as the explanation of a login.

## 6. Coverage and empty results

Every 200 answer carries `history`:

- `availability`: `available`, or `partial` when a source could not be read, is not installed, or holds no rows of the
  deployment (`auth_events` unreadable: every flow's `steps.second_factor` is `not_recorded`, never "not required").
- `sources[]`: `state` (`read`, `read_failed`, `not_installed`, `no_rows_for_deployment`) and `window_coverage`
  (`within_retention`, `partially_expired`, `expired`) per table. `no_rows_for_deployment` means the stream is disabled
  **or** nothing was recorded; the two cannot be told apart.
- `conditions[]`: the limiting conditions above as codes, plus `LEGACY_ROWS_PRESENT`, `CONTRACT_CUTOVER_UNKNOWN`,
  `NO_CONTRACT_ROWS_IN_WINDOW`, `CANDIDATE_NETWORKS_PARTIAL`.
- `known_limits[]`: limits that always apply, for example `SUCCESS_DEDUPLICATION_MAY_HIDE_REPEATS`,
  `BOUNDED_BUFFERS_MAY_DROP_ROWS`, `BEST_EFFORT_TERMINAL_POST_ACTIONS_MAY_BE_DROPPED`, `NO_ROW_WITHOUT_ANALYTICS_EFFECT`,
  `FLOW_COMPLETION_NEVER_RECORDED`, `BROWSER_ABORTS_NOT_RECORDED`, `LOGIN_CASE_VARIANTS_NOT_MATCHED`.
- `delivery_completeness` is always `not_guaranteed`; `late_events_possible` is true when the window ends within five
  minutes of the query (export delay).
- `contract_rows_since`: first row of the diagnostic contract in the window (older rows are legacy).

`result_basis` is the match state of every answer. `matches_found` wins over any condition. An answer without matches
names the state of its primary source (`logins` for attempts, `bruteforce_lifecycle` for bans), in this order:
`source_not_installed`, `source_without_rows`, `source_read_failed`, `window_expired`, `window_partially_expired`; then
`evidence_truncated`, then `identity_unresolved` (a login without a stored or recorded account), and only then
`no_matches`. Secondary sources (step events, raw brute-force rows, summaries) only appear in `conditions`, so a
deployment without second factors can still answer `no_matches`. An empty list never means "the user did not log in"; show
`result_basis` and `conditions`.

Retention: `logins` and `auth_events` one week, raw brute-force attempts 14 days, lifecycle and hourly summary 400
days. Expired or disabled sources are never an all-clear. Production data written before the contract rollout is
legacy (`contract_version = 0`) and is shown as `LEGACY_UNINTERPRETED` without a cause.

## 7. Attempts

An attempt is one IdP browser flow (`kind: flow`, all rows and factor events sharing the non-authorizing `flow_ref`)
or one authentication request without flow (`kind: request`, keyed by the request id = log `session`). `attempt_id`
is `fl1.<flow_ref>` or `rq1.<request id>`; neither grants anything. Correlation never uses time proximity, account, or
IP; parallel tabs are separate flows, and every factor retry is its own event.

| Field | Values |
|---|---|
| `outcome` | `succeeded`, `rejected`, `technical_error`, `not_observed`, `unknown` |
| `outcome_basis` | `request_terminal_answer` (sealed answer of a request), `primary_failure_latched` (a fail-latched flow cannot succeed), `primary_failure_kept` (detail role: the latched step-up was consumed), `none`, `legacy` |
| `final_outcome_observed` | true only with one of the recorded bases above |
| `progress` | furthest recorded step: `none`, `technical_error`, `pre_credential_rejected`, `primary_rejected`, `primary_succeeded`, `second_factor_completed`, `primary_failure_latched` |
| `steps` | `primary`: `recorded`/`not_recorded`; `second_factor`: `recorded`, `not_recorded`, `withheld`, `not_applicable` |
| `findings[]` | every observed failure with `code`, `category`, `certainty` (`observed`/`uncertain`), `uncertainty[]`, `event_id`; there is no single invented "main cause" |
| `recording` | `known_gaps[]` (`CONFLICTING_TERMINAL_RECORDS`, `PRIMARY_ROW_NOT_RECORDED`, `AUTH_EVENTS_NOT_READ`, `ATTEMPT_MAY_EXTEND_BEYOND_READ_WINDOW`, `FLOW_COMPLETION_NEVER_RECORDED`, `LEGACY_ROWS_UNINTERPRETED`), `replayed_rows_merged`, `legacy_rows`, `events_truncated`, `events_withheld` |

A completed IdP login is never recorded (no token or assertion event exists), so IdP flows stay `not_observed` unless
the flow was latched. An IdP password row with `ok` means only "primary step succeeded"; a request row with `ok`
means the authentication request of that protocol was accepted. `known_gaps: []` only means no gap is known.

Events (`events[]`, at most 200 per attempt, ordered by recorded time; `sequence` is presentation order only, there is
no global order across instances) carry `stage`, `result`, `code`, `category`, `identity` (`supplied_login` is the
claim as typed, `canonical_account` the account recorded at event time, `account_found_at_capture` is a weak
capture-time flag, `matched_by`, `subject_match`, `redacted`), `context`, the recorded Policy `decision`
(`outcome_marker`, `response_marker`, `tempfail_reason`, `decision_sources`, …), `factor` for second-factor events,
and structured `reputation` (`state: none_recorded` is never a neutral rating; an early rejection can end before any
reputation check).

### Codes

| Code | Meaning |
|---|---|
| `AUTHENTICATION_ACCEPTED` / `PRIMARY_AUTHENTICATION_SUCCEEDED` | Request accepted / IdP primary step succeeded (not a completed login). |
| `CREDENTIALS_REJECTED` | Credential check failed. Never "password wrong": unknown user and wrong password are not distinguished (uncertainty `UNKNOWN_USER_AND_WRONG_PASSWORD_NOT_DISTINGUISHED`). |
| `CREDENTIALS_INCOMPLETE` | Empty password or username. |
| `REJECTED_BY_BRUTE_FORCE_PROTECTION`, `REJECTED_BY_RBL`, `REJECTED_BY_RELAY_DOMAIN_POLICY`, `REJECTED_BY_ENVIRONMENT_CONTROL`, `REJECTED_BEFORE_CREDENTIAL_CHECK`, `REJECTED_TLS_REQUIRED` | Rejected before the credential check; the password was never verified. |
| `REJECTED_BY_SUBJECT_CONTROL`, `REJECTED_BY_POLICY` | Policy rejection; the credential result is not recorded. |
| `TECHNICAL_ERROR_BACKEND`, `TECHNICAL_ERROR_BRUTE_FORCE`, `TECHNICAL_ERROR_POLICY`, `TECHNICAL_ERROR_ENVIRONMENT`, `TECHNICAL_ERROR_INTERNAL_GUARD`, `TECHNICAL_ERROR` | Tempfail without a deliberate rejection. |
| `OUTCOME_NOT_RECORDED`, `LEGACY_UNINTERPRETED` | No interpretable terminal outcome. |
| `SECOND_FACTOR_ACCEPTED` | Factor verified and step-up completed (login completion still not recorded). |
| `SECOND_FACTOR_REJECTED` | Factor did not verify (uncertainties: `TOTP_INVALID_MAY_INCLUDE_VERIFIER_ERROR`, `RECOVERY_CODE_IN_TOTP_FORM_REPORTED_AS_TOTP`, `RECOVERY_CODE_REUSE_NOT_DISTINGUISHABLE`, `WEBAUTHN_HELPER_FAILURES_REPORTED_AS_REJECTED`). |
| `SECOND_FACTOR_CHALLENGE_UNAVAILABLE`, `STEP_UP_EXPIRED`, `STEP_UP_CONFLICT`, `FLOW_RESUME_CONFLICT` | Challenge or flow state missing, expired, or conflicting. |
| `SECOND_FACTOR_ATTEMPT_LIMIT` | Attempt budget exhausted. |
| `SECOND_FACTOR_TECHNICAL_ERROR`, `FLOW_STATE_ERROR` | Verifier, attempt store, or state failure. |
| `SECOND_FACTOR_ON_LATCHED_FLOW` | Support role: factor attempts on a flow whose primary step failed; results withheld. |
| `SECOND_FACTOR_VERIFIED_PRIMARY_FAILURE_KEPT` | Detail role: the factor was right, the earlier primary failure stays. Never a password success. |

UIs must switch on codes and tolerate unknown codes (show them verbatim as "unclassified").

### Paths and their evidence

| Path | Recorded | Not recorded |
|---|---|---|
| Mail/API authentication (nginx, header, json, cbor, basic, gRPC) | one or more `logins` rows with the sealed answer | repeats hidden by deduplication, dropped buffers, requests without analytics effect |
| IdP password (OIDC, SAML, self-service portal) | one row per submission in the flow | completion of the login, SSO session reuse |
| TOTP, recovery code, WebAuthn as second factor | one event per verification | browser aborts, a ceremony never submitted |
| Passwordless WebAuthn | does not exist in the IdP (second factor only) | – |
| Self-service step-up (`protocol: account`) | events keyed by request id, no `flow_ref` | link to the portal login flow |
| Pre-credential rejection (ban, RBL, relay domain, TLS, environment) | row with `pre_auth` stage, marker, `decision_sources` | later checks (GeoIP/reputation may be absent) |

### Identity

`subject.login` is matched literally and in lower case against the recorded `username`; accounts come from the supplied
`account`, today's stored login mapping (`current_account_mapping`, Redis read only, no authentication), and accounts
recorded on rows of that login in the window (`recorded_at_event`, one hop). `subject_resolution` lists each with its
provenance. Today's mapping cannot prove a historical alias; renamed accounts are found through recorded rows, never
re-labelled. An unresolved login is never shown as a verified account.

### Projection

Support: other identities in a flow are `redacted`; on fail-latched flows every factor event is withheld and
replaced by `SECOND_FACTOR_ON_LATCHED_FLOW`, and `started_at`/`last_observed_at`/counts are computed over visible
events only. Detail: everything recorded except data the API never reads (password hashes, OTPs, recovery codes,
tokens, session or flow handles, WebAuthn payloads, client ports, user agents).

### Paging and consistency

Attempts are ordered by latest subject-matching activity, newest first. The window is scanned in slices (24 h,
shrinking to 1 h before 422); `page.scanned_until` states the fully covered part `(scanned_until, until)` (attempts
anchored exactly at `scanned_until` may follow on the next page). A page may be short while `next_cursor` is set. There is no snapshot isolation: rows exported late (login flush 60 s, event flush
10 s) can repeat an attempt on a later page – deduplicate by `attempt_id`, and re-run a search that ends near "now".

## 8. Brute-force bans

Candidate networks of an IP come from the configured rule prefixes and the prefixes recorded in the evidence tables,
never from a scan. Each ban instance (`ban_ref` = activation event id) shows the recorded rule and limits (never
today's configuration), `activation.activating_request: NOT_A_CULPRIT` (behind NAT the request that wrote the ban can
be an uninvolved user), the end (`released` is the only recorded end; `superseded_by_new_activation` bounds the end
without recording it; `planned_end_passed_unconfirmed`, `planned_end_after_window`, and `unknown` are not recorded),
`unknowns[]` (for example `ACTIVATION_CREATOR_UNKNOWN`, `END_NOT_RECORDED_EVICTION_OR_SCRIPT_POSSIBLE`,
`UNCONFIRMED_ACTIVATION_DURING_BAN` – an unconfirmed activation inside a running ban is never treated as a new ban –
and `LIFECYCLE_ROWS_TRUNCATED` when a network has more than 512 lifecycle rows in retention; the newest rows are kept),
and:

- `contributions`: counted increments of the activating bucket between the counter resets before and after the
  activation; `windows[]` states the activation window and the previous window separately (`complete`,
  `loss_detected`, `aggregate_only`, `expired`, `not_applicable`), `status` is the worst. Beyond raw retention the hourly
  summary is used (`counts_are_upper_bounds`, `summary_check_unreliable` after a reset). `crossing_candidate` is a
  heuristic, never a cause. `complete` covers the contributions of this ban decision, not all login attempts.
- `hits`: requests rejected by the existing ban inside the window (raw rows, or hour-aligned summary beyond 14 days).
- `orphan_hits`: hits no recorded ban explains (bans written by scripts, evicted keys, lost lifecycle events).
- `threshold_tolerated`, `releases`, `counter_resets`, `unconfirmed_activations` as separate lists.

Support sees counts and distinct-name counts only; claimed names, accounts, client IPs, claimant lists, and operator
ids need the detail role, and a `subject` is accepted only there (no name-testing oracle). Claimed names are claims,
never persons.

## 9. Privacy and audit

Filters travel only in bodies; responses are `no-store`. Each operation that reaches the service, allowed, denied, or
invalid, writes one structured log
record (`audit=support_history`): operation, caller client id, method, projection, result code, result count, duration,
`audit_reference`, and a domain-separated digest of the subject (no clear-text subject, no evidence). Transport-shape
rejections (query parameters, wrong media type, oversized or non-strict JSON) are answered by the adapter with 400
before the service and are not audited; they reveal no data. Queries never
change authentication state, never authenticate, and never trigger Policy, post-actions, or writes; the reader account
is refused unless read-only.

## 10. Schema evolution

`schema_version` is `1`. Additive response fields and new codes may appear without a version change; removing or
re-meaning a field or code needs a new version. Requests with unknown fields are rejected.

## 11. UI examples (abridged)

Password rejection (mail request):

```json
{"attempt_id": "rq1.2qCq7…", "kind": "request", "outcome": "rejected", "outcome_basis": "request_terminal_answer",
 "final_outcome_observed": true, "progress": "primary_rejected",
 "findings": [{"code": "CREDENTIALS_REJECTED", "category": "credential", "certainty": "uncertain",
               "uncertainty": ["UNKNOWN_USER_AND_WRONG_PASSWORD_NOT_DISTINGUISHED"], "event_id": "9f1c…"}]}
```

MFA rejection inside a flow that is still open:

```json
{"attempt_id": "fl1.0123…", "kind": "flow", "outcome": "not_observed", "outcome_basis": "none",
 "final_outcome_observed": false, "progress": "primary_succeeded",
 "steps": {"primary": "recorded", "second_factor": "recorded"},
 "findings": [{"code": "SECOND_FACTOR_REJECTED", "category": "second_factor", "certainty": "uncertain",
               "uncertainty": ["TOTP_INVALID_MAY_INCLUDE_VERIFIER_ERROR", "RECOVERY_CODE_IN_TOTP_FORM_REPORTED_AS_TOTP"]}],
 "recording": {"known_gaps": ["FLOW_COMPLETION_NEVER_RECORDED"]}}
```

Technical error:

```json
{"outcome": "technical_error", "findings": [{"code": "TECHNICAL_ERROR_BACKEND", "category": "technical"}],
 "events": [{"decision": {"outcome": "tempfail", "tempfail_reason": "backend_tempfail"}}]}
```

Incomplete evidence:

```json
{"result_basis": "no_matches",
 "history": {"availability": "partial", "conditions": ["SOURCE_WITHOUT_ROWS_STREAM_DISABLED_OR_NO_TRAFFIC",
             "WINDOW_PARTIALLY_EXPIRED"], "delivery_completeness": "not_guaranteed"},
 "attempts": []}
```

Suggested wording: "No recorded attempt matches in the readable part of the history" – never "the user did not try to
log in".

## 12. Clients and verification

- Go: `server/openapi/client` `SearchAuthenticationAttempts`, `GetAuthenticationAttempt`, `SearchBruteForceBans`.
- Python: `contrib/client/nauthilus-admin.py support …` (see its README for exit codes; a deployed mail-stack copy must
  be synced separately).
- Tests: `server/supporthistory` (JSON scenario `testdata/attempt_scenarios.json`), `server/supporthistory/clickhousestore`,
  `server/handler/support` (scope matrix, OpenAPI response validation), and the `clickhouse_integration` tests
  `TestClickHouseHistory*` that write through the real plugin into ClickHouse 25.8 and read through a provisioned
  read-only account (`contrib/clickhouse-kubernetes/run-integration-tests.sh -run TestClickHouseHistory`).
