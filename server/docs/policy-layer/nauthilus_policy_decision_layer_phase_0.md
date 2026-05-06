# Nauthilus Policy Decision Layer - Phase 0

## Goal

Freeze the current externally visible authentication behavior before any Policy Decision Layer runtime exists. This phase adds and records parity tests that detect regressions in the current direct paths, current `AuthResult` handling, current auth-FSM mappings, response rendering, and transport adapters.

No policy compiler, policy runtime snapshot, `auth.policy` config surface, `standard_auth` evaluator, decision authority switch, or target-FSM adapter was introduced.

## Implemented Files and Modules

| File | Purpose |
|---|---|
| `server/core/current_behavior_parity_test.go` | Adds focused current-behavior parity tests for Lua environment source trigger/abort, TLS tempfail, relay-domain reject, RBL reject, direct brute-force block, and Lua subject source status-message denial at the auth boundary. |
| `server/core/auth_fsm_test.go` | Extends the current auth-FSM parity coverage for feature fail/tempfail/unset transitions, password fail/tempfail/empty-password transitions, and feature-result-to-FSM mappings for Lua, RBL, and tempfail. |
| `server/docs/policy-layer/nauthilus_policy_decision_layer_phase_0.md` | Documents the implemented Phase 0 scope, validation, temporary adapter status, risks, and review comparison. |

## Tests and Validation

Focused validation run:

```bash
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test ./server/core -run 'TestCurrentBehaviorParity|TestNextAuthFSMState|TestMapAuth'
```

Result: passed.

The first run without an explicit cache failed because the sandbox could not write to `/Users/croessner/Library/Caches/go-build`. The successful run used `GOCACHE=/tmp/nauthilus-go-cache`.

Package validation:

```bash
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test ./server/core
```

Result: passed.

Guardrail validation:

```bash
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache make guardrails
```

Result: passed. An earlier guardrail run found the new built-in control parity test above the local `funlen` limit; the test cases were extracted into a small helper and the final guardrail run passed.

Forbidden Go-name check:

```bash
git diff -- '*.go' | rg -n -i '^\+.*phase'
git diff --no-index -- /dev/null server/core/current_behavior_parity_test.go | rg -n -i '^\+.*phase'
rg -n -i 'phase' server/core/current_behavior_parity_test.go server/core/auth_fsm_test.go
```

Result: no matches in changed Go code.

## Parity Coverage

New focused coverage:

| Requirement | Coverage |
|---|---|
| Brute-force direct block | `TestCurrentBehaviorParityBruteForceDirectBlock` drives the current `CheckBruteForce` direct gate and asserts the current block result and brute-force runtime fields. |
| Lua environment source trigger | `TestCurrentBehaviorParityLuaEnvironmentTriggerAndAbort/trigger returns Lua environment result` asserts `AuthResultFeatureLua` and the environment rejection flag. |
| Lua environment source abort | `TestCurrentBehaviorParityLuaEnvironmentTriggerAndAbort/abort allows remaining auth flow` asserts current abort behavior returns `AuthResultOK`. |
| TLS tempfail | `TestCurrentBehaviorParityBuiltInPreAuthControls/tls without accepted transport is temporary failure feature` asserts `AuthResultFeatureTLS`. |
| Relay-domain reject | `TestCurrentBehaviorParityBuiltInPreAuthControls/unknown relay domain is deny feature` asserts `AuthResultFeatureRelayDomain`. |
| RBL reject | `TestCurrentBehaviorParityBuiltInPreAuthControls/rbl threshold match is deny feature` asserts `AuthResultFeatureRBL`. |
| Lua subject source reject and status message | `TestCurrentBehaviorParityLuaSubjectStatusMessage` asserts auth denial, `auth_fail` terminal state, and the Lua-provided status message. |
| Auth-FSM feature/password transitions | `TestNextAuthFSMState_AllowedTransitions`, `TestMapAuthFeatureResultToFSMEvent`, and `TestMapAuthPasswordResultToFSMEvent`. |

Existing coverage kept as Phase 0 corpus material:

| Requirement area | Existing coverage |
|---|---|
| Brute-force bucket and learning-related mechanics | `server/bruteforce/bruteforce_test.go`, `server/core/compute_bf_hints_test.go`, `server/config/control_config_test.go`. |
| Backend success, failure, and tempfail | `server/core/auth_application_service_test.go`. |
| Lookup-identity / no-auth success, failure, and tempfail | `server/core/auth_application_service_test.go`, `server/handler/grpcauth/server_test.go`, `server/handler/grpcauth/handler_test.go`. |
| List-accounts success and scope/caller-auth rejection | `server/core/auth_application_service_test.go`, `server/handler/grpcauth/server_test.go`, `server/handler/grpcauth/handler_test.go`. |
| HTTP JSON response parity | `server/core/response_json_golden_test.go`, `server/core/response_fail_test.go`, `server/core/response_headers_test.go`. |
| HTTP CBOR and list-accounts media parity | `server/core/rest_list_accounts_cbor_test.go`, `server/handler/auth/handler_test.go`, `server/util/contentneg/negotiator_test.go`. |
| Nginx and header-style response parity | `server/core/response_headers_test.go`, `server/core/response_fail_test.go`, `server/core/nginx_password_test.go`. |
| gRPC AuthService, LookupIdentity, and ListAccounts parity | `server/handler/grpcauth/server_test.go`, `server/handler/grpcauth/handler_test.go`, `server/grpcapi/auth/v1/request_mapper_test.go`. |
| IdP auth-flow parity | `server/handler/frontend/idp/login_test.go`, `server/handler/frontend/idp/oidc_test.go`, `server/handler/frontend/idp/saml_test.go`, `server/handler/frontend/idp/oidc_device_code_test.go`, and related IdP flow tests. |

## Active Temporary Adapters

No new temporary adapter was introduced in this phase.

Current pre-policy behavior remains active as baseline material only:

| Current baseline path | Planned later replacement/removal |
|---|---|
| Direct brute-force gate in `PreproccessAuthRequest` / `CheckBruteForce` | Wrapped into `CheckResult` collection in Phase 3, shadow-compared by `standard_auth` in Phase 4, routed through policy-owned obligations in Phase 7 and authoritative default policy in Phase 8, then removed as a direct bypass in Phase 14. |
| Current `AuthResultFeature*` to `features_*` FSM mapping | Compared against target markers in Phase 6, then removed when target FSM becomes authoritative in Phase 9 and final cleanup lands in Phase 14. |
| Current password-result to `password_*` FSM mapping | Compared through the target-FSM adapter in Phase 6 and removed from the policy decision path in Phase 9/14. |

## Deliberately Not Implemented

- No `auth.policy` config structs, `mapstructure` tags, schema-index entries, `ConfigProblem` validation, dump/redaction output, or config conversion logic.
- No Policy Runtime Snapshot, attribute registry, check registry, AST, compiler, evaluator, report model, Prometheus policy metrics, OTel policy spans, or policy debug module.
- No `standard_auth` built-in policy definition or shadow evaluation.
- No target-FSM event marker adapter or target-FSM authority switch.
- No public config root such as `policy_engine`.

## Open Risks

- Some broad transport and IdP rows in section 17.6 are covered by existing focused tests rather than new matrix-named tests. This keeps Phase 0 scoped, but later phases should consolidate these into an explicit policy parity suite when shadow policy output exists.
- Observe-mode mismatch reporting cannot be exercised without the observe-mode runtime introduced in later phases. Phase 0 records this as a later validation target rather than inventing a policy-less placeholder.
- Logs, metrics, and trace parity are currently asserted indirectly by existing mechanism tests. Later policy phases must add explicit policy-report, metric, trace, and mismatch assertions when those runtime paths exist.

## Review-Abgleich

### General Completion Rules from Section 18.1

| Rule | Result |
|---|---|
| Focused reproducer or parity tests exist before behavior-changing code | Satisfied. This phase changed only tests and temp documentation; no production behavior was changed. |
| Current external behavior unchanged unless explicitly changed | Satisfied. No production code changed. |
| New runtime paths have observability | Not applicable. No new runtime path was introduced. |
| New config paths have schema, errors, and dump support | Not applicable. No new config path was introduced. |
| Reports/logs follow redaction rules | Not applicable. No new report or policy log surface was introduced. |
| New policy code has unit and auth-boundary parity tests | No policy code was introduced. Core parity tests were added at feature/auth-boundary level. |
| Reload behavior is atomic | Not applicable. No snapshot or reload behavior was introduced. |
| Phase note lists adapters and planned removal | Satisfied in the "Active Temporary Adapters" section. |

### Phase 0 Requirements

| Requirement | Result |
|---|---|
| Freeze brute-force direct block | Satisfied by new direct `CheckBruteForce` parity test. |
| Freeze brute-force learning behavior | Covered by existing brute-force and config learning tests; no new learning behavior was introduced. |
| Freeze Lua environment source trigger and abort | Satisfied by new Lua environment source parity test. |
| Freeze TLS tempfail, relay-domain reject, RBL reject | Satisfied by new built-in pre-auth control parity test. |
| Freeze backend success/failure/tempfail | Covered by existing auth application service tests. |
| Freeze Lua subject source reject and Lua status message | Satisfied by new auth-boundary subject-source status-message parity test. |
| Freeze auth-FSM feature/password transitions | Satisfied by extended FSM tests. |
| Freeze lookup-identity / no-auth parity | Covered by existing application service and gRPC tests. |
| Freeze list-accounts parity | Covered by existing application service, gRPC, and HTTP CBOR/list-accounts tests. |
| Freeze response rendering surfaces | Covered by existing response, content negotiation, gRPC, and IdP tests; later phases should centralize these into an explicit policy parity suite. |

### Section 17 Registry and Mapping Tables

The implementation did not create registries yet. Phase 0 uses the tables as coverage targets:

- Check-type rows for brute force, Lua environment source, TLS, relay domains, RBL, backend, Lua subject source, and account provider are represented by new or existing current-behavior tests.
- FSM marker intent is represented by current FSM state/event tests and current `AuthResult` mapping tests.
- Response marker parity is represented by existing response surface tests.
- `standard_auth` mapping is not implemented in this phase; the new tests freeze the current behavior that `standard_auth` must later reproduce.

### Config UX, Observability, and Atomic Reload

No config surface, observability surface, report surface, or runtime snapshot was changed. The relevant spec requirements are intentionally deferred to the phases where those surfaces are introduced.

### Gaps Found and Fixed During Review

- Added missing current FSM allowed-transition coverage for feature fail/tempfail/unset and password fail/tempfail/empty-password outcomes.
- Added missing feature-result mapping coverage for Lua, RBL, and generic tempfail.
- Added an auth-boundary Lua subject source status-message denial test instead of relying only on lower-level Lua tests.
- Split the new built-in control parity test setup after guardrails reported the function above the local size limit.
