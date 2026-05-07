# Nauthilus Policy Decision Layer - Phase 8

## Goal

Phase 8 makes the built-in `standard_auth` policy set the authoritative production decision source when the active policy snapshot has no configured custom policy rules.

This slice keeps custom policies non-authoritative, keeps the current auth FSM authoritative, keeps current response rendering in place, and does not add any public config root or field. Current behavior remains represented by `standard_auth`; no separate legacy execution pipeline was introduced.

## Implemented Files and Modules

- `server/policy/types.go`
  - Adds central response-marker and obligation constants for the built-in policy decision surface.
  - Keeps stable public marker values as `auth.response.*` and `auth.obligation.*` strings instead of current internal enum names.

- `server/policy/evaluation/standard.go`
  - Adds a pre-auth-only built-in evaluator so terminal pre-auth decisions can be selected without falling through to final default-deny.
  - Normalizes built-in evaluation so repeated authority and comparison runs replace the selected policy sequence instead of appending duplicate decisions.
  - Reuses central response-marker and obligation constants.

- `server/policy/collection/collection.go`
  - Adds a request-context guard that allows built-in default authority only when the active snapshot default is `standard_auth` and no configured rules exist in any compiled stage plan.
  - Leaves configured/custom policy sets in diagnostic-only mode for this slice.

- `server/core/policy_authority.go`
  - Adds the private authority adapter from selected `standard_auth` decisions to current `AuthResult` values and current response helpers.
  - Applies selected response messages before current response rendering.
  - Executes policy-owned obligations from the authoritative decision, currently brute-force counter update and Lua post-action enqueue.
  - Stores the old direct outcome as a request-local diagnostic so shadow comparison against the old direct path remains available after the authoritative policy decision is applied.

- `server/core/policy_collection.go`
  - Merges the request-local direct-outcome diagnostic into the existing policy comparison path.
  - Keeps current response surface and current FSM path details from the response-time comparison when the diagnostic did not know them yet.

- `server/core/environment.go`
  - Routes terminal pre-auth pre-auth results through built-in policy authority when the active snapshot is the default-only set.
  - Preserves current external `AuthResult` mappings while selecting the built-in policy decision first.

- `server/core/auth.go`
  - Routes password/backend final decisions through built-in policy authority.
  - Applies the built-in pre-auth decision at the brute-force checkpoint before falling back to the old direct brute-force handling.
  - Evaluates list-account built-in final decisions before the existing comparison path while leaving list-account public rendering unchanged.

- `server/core/protect_impl.go`
  - Applies the built-in pre-auth decision for protected endpoint brute-force rejection before the old direct fallback.

- `server/idp/nauthilus_idp.go`
  - Applies the built-in pre-auth decision for IdP brute-force rejection before the old direct fallback.

- `server/core/response.go`
  - Reuses central response-marker constants for comparison output.

## Tests and Validation

Focused tests were added before behavior-changing code. The first focused runs failed because the default-only authority guard, pre-auth-only evaluator, auth-boundary authority selection, and old-direct diagnostic preservation did not exist yet.

Added tests:

- `server/policy/evaluation/standard_test.go`
  - Verifies pre-auth-only built-in evaluation selects the implicit pre-auth pass without selecting final default-deny.

- `server/policy/collection/collection_test.go`
  - Verifies the built-in default set is authoritative only when no configured policy rules exist.

- `server/core/policy_authority_test.go`
  - Verifies pre-auth control handling selects `standard_tls_enforcement` as the authoritative decision under a default-only snapshot.
  - Verifies password/final handling selects `standard_auth_failure` as the authoritative decision under a default-only snapshot.
  - Verifies the old direct outcome remains available as a comparison diagnostic when the authoritative default decision overrides the old direct result.

Validation run so far:

```bash
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test -run TestAuthBoundaryKeepsDirectOutcomeDiagnosticWhenDefaultSetOverrides ./server/core
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test -run 'TestAuthBoundaryDefaultSetSelects|TestAuthBoundaryKeepsDirectOutcomeDiagnostic|TestStandardPreAuthEvaluation|TestDecisionContextDefaultSetAuthority' ./server/core ./server/policy/evaluation ./server/policy/collection
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test -run 'TestAuthBoundaryRecordsStandardAuthShadowForTLSTempfail|TestAuthBoundaryKeepsDirectOutcomeDiagnosticWhenDefaultSetOverrides' ./server/core
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test ./server/core ./server/policy/... ./server/idp
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache GOMODCACHE=/tmp/nauthilus-gomod-cache make test
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache GOMODCACHE=/tmp/nauthilus-gomod-cache make guardrails
git diff --check
git diff -- '*.go' | rg -n -i '^\+.*phase'
git diff --no-index -- /dev/null server/core/policy_authority.go | rg -n -i '^\+.*phase'
git diff --no-index -- /dev/null server/core/policy_authority_test.go | rg -n -i '^\+.*phase'
```

Result: passed after the missing authority and diagnostic code was implemented.

The first broad affected-package run exposed a review gap in the direct-outcome diagnostic: pre-auth diagnostics compared the empty pre-render state instead of the old direct renderer's default response message. That produced a false `response_message` mismatch for the TLS tempfail parity test. The gap was fixed by deriving old direct default messages for pre-auth and final auth diagnostics.

`make guardrails` passed. It emitted the existing warning about unknown `gomnd` entries in `//nolint` directives and then reported `0 issues`.

The Go diff scan produced no matches for added case-insensitive `phase` strings. Because `server/core/policy_authority.go` and `server/core/policy_authority_test.go` are new untracked Go files, both files were additionally scanned with `git diff --no-index` against `/dev/null`; those scans also produced no matches.

## Active Temporary Adapters

- Private built-in authority adapter in `server/core/policy_authority.go`.
  - Purpose: translate selected `standard_auth` response markers and FSM markers into current `AuthResult` values and current response helpers while the current FSM and response renderer remain in place.
  - Exposure: private Go implementation detail only. It is not a public config field, YAML key, registry entry, report schema addition, or supported plugin API.
  - Removal plan: narrow after the target FSM becomes authoritative in the next slice and remove obsolete current-result translation in the final migration cleanup.

- Request-local direct-outcome diagnostic in `server/core/policy_authority.go` and `server/core/policy_collection.go`.
  - Purpose: keep old-direct-path comparison available after the built-in default policy has become authoritative.
  - Exposure: private Gin context value only.
  - Removal plan: remove with old-vs-new migration diagnostics in the final cleanup after the policy decision path and target FSM are fully authoritative.

- Current response/FSM bridge in existing response and auth-FSM code.
  - Purpose: preserve external behavior while policy markers select the decision and current handlers render the response.
  - Removal plan: replace with direct target-FSM and policy-renderer ownership in the later authority slices.

## Planned Later Removal

- Remove or narrow the current-result translation once the target FSM is authoritative.
- Remove the request-local direct-outcome diagnostic when old direct decisions are no longer needed for migration comparison.
- Remove old direct brute-force fallback handling once all in-scope pre-auth gates are fully owned by policy orchestration and no diagnostic fallback is required.

## Open Risks and Deliberately Deferred Points

- Custom policy sets remain non-authoritative by design in this slice.
- The target FSM is still not the production FSM; current FSM transition code remains in place until the next authority slice.
- Current response writers still render HTTP, gRPC, IdP, and protected-endpoint responses. The selected policy decision feeds the existing response classes and messages.
- Built-in `standard_auth` currently has no runtime advice side effects to execute; selected advice remains report material.
- No new config UX work was required because no `auth.policy` schema fields, `mapstructure` tags, schema-index entries, dump fields, or `ConfigProblem` paths changed.
- Atomic reload was not touched; snapshot activation and failed-build rollback behavior remain owned by the existing runtime store/compiler code.

## Review-Abgleich

Second pass completed against the Phase 8 requirements, the general completion rules from section 18.1, the section 17 registry and mapping tables, section 12 `standard_auth` target mapping, and the Phase 9 boundary.

- Scope: implementation is limited to default-only built-in decision authority, current-result translation, response-message application, policy-owned obligations, old-direct comparison diagnostics, tests, and this implementation note. No custom policy authority, target-FSM authority, compiler authority switch, or public config root was started.
- Tests first: focused policy/evaluation, collection, and auth-boundary tests were added before the corresponding code. The diagnostic test first failed because comparison used the policy-derived response outcome instead of the old direct outcome; the gap was fixed by the request-local direct-outcome diagnostic.
- Default-only guard: `standard_auth` becomes authoritative only when the active snapshot has no configured compiled policy rules. A snapshot with any configured rule remains non-authoritative.
- Brute force: brute force remains first-class policy material. The brute-force checkpoint records a policy check and applies `standard_brute_force_deny` through policy authority before the old direct fallback can run.
- Decisions and response markers: selected built-in pre-auth and final auth decisions drive the current `AuthResult` mapping and response marker class. Central response-marker constants avoid duplicate string ownership.
- Response messages: selected public response-message material is copied into `AuthState.Runtime.StatusMessage` before current response rendering.
- Obligations: policy-owned obligations are executed from the authoritative final decision. The old direct brute-force fallback is bypassed when default policy authority applies.
- Advice: no built-in rule in this slice selects runtime advice with side effects; advice remains selected report data.
- Shadow comparison: old direct outcomes remain available as temporary diagnostics even when the authoritative built-in decision changes the production result.
- Operations: `authenticate` pre-auth and final auth paths are authoritative under the default-only guard. `list_accounts` built-in decisions are evaluated and compared while caller authorization and public rendering remain current-path prerequisites.
- Config UX: no new public config fields or roots were introduced; policy config remains under `auth.policy`; no `policy_engine` root or historical public names were added.
- Observability and reports: the authoritative selection feeds existing policy reports, comparison, metrics, debug-module output, and OTel spans through the existing evaluation/compare path. No new redaction-sensitive payload fields were introduced.
- Atomic reload: no snapshot build or activation code changed, so existing atomic snapshot behavior remains in force.
- Diff hygiene: `git diff --check` passed, and the Go diff scan for added case-insensitive `phase` strings produced no matches, including the two new untracked Go files scanned via `git diff --no-index`.
