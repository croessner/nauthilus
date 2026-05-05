# Nauthilus Policy Decision Layer - Phase 4

## Goal

Phase 4 implements built-in `standard_auth` shadow evaluation. The current auth path remains authoritative. The new code evaluates the built-in default policy from collected policy facts, derives policy output markers, compares the result with the current production result, and reports mismatches.

This phase does not switch decision authority, FSM authority, or custom policy enforcement.

## Implemented Files and Modules

- `server/policy/evaluation/standard.go`
  - Adds the internal `standard_auth` evaluator.
  - Implements ordered first-match evaluation for the mapping rows from the spec.
  - Derives outcome markers, FSM event markers, response markers, selected response messages, and planned obligations.
  - Compares shadow output with the current production output.
  - Records decision, observe comparison, FSM marker, response-rendering, stage metrics, structured logs, and an OpenTelemetry comparison span.

- `server/policy/report/report.go`
  - Extends policy reports with selected policy output, final decision metadata, response-message selection, planned effect requests, and comparison output.
  - Keeps redaction-safe clone behavior for reports.

- `server/policy/collection/collection.go`
  - Exposes snapshot metadata for comparison output without exposing mutable snapshot internals.

- `server/core/policy_collection.go`
  - Adds the AuthState bridge from current terminal outcomes to policy shadow comparison.
  - Uses only an already existing request-local policy context, so terminal handlers do not create artificial default-deny comparisons on paths that collected no policy facts.
  - Adds response-surface classification for comparison and rendering metrics.

- `server/core/response.go`
  - Hooks successful, denied, and temporary-failure terminal auth responses into shadow comparison after the current ResponseWriter remains authoritative.

- `server/core/auth.go`
  - Hooks list-account provider completion into shadow comparison while keeping current account-list output authoritative.

## Tests and Validation

Added focused tests before implementation:

- `server/policy/evaluation/standard_test.go`
  - `standard_auth` first-match selection for brute force, TLS, backend success, and list-account tempfail ordering.
  - Lua public response-message detail selection and redaction marking.
  - Planned brute-force obligations without executing them.
  - Production mismatch reporting and metrics recording.

- `server/core/policy_shadow_test.go`
  - Auth-boundary parity for current TLS tempfail behavior with `standard_auth` shadow output and no production-output mismatch.

Validation run so far:

```bash
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test -count=1 ./server/policy/evaluation ./server/policy/report ./server/policy/collection ./server/core
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test -count=1 ./server/policy/... ./server/core ./server/app/...
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache make test
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache make guardrails
```

Result: passed.

The first guardrails run reported new `funlen` issues in the shadow evaluator and the table-driven test, plus one unused helper after the refactor. The evaluator was split into smaller comparison, recording, and rule-construction helpers; the test data was split into small case builders. The final guardrails run passed.

Additional Go name check:

```bash
git diff -- '*.go' | rg -n -i '^\+.*phase'
rg -n -i 'phase' server/policy/evaluation/standard.go server/policy/evaluation/standard_test.go server/core/policy_shadow_test.go
```

Result: no matches.

## Active Temporary Adapters

- Current-production-to-policy comparison bridge in `server/core/policy_collection.go`.
  - Purpose: compare current terminal outcomes with the built-in `standard_auth` shadow result.
  - Removal plan: remove or narrow after Phase 7 makes `standard_auth` authoritative and after Phase 13 removes old-vs-new migration diagnostics.

- Current response surface classifier in `server/core/policy_collection.go`.
  - Purpose: provide response-surface comparison labels before the target response renderer becomes authoritative.
  - Removal plan: replace with the policy response renderer path when the later enforcement phases own response rendering.

- Current response-message bridge in `server/core/response.go`.
  - Purpose: compare selected `standard_auth` response messages with the message that the existing response path already selected.
  - Removal plan: replace when policy response-message selection becomes part of authoritative enforcement.

There is no separate legacy decision pipeline. Brute force remains represented as collected policy facts and a normal `standard_auth` pre-auth rule.

## Planned Later Removal

The temporary comparison bridge is expected to be removed in the final cleanup after:

- Phase 7 makes `standard_auth` the production decision path when no custom policy is configured.
- Phase 8 makes the target FSM authoritative and removes old event-name adapter dependencies.
- Phase 13 removes old direct-gate and old-vs-new comparison scaffolding that is not part of supported observe mode.

## Open Risks and Deliberately Deferred Points

- Custom policies are not evaluated in observe mode. That belongs to Phase 9.
- `standard_auth` is still shadow-only. It does not execute obligations, mutate counters, enqueue Lua POST-Actions, or render responses.
- Current FSM event names remain production-internal. Target FSM authority and target-vs-current FSM comparison are not part of this phase.
- Public config shape is unchanged in this phase. No new `auth.policy` fields or public roots were added.
- The list-account comparison uses the current successful account-list response as production output. If the current provider path returns partial data after provider errors, shadow comparison can report a mismatch against the target tempfail mapping without changing production output.

## Review-Abgleich

Second pass completed against the Phase 4 requirements, section 11.5, section 17.7, and the general completion rules from section 18.1.

- Tests first: focused evaluator and auth-boundary tests were added before implementation; the initial focused run failed because the evaluator/report fields did not exist yet.
- Current authority: current `ResponseWriter` and account-list output remain authoritative; shadow comparison runs only after current production output is selected.
- Ordered first-match: `standard_auth` evaluates the section 17.7 rows in order, keeps the brute-force checkpoint first, skips non-applicable rules when required checks are missing, and leaves the final default-deny rule last.
- Mapping coverage: pre-auth brute force, TLS, relay-domain, RBL, Lua control, implicit pass, backend tempfail, empty credentials, Lua filter, auth success/failure, lookup identity, list accounts, and default deny rows are represented by the built-in evaluator.
- Brute force: modeled as first-class collected policy facts plus normal planned obligations; no new direct special path was added.
- Response and reporting: response markers, selected public Lua status messages, outcome markers, FSM markers, planned obligations, observe reports, logs, metrics, response-render metrics, and an OTel comparison span are produced.
- Config UX: no new public config root or new `auth.policy` field was added in this phase, so `mapstructure`, schema, `ConfigProblem`, dump, and redaction behavior for config are unchanged.
- Report redaction: new report fields are cloned during redaction, and selected public response-message details are explicitly marked before report redaction.
- Atomic reload: no snapshot build or activation path was changed; existing atomic snapshot behavior remains untouched.
- Deferred by scope: custom policy observe evaluation, authoritative `standard_auth` decisions, target FSM authority, and target response rendering remain later phases.

Gap fixed during review: the first implementation had oversized evaluator/test functions that violated guardrails. Those were refactored into smaller helpers, and `make guardrails` now passes.
