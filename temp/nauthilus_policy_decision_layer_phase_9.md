# Nauthilus Policy Decision Layer - Phase 9

## Goal

Phase 9 enables custom policy observe mode while keeping the built-in `standard_auth` policy set authoritative.

This slice does not start custom policy enforcement, does not introduce a new public config root, and does not change compiler authority, response-rendering authority, or target-FSM authority. Custom policy output is evaluated only for diagnostics, comparison, metrics, traces, logs, and reports.

## Implemented Files and Modules

- `server/policy/runtime/snapshot.go`
  - Adds the compiled `ObserveSafe` check flag to immutable snapshots.

- `server/policy/compiler/checks.go`
  - Carries check-type registry observe-safety defaults and allowed operator assertions into compiled check plans.

- `server/policy/collection/collection.go`
  - Keeps `standard_auth` authoritative when the active snapshot is in `observe` mode, even when configured custom rules exist.
  - Exposes the request snapshot for observe comparison.
  - Records unexecuted non-observe-safe custom-only checks as unavailable with reason `not_observe_safe`.

- `server/policy/evaluation/observe.go`
  - Adds side-effect-free custom policy observe evaluation from compiled snapshot policies and collected request facts.
  - Evaluates `require_checks`, condition expressions, selected response-message sources, target FSM markers, response markers, outcome markers, and terminal states.
  - Compares custom policy output with the authoritative default-policy output.
  - Leaves `policyReport.Final` on the authoritative default decision and stores custom output in `policyReport.Observe.Shadow`.

- `server/policy/observability/metrics.go`
  - Adds `policy_observe_unavailable_checks_total` for unavailable custom-only checks.
  - Extends the policy recorder boundary with unavailable observe measurements.

- `server/policy/report/report.go`
  - Extends observe reports with default and custom terminal states.

- `server/core/policy_collection.go`
  - Runs custom observe comparison after the existing default-policy comparison when the active snapshot is in observe mode.

## Tests and Validation

Focused tests were added before implementation. The first focused run failed because `ObserveSafe`, custom observe comparison, observe terminal-state report fields, and unavailable observe metrics did not exist yet.

Added or updated tests:

- `server/policy/collection/collection_test.go`
  - Verifies observe mode keeps the default set authoritative even when custom rules exist.
  - Verifies non-observe-safe custom-only checks are reported as unavailable and are not also reported as missing.

- `server/policy/evaluation/standard_test.go`
  - Verifies custom observe comparison reports default-vs-custom mismatches while preserving the authoritative default decision.
  - Verifies unavailable custom-only checks are reported and metered.

- `server/core/policy_collection_test.go`
  - Verifies an auth-boundary custom observe deny does not change the default TLS tempfail production response.

Validation:

```bash
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test -run 'TestDecisionContextReportsUnsafeObserveChecksUnavailable|TestDecisionContextObserveModeKeepsDefaultSetAuthoritative|TestCustomObserveComparesConfiguredPolicyWithDefault|TestCustomObserveReportsUnsafeCustomOnlyCheckUnavailable|TestAuthBoundaryCustomObserveDoesNotChangeDefaultDecision' ./server/policy/collection ./server/policy/evaluation ./server/core
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test ./server/policy/... ./server/core ./server/config ./server/app/policyfx
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache make test
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache make guardrails
git diff --check
git diff -- '*.go' | rg -n -i '^\+.*phase'
git diff --no-index -- /dev/null server/policy/evaluation/observe.go | rg -n -i '^\+.*phase'
```

Result: passed.

Notes:

- `make guardrails` reported the existing golangci-lint runner warning about unknown `gomnd` nolint directives, but finished with `0 issues` and exit code 0.
- The two `/phase/i` diff scans returned no matches. The `rg` commands therefore exited with code 1, which is the expected no-match result.

## Active Temporary Adapters

- The request-local direct-outcome diagnostic remains active.
  - Purpose: keep old-direct-path diagnostics available while `standard_auth` is authoritative.
  - Removal plan: remove with old-vs-new migration diagnostics in the final cleanup.

- Current mechanism collection adapters remain active.
  - Purpose: reuse current brute-force, Lua control, TLS, relay-domain, RBL, backend, Lua filter, and account-provider execution as fact producers.
  - Removal plan: replace with native policy check executors as custom enforcement and final cleanup remove the remaining bridge code.

- Custom observe mode does not execute custom obligations, Lua POST-Action enqueueing, counters, learning updates, or mutable side effects.
  - Purpose: keep observe mode diagnostic-only.
  - Removal plan: enforcement starts only in later slices, where side effects must execute exclusively from authoritative policy decisions.

## Planned Later Removal

- Remove old-direct comparison scaffolding that is not part of supported custom observe mode.
- Replace current response-writer bridging with direct policy response rendering in later authority work.
- Replace current mechanism collection adapters with native policy check executors before final cleanup.

## Open Risks and Deliberately Deferred Points

- Custom policies remain non-authoritative by design.
- Custom-only checks that are not already produced by the current runtime path are not executed by this slice. Non-observe-safe custom-only checks are reported as unavailable; observe-safe custom-only checks without a current fact source remain missing until native check executors own scheduling in later slices.
- Current response writers still render HTTP, gRPC, IdP, and protected-endpoint responses.
- No config UX work was needed because no new `auth.policy` fields, schema-index entries, dump fields, redaction rules, or `ConfigProblem` paths changed.
- Atomic reload was not changed; snapshots remain built completely before activation.

## Review-Abgleich

Second pass completed against the Phase 9 requirements, section 7.3 observe-mode rules, section 15 observability and report rules, section 17 implementation tables, section 17.7 `standard_auth` mapping, and the completion rules from section 18.1.

- Scope: implementation is limited to custom observe mode. No custom enforce path, compiler authority change, FSM authority change, public config root, or historical public names were added.
- Tests first: focused collection, evaluation, and auth-boundary tests were added before the corresponding code. The initial focused run failed on the missing observe-mode implementation.
- Default authority: `standard_auth` remains the production decision source in observe mode even with configured custom policy rules.
- Custom evaluation: configured policies are evaluated from the immutable snapshot and request-local collected facts. The evaluator does not execute obligations, POST-Actions, counters, learning updates, or mutable side effects.
- Observe safety: non-observe-safe custom-only checks are reported as unavailable with `not_observe_safe` and are metered through `policy_observe_unavailable_checks_total`.
- Mismatch comparison: observe comparison records effect, selected custom policy, outcome marker, FSM marker, response marker, response-message source and rendered sanitized message, and terminal state.
- Observability: observe comparison metrics and OTel span attributes include mismatch type; unavailable facts are metered and attached to the custom observe span.
- Observability gap fixed during review: custom observe normal mismatch logs and policy debug logs now include operation, stage, snapshot generation, selected policy names, effects, response markers, and FSM markers.
- Reports and redaction: custom output is stored in `Observe.Shadow`, default output remains `Observe.Production`, terminal states are explicit, and attribute details retain existing redaction behavior.
- `standard_auth` mapping: default decisions continue to use the built-in mapping. Brute force remains first-class policy material and no separate brute-force side path was introduced.
- Config UX: no public config additions were needed; existing `auth.policy.mode`, `observe_safe`, schema, dump, and validation behavior remain under `auth.policy`.
- Atomic reload: no snapshot activation semantics changed; the observe evaluator reads the active immutable snapshot captured for the request.
