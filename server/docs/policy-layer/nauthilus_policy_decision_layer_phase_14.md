# Nauthilus Policy Decision Layer - Phase 14

## Goal

Phase 14 removes temporary migration scaffolding that was only useful while the policy decision layer was being compared
against the old direct runtime result. The supported observe mode remains default-vs-configured policy comparison under
`auth.policy`; enforce mode no longer emits old-vs-new migration comparison reports.

## Implemented Files and Modules

- `server/core/policy_collection.go`
  - Replaced the old production-comparison call with configured observe-only evaluation.
  - Removed the request-local direct-outcome merge path and the fallback selected-decision logic.

- `server/core/response.go`
  - Removed response-time old-vs-new comparison calls from `AuthOK`, `AuthFail`, and `AuthTempFail`.
  - Removed the current-terminal/current-event-path helper code that only fed temporary diagnostics.

- `server/core/auth.go`
  - Removed account-list success old-vs-new comparison and direct diagnostic storage.
  - Keeps list-account configured policy enforcement on the existing operation path.

- `server/core/policy_authority.go`
  - Removed request-local direct outcome storage and current-result conversion helpers used only by migration diagnostics.
  - Keeps policy-selected decisions, FSM markers, obligations, and response messages as the authority inputs.

- `server/policy/evaluation`
  - Removed `CompareWithProduction`, `ProductionOutcome`, production comparison metrics/logging, and FSM comparison reports.
  - Kept `EvaluateStandardAuth` and configured observe comparison as the supported policy evaluation paths.
  - Moved response-surface metadata to `CompareInput.Surface` for configured enforce and observe evaluation.

- `server/policy/fsm`
  - Removed side-by-side current-vs-target comparison types and helpers.
  - Kept the target FSM transition evaluator and terminal-state helpers.

- `server/policy/report/report.go`
  - Removed the temporary `fsm` report section that exposed current-vs-target comparison data.

- `server/docs/auth_backchannel_fsm_adr.md`
  - Rewrote the ADR around the target FSM vocabulary and supported observe/enforce behavior.
  - Removed old event names from the stable documented model.

- Config examples
  - Checked for stale policy-target names and historical FSM event names; no example file required a content change.

- `scripts/test_convert_config_v1_to_v2.py`
  - Added converter assertions that generated target config does not expose `policy_engine`, legacy RBL roots, or legacy Lua environment-source paths.

- Tests
  - Replaced old migration-shadow tests with cleanup parity coverage.
  - Removed tests for deleted production comparison and FSM comparison APIs.

## Tests and Validation

- Reproducer first:
  - `GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test -run TestAuthBoundaryDefaultSetDoesNotCreateMigrationObserveReportForTLSTempfail ./server/core`
  - First run failed before implementation because default enforce mode still produced an observe report.

- Focused/package validation:
  - `GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test -run TestAuthBoundaryDefaultSetDoesNotCreateMigrationObserveReportForTLSTempfail ./server/core`
  - `GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test ./server/policy/... ./server/core`
  - `python3 scripts/test_convert_config_v1_to_v2.py`

- Guardrails:
  - `GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache make guardrails`
  - First guardrails run stopped on a `goconst` issue in the new cleanup test.
  - The repeated guardrails run passed.

- Naming guard:
  - `git diff -- '*.go' | rg -n -i '^\+.*phase'`
  - Result: no matches.

## Active Temporary Adapters

- No temporary old-vs-new decision comparison adapter remains active.
- No temporary current-vs-target FSM comparison report remains active.
- The existing response-writer and gRPC metadata bridges remain runtime compatibility boundaries for current transports.
  They do not expose historical policy names as the target config, registry, metric, trace, log, or report contract.

## Planned Adapter Removal

- The removed old-vs-new comparison and FSM comparison adapters have no later removal work left.
- The current response-writer and gRPC metadata bridges should be revisited only when response profiles become native
  transport renderers. That is outside this cleanup because it would change response authority and transport contracts.

## Open Risks and Deliberately Not Implemented

- No new public config root was added; policy config remains under `auth.policy`.
- No compiler, registry, snapshot, or atomic reload authority change was started.
- No native response-profile renderer was introduced. Existing response writers keep preserving external transport behavior.
- Brute force remains first-class policy material through built-in check facts and obligations; this cleanup did not add a
  brute-force bypass path.

## Review-Abgleich

The second pass re-read Phase 14, the general completion rules, Section 17 registry and mapping tables, and the
`standard_auth` mapping checklist.

Result:

- Phase 14 requirement 1: old direct-gate comparison call sites were removed from response rendering and account-list
  finalization. Policy orchestration remains the authority source for selected final decisions.
- Phase 14 requirement 2: `CompareWithProduction`, `ProductionOutcome`, direct diagnostic storage, and related tests were
  removed. Supported observe mode is now only configured policy set versus `standard_auth`.
- Phase 14 requirement 3: current-vs-target FSM comparison types, report cloning, tests, and OTel attributes were removed.
  The target FSM evaluator remains intact.
- Phase 14 requirement 4: target config, registry, metrics, traces, logs, and report code no longer expose the removed
  comparison report or historical event names as a stable contract. The compiler still rejects historical event names.
- Phase 14 requirement 5: the backchannel FSM ADR now documents only the target vocabulary, config examples were checked
  for stale target names, and converter tests assert that generated target config stays under `auth.policy` without legacy
  target roots.
- Phase 14 requirement 6: focused tests, policy/core package tests, converter tests, and guardrails passed after the
  cleanup-test constant fix.
- Completion rules: tests were added before behavior-changing code; no new config or atomic reload path was added; report
  redaction was simplified by removing the temporary report section; observability was reduced only for unsupported
  migration comparison paths, while configured observe/enforce metrics and spans remain covered by shared evaluators.
