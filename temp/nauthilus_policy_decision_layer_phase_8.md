# Nauthilus Policy Decision Layer - Phase 8

## Goal

Phase 8 makes the target auth FSM authoritative for production auth orchestration and removes the temporary target-to-current FSM adapter introduced earlier.

This slice does not start custom policy observe or enforce mode, does not add a new public config root, and does not change the policy compiler surface. The built-in `standard_auth` default policy remains the only authoritative policy set when no configured policy rules exist.

## Implemented Files and Modules

- `server/policy/fsm/fsm.go`
  - Removes the private target-to-current event adapter.
  - Exposes the target state constants and transition helper so production code uses the same target transition table as policy diagnostics.
  - Keeps comparison helpers from synthesizing a production event path from old event names.

- `server/core/auth_fsm.go`
  - Replaces the old core FSM state and event vocabulary with target states and target marker IDs.
  - Delegates transition validation to `server/policy/fsm`.

- `server/core/rest.go`
  - Starts auth pipeline FSM tracking at `init` and applies `auth.fsm.event.parse_ok`.
  - Maps feature outcomes to target `pre_auth_*` markers.
  - Maps backend/password outcomes to target final auth markers.
  - Records target FSM transition metrics on the production path.

- `server/core/policy_authority.go`
  - Applies target FSM marker sequences for direct authoritative policy decisions before rendering the current response.

- `server/core/auth.go`
  - Applies target FSM marker sequences for list-account policy decisions before the existing response comparison.

- `server/policy/evaluation/standard.go`
  - Exposes target marker sequence construction for production FSM application.
  - Stops recording adapter-comparison FSM metrics from the comparison path.

- `server/policy/evaluation/fsm_compare_test.go`
  - Updates production event-path fixtures to target marker IDs.

## Tests and Validation

Focused tests were added before implementation. The first focused run failed because core still exposed old FSM names and the policy FSM comparison still synthesized a production path through the adapter.

Added or updated tests:

- `server/core/auth_fsm_test.go`
  - Verifies target transitions through `pre_auth_checked`, `auth_checked`, and `account_provider_checked`.
  - Verifies feature and password/backend results map to target marker IDs.
  - Verifies core event values are target marker IDs.

- `server/policy/fsm/fsm_test.go`
  - Replaces adapter mapping coverage with a check that no production event path is synthesized without an actual production path.
  - Verifies comparison preserves an already supplied target production path.

- `server/core/policy_authority_test.go`
  - Verifies a direct authoritative pre-auth decision applies a target FSM event path and target terminal state.

Validation run:

```bash
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test -run 'TestNextAuthFSMState|TestMapAuthFeatureResultToFSMEvent|TestMapAuthPasswordResultToFSMEvent|TestAuthFSMEventValuesAreTargetMarkers|TestCompareDoesNotSynthesizeProductionPath|TestCompareReportsTerminalMismatchWithoutChangingProductionPath' ./server/core ./server/policy/fsm
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test -run 'TestAuthBoundaryDefaultSetAppliesTargetFSMForDirectPreAuthDecision|TestAuthBoundaryDefaultSetSelects|TestAuthBoundaryKeepsDirectOutcomeDiagnostic' ./server/core
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test ./server/core ./server/policy/fsm ./server/policy/evaluation ./server/policy/report ./server/policy/collection ./server/policy/compiler
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test ./server/policy/... ./server/core ./server/idp
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache GOMODCACHE=/tmp/nauthilus-gomod-cache make test
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache GOMODCACHE=/tmp/nauthilus-gomod-cache make guardrails
git diff --check
git diff -- '*.go' | rg -n -i '^\+.*phase'
```

Result: passed.

`make guardrails` first caught one unchecked log return and missing revive comments for exported FSM helpers. Those findings were fixed directly, and the final `make guardrails` run passed with `0 issues`. The command still prints the pre-existing warning about unknown `gomnd` entries in `//nolint` directives.

The only remaining historical FSM string found by a repository scan is `features_ok` in `server/policy/compiler/snapshot_compiler_test.go`, where it is intentionally used to prove old current-event names are rejected by policy marker validation.

## Active Temporary Adapters

- The target-to-current FSM adapter has been removed.

- The private current-result translation in `server/core/policy_authority.go` remains active.
  - Purpose: keep current response rendering and `AuthResult` compatibility while the policy-selected decision is authoritative.
  - Removal plan: remove obsolete current-result translation during final cleanup once response rendering and remaining direct fallback scaffolding are fully policy-owned.

- The request-local direct-outcome diagnostic remains active.
  - Purpose: keep old-direct-path comparison available after built-in default policy authority.
  - Removal plan: remove with old-vs-new migration diagnostics in the final cleanup.

## Planned Later Removal

- Final cleanup removes obsolete old-direct comparison scaffolding that is not part of supported observe mode.
- Later response-authority work can replace current response writer bridging with direct policy response rendering, but that is outside this slice.

## Open Risks and Deliberately Deferred Points

- Custom policies remain non-authoritative by design.
- Current response writers still render HTTP, gRPC, IdP, and protected-endpoint responses.
- The policy report still has current-vs-target comparison fields for bounded diagnostics, but production event paths now contain target markers and no adapter-generated old event names.
- No config UX work was needed because no `auth.policy` schema fields, `mapstructure` tags, schema-index entries, dump fields, or `ConfigProblem` paths changed.
- Atomic reload was not touched; snapshot activation and failed-build rollback behavior remain owned by the existing runtime store/compiler code.

## Review-Abgleich

Second pass completed against the Phase 8 requirements, section 9.7 target FSM semantics, section 17.3 FSM marker registry, section 17.7 `standard_auth` mapping checklist, and the completion rules from section 18.1.

- Scope: implementation is limited to target-FSM authority, adapter removal, production FSM metrics, tests, and this implementation note. No compiler-authority switch, custom policy observe/enforce mode, new config root, or response-rendering authority switch was started.
- Tests first: focused core FSM and policy FSM tests were written before code changes. The first focused run failed on missing target core event names and adapter-synthesized production paths.
- Target FSM authority: production auth orchestration now applies target marker IDs directly through the target transition table shared from `server/policy/fsm`.
- Adapter removal: the private target-to-current FSM adapter and its old event mapping were removed. Policy FSM comparison no longer synthesizes production paths from old names.
- Old event names: core auth decision mapping no longer emits `features_*` or `password_*` names. A Go scan finds only the compiler rejection test that intentionally uses `features_ok` as invalid input.
- Metrics and observability: production FSM application records `policy_fsm_transitions_total` through the policy recorder. Adapter-comparison FSM metric recording was removed from the comparison path.
- Reports and logs: existing bounded FSM report fields remain, but production event paths now carry target marker IDs. No old event name is generated for report, log, trace, metric, registry, or config surfaces.
- `standard_auth` mapping: pre-auth outcomes map to `pre_auth_*` markers, auth outcomes map to `auth_*` markers, and list-account decisions use `account_provider_evaluated` before final markers.
- Brute force: brute force remains first-class `standard_auth` pre-auth material; no separate brute-force FSM or decision side path was introduced.
- Config UX: no config structs, schema index, dump behavior, redaction, or `ConfigProblem` paths changed.
- Atomic reload: no snapshot activation code changed; existing immutable snapshot behavior remains unchanged.
- Diff hygiene: `git diff --check` passed and the Go diff scan for added case-insensitive `phase` strings produced no matches.
