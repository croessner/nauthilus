# Nauthilus Policy Decision Layer - Phase 7

## Goal

Phase 7 moves decision-dependent request-time Lua action dispatch behind
registered policy obligations in the already-renumbered target-model codebase.

The retrofit closes the gap left after the later authority, observe, enforce,
and cleanup work had already landed: synchronous Lua actions are no longer run
directly by policy-authoritative environment or brute-force mechanisms. They are
selected and executed through `auth.obligation.lua_action.dispatch`.

## Implemented Files and Modules

- `server/policy/types.go`
  - Registered `auth.obligation.lua_action.dispatch`.
  - Added the bounded synchronous action names `brute_force`, `lua`,
    `tls_encryption`, `relay_domains`, and `rbl`.
  - Added a shared action-name validator used by compiler and runtime code.

- `server/policy/compiler/definitions.go`
  - Added the synchronous Lua action obligation to the built-in obligation
    registry.

- `server/policy/compiler/policies.go`
  - Added typed argument validation for
    `auth.obligation.lua_action.dispatch`.
  - Validates required `action`, optional string `environment`, optional boolean
    `wait`, and rejects unsupported argument keys.

- `server/policy/evaluation/standard.go`
  - Added planned synchronous Lua action obligations to `standard_auth` rows
    for `brute_force`, `tls_encryption`, `relay_domains`, `rbl`, and named Lua
    control triggers.
  - Keeps brute-force update and Lua POST-Action enqueueing as registered
    obligations.

- `server/core/policy_obligations.go`
  - Added the central runtime obligation executor used by
    `applyPolicyObligations`.
  - Executes only obligations attached to the selected `FinalDecision`.
  - Skips mutable effects when the active request policy context is in observe
    mode.
  - Records obligation metrics and policy debug-module entries.
  - Dispatches synchronous Lua actions through the existing action dispatcher,
    preserving request context, cancellation checks, and action latency metrics.
  - Routes conditional environment-learning updates through
    `auth.obligation.brute_force.update`, independently from Lua dispatch.
  - Preserves the historical brute-force Lua action `CommonRequest` shape by
    exposing the matched rule name during dispatch while keeping the internal
    repeating/guessed security marker after dispatch.

- `server/core/policy_authority.go`
  - Routes pre-auth default and configured decisions through the central
    obligation executor before translating the selected policy result back to
    current `AuthResult` carriers.
  - Keeps final auth Lua POST-Action enqueueing on the same central executor.

- `server/core/environment.go`
  - Keeps current mechanism execution as a fact producer.
  - Removes mechanism-owned synchronous Lua action dispatch.
  - Keeps environment-learning updates behind the selected brute-force update
    obligation.

- `server/core/bruteforce.go`
  - Keeps brute-force trigger detection and policy fact production.
  - Removes the direct brute-force Lua action dispatcher.
  - Runs the brute-force synchronous Lua action only through the selected
    `auth.obligation.lua_action.dispatch` obligation.

- Tests:
  - `server/core/policy_authority_test.go`
  - `server/policy/compiler/snapshot_compiler_test.go`
  - `server/policy/evaluation/standard_test.go`

## Tests and Validation

Focused reproducer tests were added before implementation.

Initial focused run failed before implementation:

```bash
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test -run 'TestAuthBoundaryConfiguredPreAuthDecision(WithoutLuaActionObligationSkipsSynchronousAction|RunsSelectedLuaActionObligationOnce)|TestPolicyObligationExecutorSkipsMutableEffectsInObserveMode|TestCompiler(AcceptsLuaActionDispatchObligationArgs|RejectsLuaActionDispatchInvalidArgs)' ./server/core ./server/policy/compiler
```

The failure showed:

- `auth.obligation.lua_action.dispatch` was missing from the compiler
  registry;
- no central runtime obligation executor existed yet.

Validation after implementation:

```bash
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test -run 'TestAuthBoundaryConfiguredPreAuthDecision(WithoutLuaActionObligationSkipsSynchronousAction|RunsSelectedLuaActionObligationOnce)|TestPolicyObligationExecutorSkipsMutableEffectsInObserveMode|TestCompiler(AcceptsLuaActionDispatchObligationArgs|RejectsLuaActionDispatchInvalidArgs)' ./server/core ./server/policy/compiler
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test ./server/core ./server/policy/... ./server/lualib/environment ./server/lualib/subject ./server/lualib/pipeline ./server/lualib/policyschedule
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache make test
```

Result: passed.

## Active Temporary Adapters

- Current action dispatcher bridge in `server/core/auth/action_service.go`.
  - Purpose: reuses existing Lua action worker, request context object,
    timeout/cancel behavior, and script configuration.
  - Planned removal: replace only when a native policy enforcement context owns
    Lua action dispatch directly.

- Existing response-writer, gRPC metadata, mechanism fact, Lua execution, and
  AuthResult translation bridges remain from the later completed work.
  - Purpose: preserve current transport behavior while policy owns decisions.
  - Planned removal: revisit only with native policy response profiles and
    native check executors.

## Planned Later Removal

- No synchronous Lua action mechanism fallback remains after this retrofit.
- Replace the action dispatcher bridge only when Lua action execution has a
  native policy enforcement context.
- Keep `wait` typed and validated for the obligation contract; no async action
  mode was introduced in this retrofit.

## Open Risks and Deliberately Not Implemented

- No new public configuration root or historical public name was introduced.
- No compiler authority switch, FSM authority change, response-profile renderer,
  or native check-executor architecture was started.
- Existing Lua action script configuration and the current action worker remain
  unchanged.
- Brute-force remains first-class policy material. No brute-force bypass or
  separate old-behavior pipeline was added.
- Observe mode now skips the central mutable obligation executor. Existing
  observe comparison remains report-only and still records planned custom
  obligations without executing them.

## Review-Abgleich

Second pass re-read the Phase 7 requirements, the completion rules from section
18.1, the obligation/advice registry in section 17.5, the `standard_auth`
mapping checklist in section 17.7, and the observe/enforce side-effect rules.

Result:

- Scope stayed limited to policy-owned runtime obligations for synchronous Lua
  action dispatch and the already-existing brute-force update / Lua POST-Action
  executor boundary. No later authority work was restarted.
- `auth.obligation.lua_action.dispatch` is registered and validates bounded
  typed arguments.
- Only `brute_force`, `lua`, `tls_encryption`, `relay_domains`, and `rbl` are
  accepted action names.
- Optional `environment` is preserved for policy-selected action context.
- The brute-force update obligation accepts bounded `feature` and `environment`
  metadata for conditional environment learning.
- Environment-triggered and brute-force-triggered synchronous Lua actions no longer
  dispatch from mechanism paths; the direct brute-force action helper was
  removed.
- `standard_auth` now plans Lua action obligations for the required
  `brute_force`, `lua`, `tls_encryption`, `relay_domains`, and `rbl` outcomes.
- Configured pre-auth decisions without `auth.obligation.lua_action.dispatch`
  do not run synchronous Lua actions even when a triggering fact exists.
- Configured pre-auth decisions with `auth.obligation.lua_action.dispatch`
  dispatch exactly once through the selected obligation.
- Observe mode skips mutable central obligation execution, including synchronous
  Lua actions, Lua POST-Action enqueueing, brute-force updates, and learning
  updates handled by the brute-force update obligation path.
- The review pass tightened the boundary so the executor also skips mutable
  effects when no request-local policy context exists. This is covered by
  `TestPolicyObligationExecutorSkipsMutableEffectsWithoutPolicyContext`.
- The CommonRequest review found and fixed a brute-force parity gap: the generic
  dispatcher would have exposed `rule,guessed` as `brute_force_bucket`, while the
  old dispatcher exposed the matched rule name. The executor now restores the
  old Lua request shape for dispatch and then restores the internal security
  name. `TestBruteForceLuaActionAccountRefreshPreservesCommonRequestAccountField`
  covers the old account-field refresh behavior.
- Reports keep planned obligations on selected decisions; metrics and policy
  debug logs record executed runtime obligations.
- No new config UX surface was required; everything remains under `auth.policy`.
- The Go diff scan for newly added case-insensitive `phase` strings is part of
  final validation and must remain empty.

## Final Validation

Passed:

```bash
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test -run 'TestAuthBoundaryConfiguredPreAuthDecision(WithoutLuaActionObligationSkipsSynchronousAction|RunsSelectedLuaActionObligationOnce)|TestPolicyObligationExecutorSkipsMutableEffectsInObserveMode|TestCompiler(AcceptsLuaActionDispatchObligationArgs|RejectsLuaActionDispatchInvalidArgs)' ./server/core ./server/policy/compiler
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test -run 'TestPolicyObligationExecutorSkipsMutableEffectsWithoutPolicyContext' ./server/core
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test -run 'TestPolicyBruteForceLuaActionPreservesCommonRequestShape' ./server/core
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test -run 'TestBruteForceLuaActionAccountRefreshPreservesCommonRequestAccountField' ./server/core
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test ./server/core ./server/policy/... ./server/lualib/environment ./server/lualib/subject ./server/lualib/pipeline ./server/lualib/policyschedule
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache make test
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache make guardrails
git diff --check
git diff -- '*.go' | rg -n -i '^\+.*phase'
git diff --no-index -- /dev/null server/core/policy_obligations.go | rg -n -i '^\+.*phase'
```

The two Go diff scans returned no matches.
