# Nauthilus Policy Decision Layer - Phase 11

## Goal

Phase 11 enables configured custom policy enforcement for the `pre_auth` stage only.

The implemented scope is limited to:

1. brute force;
2. Lua controls;
3. TLS enforcement;
4. relay domains;
5. RBL.

This slice does not start custom enforcement for backend results, Lua filters, lookup-identity, account listing, final `auth_decision` rules, config compiler authority changes, or any new FSM vocabulary. `standard_auth` remains the built-in default policy set and remains the final auth-decision authority until the later backend/filter enforcement slice.

## Implemented Files and Modules

- `server/policy/evaluation/enforce.go`
  - Adds configured `pre_auth` evaluation for `mode: enforce`.
  - Evaluates configured snapshot policies from collected request facts.
  - Records stage, decision, FSM-marker, and response-render instrumentation for selected custom decisions.
  - Leaves unmatched configured `pre_auth` rules as neutral continuation and does not synthesize final default-deny in `pre_auth`.

- `server/policy/collection/collection.go`
  - Adds request-local authority detection for configured `pre_auth` rules in enforce mode.
  - Keeps observe mode diagnostic-only.

- `server/core/policy_authority.go`
  - Routes selected configured `pre_auth` decisions into current auth results or direct enforcement.
  - Applies configured response messages before the existing response surfaces render.
  - Emits policy debug-module logs for selected configured decisions.

- `server/core/features.go`
  - Allows configured `pre_auth` policy rules to override current Lua-control, TLS, relay-domain, RBL, and technical-error outcomes.
  - Continues later current pre-auth controls when configured policy authority is active and no terminal configured decision was selected.

- `server/core/protect_impl.go`, `server/core/auth.go`, `server/idp/nauthilus_idp.go`
  - Route brute-force pre-auth blocks through configured policy authority first.
  - Continue later pre-auth controls when configured policy authority is active and the configured policy does not select a terminal decision.

- `server/core/policy_collection.go`
  - Preserves selected configured `pre_auth` finals during response side-effect comparison so the default-policy diagnostic path does not overwrite the authoritative configured result.

## Tests and Validation

Focused tests were added before implementation. The first focused run failed because configured `pre_auth` enforce evaluation did not exist and auth-boundary handling still used the built-in/default or direct result.

Added or updated tests:

- `server/policy/compiler/snapshot_compiler_test.go`
  - Verifies `permit` remains invalid in `pre_auth`.

- `server/policy/evaluation/standard_test.go`
  - Verifies configured `pre_auth` enforce selects a configured terminal decision.
  - Verifies configured `pre_auth` enforce does not synthesize final default-deny when no configured `pre_auth` rule matches.

- `server/policy/collection/collection_test.go`
  - Verifies configured `pre_auth` authority is active only in enforce mode, not observe mode.

- `server/core/policy_collection_test.go`
  - Verifies a configured `pre_auth` deny overrides the current TLS tempfail result at the auth boundary.
  - Verifies an unmatched configured `pre_auth` rule lets a current TLS tempfail continue as neutral.
  - Verifies a configured brute-force `skip_remaining_stage_checks` control prevents later pre-auth checks from running and records the selected control decision only once.

Initial reproducer run:

```bash
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test -run 'TestCompilerRejectsPreAuthPermitDecision|TestConfiguredPreAuthEnforceSelectsConfiguredDecision|TestConfiguredPreAuthEnforceDoesNotSelectFinalDefaultDeny|TestAuthBoundaryConfiguredPreAuthEnforceOverridesCurrentTLSResult|TestAuthBoundaryConfiguredPreAuthEnforceLetsUnmatchedTLSContinue' ./server/policy/compiler ./server/policy/evaluation ./server/core
```

Result: failed before implementation on the missing configured enforce evaluator and auth-boundary behavior.

Focused validation after implementation:

```bash
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test -run 'TestCompilerRejectsPreAuthPermitDecision|TestConfiguredPreAuthEnforceSelectsConfiguredDecision|TestConfiguredPreAuthEnforceDoesNotSelectFinalDefaultDeny|TestAuthBoundaryConfiguredPreAuthEnforceOverridesCurrentTLSResult|TestAuthBoundaryConfiguredPreAuthEnforceLetsUnmatchedTLSContinue|TestDecisionContextConfiguredPreAuthAuthorityUsesEnforceMode' ./server/policy/compiler ./server/policy/evaluation ./server/policy/collection ./server/core
```

Result: passed.

Additional validation after the review fix:

```bash
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test -run TestConfiguredPreAuthControlAtBruteForceSkipsLaterChecks ./server/core
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test ./server/policy/... ./server/core ./server/idp ./server/config ./server/app/policyfx
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache make test
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache make guardrails
git diff --check
git diff -- '*.go' | rg -n -i '^\+.*phase'
rg -n -i 'phase' server/policy/evaluation/enforce.go
```

Result:

- focused and package validations passed;
- `make test` passed;
- `make guardrails` passed with the existing `gomnd` nolint warning and `0 issues`;
- `git diff --check` passed;
- the Go diff check for new technical `phase` names returned no matches;
- the new evaluator file scan returned no matches for technical `phase` names.

## Active Temporary Adapters

- Current mechanism collection adapters remain active.
  - Purpose: reuse current brute-force, Lua control, TLS, relay-domain, and RBL mechanism execution as fact producers.
  - Removal plan: replace with native policy check executors before final cleanup.

- Current feature side effects still run through current mechanism code for Lua controls, TLS, relay-domain, and RBL triggers.
  - Purpose: preserve current behavior while configured `pre_auth` decisions become authoritative.
  - Removal plan: move remaining side effects behind registered policy obligations when native check executors and response enforcement are completed.

- Brute force still starts from the current early check call sites.
  - Purpose: preserve current Redis bucket and cache behavior while making the configured policy decision authoritative when it selects a terminal result.
  - Removal plan: remove old direct-gate scaffolding once native pre-auth orchestration owns check scheduling end to end.

- Current response writers still render HTTP, gRPC, IdP, and protected-endpoint responses.
  - Purpose: preserve the existing response surfaces while configured `response_marker` and `response_message` are bridged through current auth results and status messages.
  - Removal plan: replace with direct policy response rendering in the later response-authority work.

- Generic configured `pre_auth` deny currently maps to an existing deny-capable auth result carrier.
  - Purpose: keep the current FSM and response writers on a denial path without exposing old names in policy config.
  - Removal plan: remove this current-result translation when policy response rendering is fully authoritative.

## Planned Later Removal

- Remove old direct-result comparison scaffolding that is not part of supported observe mode.
- Replace current response-result translation with direct policy response rendering.
- Replace mechanism-local feature side effects with registered policy obligations.
- Remove remaining old direct-gate call-site assumptions after native pre-auth check scheduling is complete.

## Open Risks and Deliberately Deferred Points

- Custom backend, Lua filter, status-message, lookup-identity, and list-account enforcement remain deliberately out of scope.
- Existing current mechanism code may still perform current feature side effects before a configured policy decision is selected. This is documented as a temporary adapter and must be removed by later native check-executor and obligation work.
- The configured `pre_auth` evaluator uses collected facts from current adapters. Custom-only check execution beyond current fact producers remains deferred.
- Atomic reload semantics were not changed; the evaluator reads the immutable snapshot captured for the request.
- No new public config paths were added; existing `auth.policy` schema, `mapstructure`, dump, redaction, and `ConfigProblem` behavior remain in force.

## Review-Abgleich

The second review re-read the Phase 11 requirements, the general completion rules, and the section 17 registry and mapping tables.

Result:

- Phase scope stayed limited to custom `pre_auth` enforcement for brute force, Lua controls, TLS, relay domains, and RBL. Backend, Lua filter, lookup-identity, list-account, response-authority, compiler-surface, and FSM-vocabulary changes were not started.
- The first added tests covered the missing configured evaluator and auth-boundary behavior before implementation. A second review test then exposed and fixed one gap: brute-force `skip_remaining_stage_checks` controls now skip later pre-auth checks instead of merely continuing to the current feature path. The same test also guards against duplicate report entries from repeated request-local evaluation calls.
- `permit` remains rejected for `pre_auth` by the compiler test.
- No configured `pre_auth` fallback default-deny was introduced. Unmatched configured `pre_auth` rules remain neutral and final auth default-deny semantics stay unchanged.
- Brute force is handled as first-class policy input through the collected `builtin.brute_force` facts and no separate legacy decision pipeline was added.
- Config UX stayed under the existing `auth.policy` model. No new public config root, `mapstructure`, schema, dump, redaction, or `ConfigProblem` changes were required for this slice.
- Observability for selected configured `pre_auth` decisions records policy metrics, a `policy.evaluate` span, structured policy decision logs, debug-module output, report decisions, FSM markers, and response-render measurements when the surface is known.
- Atomic reload behavior stayed unchanged. Request handling evaluates the immutable snapshot clone captured by the request-local decision context.
- Section 17 mapping stayed aligned: the implementation uses existing registered pre-auth check types, attributes, FSM markers, response markers, and the `standard_auth` pre-auth semantics as the default behavior model.
