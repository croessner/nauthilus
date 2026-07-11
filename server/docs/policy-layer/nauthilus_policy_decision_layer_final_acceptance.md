# Nauthilus Policy Decision Layer Final Acceptance

## Goal

This acceptance pass closes the implemented Policy Decision Layer rollout against
`server/docs/policy-layer/nauthilus_policy_decision_layer_spec.md`, the reconciled per-step
documents `server/docs/policy-layer/nauthilus_policy_decision_layer_phase_0.md` through
`server/docs/policy-layer/nauthilus_policy_decision_layer_phase_14.md`, and the current code paths.

The pass did not introduce a new pre-auth stage, a new public authority model, or
a new public config root. Fixes were limited to consistency gaps inside the
implemented target model.

## Current Reconciliation Note

On 2026-05-06 the phase documents were reconciled against the current
specification, which contains an inserted Phase 7 for policy-owned runtime
obligations.

The old Phase 7 through Phase 13 documents have been renumbered to Phase 8
through Phase 14. The inserted Phase 7 has now been implemented as a retrofit:
synchronous Lua actions are selected through
`auth.obligation.lua_action.dispatch` and no longer run directly from
policy-authoritative environment or brute-force mechanisms.

Current acceptance is no longer blocked by Phase 7. The historical validation
results below remain useful evidence for the already-completed renumbered
phases and are extended by the Phase 7 retrofit validation.

## Checked Areas

- Completion rules from spec section 18.1.
- Requirements from all 14 implementation steps plus the initial baseline step.
- Registry and mapping tables from spec section 17.
- Built-in `standard_auth` mapping for pre-auth, backend, subject-source, auth-decision,
  account-provider, response, FSM markers, obligations, and advice.
- Config UX: `mapstructure` decoding, schema index, `ConfigProblem` formatting,
  config dump defaults and redaction, and the v1-to-v2 converter.
- Observability: policy debug module, normal logs, decision reports, Prometheus
  recorders, OTel attributes, and report redaction.
- Atomic reload and immutable snapshot behavior.
- Response, FSM, and decision-authority boundaries.
- Remaining temporary adapters and their documented removal direction.

## Final Checklist

| Area | Status | Evidence |
| --- | --- | --- |
| No separate legacy pipeline | Pass | Runtime authority flows through policy contexts; old behavior is represented by `standard_auth` or documented adapters. |
| Old behavior only through `standard_auth` or documented migration adapters | Pass | Default policy constant remains `standard_auth`; converter maps old config into `auth.policy`. |
| Brute force is first-class policy/FSM material | Pass | Brute-force check type, attributes, standard decisions, FSM markers, metrics, and obligation are modeled in policy code. |
| Synchronous Lua actions are policy-owned obligations | Pass | `auth.obligation.lua_action.dispatch` is registered, typed, planned by `standard_auth`, and executed only from selected decisions. |
| Policy config under `auth.policy` | Pass | Config structs, compiler paths, dumps, and converter output all use `auth.policy`; `policy_engine` is only present in spec/temp text and converter negative assertions. |
| No historical public target names | Pass | Compiler rejects old FSM event strings; target markers and response markers use `auth.*` policy IDs. |
| No new Go `phase` names | Pass | The Go diff check is part of validation and had no matches. |
| Observe comparison bounded to observe mode | Pass | `CompareCustomObserve` is the remaining comparison path and is gated by configured observe mode. |
| Atomic reload | Pass | Compile happens before activation; activation stores a cloned complete snapshot only after successful compile. |
| Report/log/metric/trace redaction | Pass | Normal decision logs use bounded fields; reports redact unsafe details unless a public selected response message was chosen. |
| Active temporary adapters documented | Pass | See "Active Temporary Adapters". |

## Found And Fixed Gaps

### Removed Lua scheduler keys still accepted by runtime config

Gap:
`when_no_auth`, `when_authenticated`, `when_unauthenticated`, and `depends_on`
were still accepted under `auth.policy.attribute_sources.lua.environment` and
`auth.policy.attribute_sources.lua.subject` because the keys were still present
in the target runtime config structs.
`auth.controls.enabled` also still had a migration-only `when_no_auth` decode
shape.

Why this was a target-model gap:
The target config surface must not retain mechanism-local scheduler keys. Old
Lua scheduling is represented by policy check `operations`, `run_if.auth_state`,
and `after`, with conversion handled by the migration tool. Runtime config must
fail through normal unknown-key or invalid-shape semantics when old keys are
left in the active configuration.

Reproducer tests added first:

- `TestHandleFile_LuaAttributeSourcesRejectRemovedSchedulerKeys`
- `TestHandleFile_ServerControlsRejectRemovedWhenNoAuthShape`

Fix:

- Removed `depends_on` and `when_*` from `LuaEnvironmentSource` and `LuaSubjectSource` config
  structs.
- Removed the migration-only `when_no_auth` decode hook for enabled
  control declarations.
- Updated Lua runtime script structs to use internal `Modes` and `Dependencies`
  names instead of the old config key names.
- Regenerated the Vim syntax file and added generator assertions that the
  removed keys are not emitted.

### Stage-scoped `standard_auth` authority

Gap:
Configured policy rules in one production stage disabled the built-in default
set for every stage in enforce mode. This meant:

- configured final auth rules could prevent default pre-auth decisions such as
  `standard_tls_enforcement` from being selected and reported;
- configured pre-auth rules could prevent default final auth decisions such as
  `standard_auth_failure` from being selected and reported.

Why this was a target-model gap:
`standard_auth` is the built-in representation of current behavior. Configured
rules should take production authority only for their configured operation and
stage, not evict default authority for unrelated stages.

Reproducer tests added first:

- `TestAuthBoundaryDefaultPreAuthAppliesWhenConfiguredFinalRulesExist`
- `TestAuthBoundaryDefaultFinalDecisionAppliesWhenConfiguredPreAuthRulesExist`

Fix:

- Added `BuiltinDefaultAuthoritativeForStage(stage)` to the decision context.
- Kept observe mode behavior unchanged.
- Changed default pre-auth and final-auth resolution to ask for default
  authority only for the relevant stage.
- Added `TestDecisionContextDefaultSetAuthorityIsStageScoped` for the collection
  boundary.

### Checks-only Lua scheduling did not drive runtime execution

Gap:
`auth.policy.checks` could be configured without custom policy rules, but Lua
environment sources did not consume the policy script plan at runtime. Lua
subject sources consumed `run_if` selection but not policy `after` ordering.
This made checks-only
scheduling incomplete when `standard_auth` remained the decision authority.

Why this was a target-model gap:
`standard_auth` must remain authoritative when no custom rules exist, but
policy checks still own fact collection and Lua scheduling for configured check
families. Operation scope, auth-state guards, and start order must therefore be
effective without requiring a full custom rule set.

Reproducer tests added first:

- `TestCallEnvironmentLuaUsesPolicyScheduleForNoAuthControl`
- `TestCallSubjectLuaUsesPolicyScheduleDependencies`
- `TestScriptSinkBuildsPolicyScriptSchedule`
- `TestCompilerRejectsRunIfIncompatibleCheckDependency`
- `TestStandardAuthMapsLuaScriptsForLookupIdentity`
- `TestScriptSinkResolvesLuaResultByConfigRef`
- `TestStandardAuthMapsLuaScriptsFromEmittedAttributes`

Fix:

- Added a request-local script schedule plan from policy checks.
- Routed Lua environment and subject sources through that schedule when configured.
- Preserved built-in scheduling when no Lua checks exist for that script family.
- Enforced `after` scheduler compatibility for both operation scope and
  auth-state guard coverage.
- Extended `standard_auth` Lua environment/subject source mapping to `lookup_identity`.
- Resolved Lua runtime results by `config_ref` so hand-written check names work
  with named scripts.
- Resolved dynamic `standard_auth` Lua rule names from emitted Lua attributes so
  hand-written check names still map to the correct script fact attributes.

### Bundled Lua plugin facts were not real policy emitters

Gap:
The bundled policy-aware Lua plugins wrote request-local `policy_facts` context
and custom-log values, but those values were not emitted into the request-local
policy `DecisionContext`. Policies could consume generated script result
attributes such as `auth.lua.subject.<name>.rejected`, but not the plugin-owned
signals documented under `lua.plugin.*`.

Why this was a target-model gap:
Lua plugin signals that participate in policy decisions must be registered
attributes and runtime emissions, not a parallel context/log channel. Unknown,
unregistered, wrong-stage, or wrong-type plugin emissions must fail hard through
the Lua execution path.

Reproducer tests added first:

- `TestPolicyEmitterRecordsRegisteredLuaAttribute`
- `TestPolicyEmitterRejectsUnknownLuaAttribute`
- `TestPolicyEmitterRejectsStageMismatch`
- `TestPolicyFactsHelperStoresContextAndPublicLogs`
- `TestCompilerLoadsBundledLuaPluginRegistry`

Fix:

- Added request-bound `nauthilus_policy.emit_attribute` for Lua environment and
  subject sources.
- Added a stateless placeholder that fails when emission is attempted outside a
  request-local policy context.
- Bound the real emitter in environment execution at `pre_auth` and subject-source
  execution at `subject_analysis`.
- Validated runtime emissions against the active snapshot registry, attribute
  source, stage, operation, value type, registered details, and detail length.
- Converted `nauthilus_policy_facts` into a real emitter wrapper while keeping
  request-local facts for later Lua actions.
- Added `server/lua-plugins.d/policy/registry.lua` for bundled plugin
  attributes.
- Updated bundled policy-aware scripts with emitted-attribute headers.
- Added Next website documentation for Lua policy plugins and the
  `nauthilus_policy` Lua API.

### Synchronous Lua actions remained mechanism-owned

Gap:
The current target-model end state registered and executed
`auth.obligation.brute_force.update` and
`auth.obligation.lua_post_action.enqueue`, but did not yet register or execute
`auth.obligation.lua_action.dispatch`. Environment-triggered actions still ran from
`processEnvironmentAction` / `performAction`, and brute-force-triggered actions
still ran from `handleBruteForceLuaAction`, even when the request already had a
policy-authoritative pre-auth decision.

Why this was a target-model gap:
Synchronous Lua action dispatch is a request-time side effect selected by the
winning policy decision. A triggering check fact alone must not dispatch a Lua
action, and observe mode must report planned obligations without running mutable
effects.

Reproducer tests added first:

- `TestAuthBoundaryConfiguredPreAuthDecisionWithoutLuaActionObligationSkipsSynchronousAction`
- `TestAuthBoundaryConfiguredPreAuthDecisionRunsSelectedLuaActionObligationOnce`
- `TestPolicyObligationExecutorSkipsMutableEffectsInObserveMode`
- `TestCompilerAcceptsLuaActionDispatchObligationArgs`
- `TestCompilerRejectsLuaActionDispatchInvalidArgs`

Fix:

- Registered `auth.obligation.lua_action.dispatch`.
- Added bounded typed compiler validation for `action`, `environment`, and `wait`.
- Added a central runtime obligation executor behind `applyPolicyObligations`.
- Planned Lua action obligations in `standard_auth` for `brute_force`, `lua`,
  `tls_encryption`, `relay_domains`, and `rbl`.
- Removed direct environment and brute-force synchronous Lua action dispatch from
  mechanism paths.
- Removed the old direct brute-force action dispatcher.
- Preserved existing action dispatcher behavior, request context objects,
  cancellation checks, and action metrics.
- Assigned environment-learning ownership to
  `auth.obligation.brute_force.update` so Lua dispatch cannot mutate bucket
  state.
- Preserved brute-force Lua action `CommonRequest` parity by exposing the
  matched rule name during dispatch instead of the internal repeating/guessed
  security marker.
- Preserved the old brute-force Lua action account refresh behavior for
  `account` / `account_field` when the account is found during the action path.
- Skipped central mutable obligation execution in observe mode.
- Tightened the executor so mutable obligations also skip when no request-local
  policy context exists; this prevents a non-authoritative fallback path.

## Deliberately Unchanged Points

- No native response-profile renderer was introduced in this pass.
- No proto or transport contract was changed for gRPC list-account denial
  payloads.
- No new policy check executor architecture was introduced.
- No public config root, public naming model, or authority surface was changed.

## Active Temporary Adapters

| Adapter | Current Purpose | Planned Removal |
| --- | --- | --- |
| Response-writer bridge | Keeps current HTTP, CBOR, header, nginx, IdP, and gRPC response rendering while policy owns decisions. | Remove when native policy response profiles render all surfaces directly. |
| gRPC list-account metadata bridge | Carries policy denial/tempfail semantics through the current gRPC list-account contract. | Remove when the response-profile renderer and proto contract can carry typed policy denial payloads. |
| HTTP list-account writer bridge | Preserves current list-account denial/tempfail output while policy owns the final decision. | Remove with the same native account-provider response-profile work. |
| Mechanism fact adapters | Convert current TLS, relay-domain, RBL, brute-force, Lua, backend, subject-source, and account-provider outcomes into policy facts. | Remove piece by piece when native policy check executors replace current mechanism-local execution. |
| Lua execution bridge | Keeps current Lua script execution through the existing runtime while public scheduling keys are removed from active config. | Remove when native policy check executors own Lua environment/subject source execution directly. |
| Lua policy-emitter binding | Binds the existing Lua runtime to the active request policy context so scripts can emit registered `lua.plugin.*` attributes. | Remove when native policy check executors provide their own policy-native Lua execution environment. |
| AuthResult translation bridge | Maps policy decisions back into current `AuthResult` values for existing transport handlers. | Remove when response and enforcement are policy-native end to end. |
| Obligation handoff bridge | Applies brute-force updates, synchronous Lua actions, and Lua post-actions through current AuthState methods and action dispatcher. | Remove when obligations execute through a native enforcement context. |

## Validation Results

Passed:

- `GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test -run 'TestAuthBoundaryDefault(PreAuthAppliesWhenConfiguredFinalRulesExist|FinalDecisionAppliesWhenConfiguredPreAuthRulesExist)|TestDecisionContextDefaultSetAuthorityIsStageScoped' ./server/core ./server/policy/collection`
- `GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test -run 'TestHandleFile_LuaAttributeSourcesRejectRemovedSchedulerKeys|TestHandleFile_ServerControlsRejectRemovedWhenNoAuthShape|TestHandleFile_LuaEnvironmentSourcesPopulateInternalList|TestHandleFile_ServerControlsAndServicesEnableRuntimeModules|TestKnownConfigSyntaxKeys_IncludeNestedListAndMappingKeys' ./server/config`
- `GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test ./server/config ./server/lualib/environment ./server/lualib/subject ./server/policy/collection`
- `GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test -run 'TestCallEnvironmentLuaUsesPolicyScheduleForNoAuthControl|TestCallSubjectLuaUsesPolicyScheduleDependencies|TestScriptSinkBuildsPolicyScriptSchedule|TestCompilerRejectsRunIfIncompatibleCheckDependency|TestStandardAuthMapsLuaScriptsForLookupIdentity|TestStandardAuthMapsLuaScriptsFromEmittedAttributes|TestScriptSinkResolvesLuaResultByConfigRef' ./server/lualib/environment ./server/lualib/subject ./server/policy/collection ./server/policy/compiler ./server/policy/evaluation`
- `python3 scripts/test_generate_vim_syntax.py`
- `git diff -- '*.go' | rg -n -i '^\+.*phase'`
  - Result: no matches.
- Historical target-surface scan:
  - `policy_engine` appears only in converter negative assertions and temp/spec text.
  - `unknown_pre_auth_marker` appears in the compiler rejection test that proves unknown FSM marker names are invalid.
  - `when_*` and Lua `depends_on` appear only in converter/test/spec text, not in target config structs or generated syntax.
  - Removed comparison APIs such as `CompareWithProduction` and `ProductionOutcome` have no code hits.
- `GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test ./server/policy/... ./server/core ./server/lualib/environment ./server/lualib/subject ./server/lualib/pipeline ./server/lualib/policyschedule`
- `GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test -run 'TestPolicyEmitter|TestPolicyFactsHelperStoresContextAndPublicLogs|TestCompilerLoadsBundledLuaPluginRegistry' ./server/lualib ./server/testing/luatest ./server/policy/compiler`
- `GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test ./server/lualib ./server/lualib/environment ./server/lualib/subject ./server/testing/luatest ./server/policy/compiler`
- `./scripts/run-lua-plugin-tests.sh`
- `python3 scripts/test_convert_config_v1_to_v2.py`
- `GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test -run 'TestAuthBoundaryConfiguredPreAuthDecision(WithoutLuaActionObligationSkipsSynchronousAction|RunsSelectedLuaActionObligationOnce)|TestPolicyObligationExecutorSkipsMutableEffectsInObserveMode|TestCompiler(AcceptsLuaActionDispatchObligationArgs|RejectsLuaActionDispatchInvalidArgs)' ./server/core ./server/policy/compiler`
- `GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test -run 'TestPolicyObligationExecutorSkipsMutableEffectsWithoutPolicyContext' ./server/core`
- `GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test -run 'TestPolicyBruteForceLuaActionPreservesCommonRequestShape' ./server/core`
- `GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test -run 'TestBruteForceLuaActionAccountRefreshPreservesCommonRequestAccountField' ./server/core`
- `GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test ./server/core ./server/policy/... ./server/lualib/environment ./server/lualib/subject ./server/lualib/pipeline ./server/lualib/policyschedule`
- `GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache make test`
- `git diff --check`
- `GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache make guardrails`
- `npm run build` in `../nauthilus-website`

## Final Acceptance Status

Pass for the reconciled current specification after the Phase 7 retrofit.

The acceptance status is based on the historical completed validation set, the
Phase 7 focused reproducer tests, the affected package validations, the second
review pass, and the final guardrail checks.

## Review-Abgleich

Second-pass scope:

- Re-read implementation-step 14 and the inserted Phase 7 requirements.
- Re-read spec section 18.1.
- Re-read spec section 17.
- Compared those points against policy/config/core/observability code and this
  acceptance document.

Second-pass result:

- Section 17 registry and mapping requirements match the implemented registry,
  compiler validation, `standard_auth` evaluators, report shapes, metrics, and
  response/FSM markers.
- Section 18.1 completion rules are satisfied for this closure pass: focused
  reproducers were added before the behavior fix, external behavior remains in
  the target model, config UX was checked without adding new config, report
  redaction remains bounded, package and boundary tests passed, reload
  activation remains atomic, and active adapters are documented above.
- Implementation-step 13 remains satisfied: no old-vs-new production comparison
  path was reintroduced, `CompareCustomObserve` remains the only supported
  comparison mode, current-vs-target FSM comparison APIs remain removed, and
  historical names are not target surfaces.
- The inserted Phase 7 is now satisfied: synchronous Lua action dispatch is a
  registered policy obligation with bounded typed arguments, selected
  `standard_auth` and custom decisions execute it centrally, and observe mode
  executes no central mutable obligations. No direct environment or brute-force
  synchronous Lua action mechanism fallback remains; the executor also refuses
  mutable execution without a request-local policy context. The CommonRequest
  follow-up review fixed the brute-force rule-name parity gap in the Lua action
  request object.
- A later checks-only scheduling gap was found and fixed in the same target
  model: policy checks now drive Lua environment/subject source operation scope, auth-state
  guards, and start order while `standard_auth` remains authoritative when no
  custom rules exist.
- A later Lua plugin emission gap was found and fixed in the same target model:
  bundled plugin facts now have a registered `lua.plugin.*` registry script and
  emit into the request policy context through the real Lua policy module.
