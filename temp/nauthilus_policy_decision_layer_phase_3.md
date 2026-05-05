# Nauthilus Policy Decision Layer - Phase 3

## Goal

Phase 3 adds request-local `CheckResult` collection and explicit adapters for the current auth mechanisms while keeping the existing production decision path authoritative. The collected data is reportable and observable, but it does not select an `AuthResult`, response marker, FSM transition, or side effect yet.

## Implemented Files and Modules

- `server/policy/types.go`: exported stable check-type, `run_if`, and minimum built-in attribute IDs used by the compiler, registry, collectors, and adapters.
- `server/policy/collection`: added `DecisionContext`, `ActiveCheck`, attribute helpers, missing/skipped/unavailable reporting, policy check metrics, OTel check spans, and Lua script sinks.
- `server/policy/report/report.go`: expanded report check entries with type, operation, reason, decision hint, match flag, emitted attributes, missing checks, and unavailable facts.
- `server/policy/observability/metrics.go`: added a process-wide safe policy metrics recorder for request-time check measurements.
- `server/policy/compiler/definitions.go` and `server/policy/registry/builtin.go`: reused the shared policy constants instead of duplicating registry strings.
- `server/core/policy_collection.go`: added request-local policy collection wiring for request attributes, built-in adapters, backend/account-provider adapters, stage completion, and the Lua script-recorder handoff.
- `server/core/bruteforce.go`, `server/core/features.go`, `server/core/auth.go`, and `server/core/auth/lua_service.go`: attached collection to brute force, Lua controls, TLS, relay domains, RBL, backend authentication, Lua filters, and account-provider paths without changing returned `AuthResult` values.
- `server/lualib/feature/feature.go` and `server/lualib/filter/filter.go`: attached one per-script collection event to the existing dependency-plan execution path after each named Lua control or filter finishes or errors.

## Tests and Validation

- Added package-local collection tests in `server/policy/collection/collection_test.go` for check result storage, attribute storage, default OK metric status, skipped/missing/unavailable facts, and per-script Lua sink output.
- Added auth-boundary parity coverage in `server/core/policy_collection_test.go` proving TLS collection does not change the current TLS feature decision.
- Validated focused packages with:
  - `GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test ./server/policy/collection ./server/core -run 'TestDecisionContext|TestScriptSink|TestAuthPathCollectsTLSCheck'`
  - `GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test ./server/lualib/feature ./server/lualib/filter ./server/policy/compiler ./server/policy/report ./server/policy/observability`
  - `GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test ./server/core`
- The sandboxed full `GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache go test ./...` failed because tests could not bind local listeners or miniredis sockets (`bind: operation not permitted`). The same command passed outside the sandbox.
- `GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache make guardrails` first found and fixed a new Revive flow-style issue. The sandboxed rerun then reached tests but failed on the same listener/miniredis restriction and cache writes outside the workspace. The same command passed outside the sandbox.

## Active Temporary Adapters

- The current auth implementation remains the authoritative decision path. The collection layer is a migration adapter that observes current mechanisms and emits target-model facts.
- `server/core/policy_collection.go` maps current built-in functions to target check names: `brute_force`, `tls_encryption`, `relay_domains`, `rbl`, `ldap_backend`, `lua_backend`, and `account_provider`.
- `server/lualib/feature` and `server/lualib/filter` emit named Lua check results through an internal `ScriptRecorder` adapter while preserving the existing dependency-plan execution and `lualib.Context` delta merge.
- Backend selection maps the current LDAP/Test/cache-compatible paths to `ldap_backend` unless the observed backend is Lua. This keeps the target check surface stable while the current backend path remains authoritative.

## Planned Adapter Removal

- The current-auth authoritative bridge is removed when policy check execution, policy decision evaluation, and response/FSM rendering become authoritative in a later implementation step.
- The built-in function wrappers in `server/core/policy_collection.go` should be replaced by native check executors or narrowed to telemetry-only shims after the policy engine owns decision selection.
- The Lua `ScriptRecorder` handoff remains until named Lua controls and filters are first-class policy check executors that emit their registered attributes directly.
- The backend mapping adapter is removed once backend checks are represented as explicit policy executors for LDAP, Lua, and any later supported backend source.

## Open Risks and Deliberately Not Implemented

- No policy decision, FSM authority switch, response rendering, obligation execution, or advice selection is implemented in this step.
- Collected check results are not returned to clients by default and do not alter current response messages or status codes.
- Config UX is intentionally unchanged: no new public config root was added, no schema keys changed, and no historical public names were introduced.
- Atomic reload remains the existing snapshot-compiler behavior from the prior step; this step consumes active snapshots but does not change snapshot activation.
- `standard_auth` rules are not evaluated as the production authority yet. This step only emits the facts that the mapping table requires.

## Review-Abgleich

- Completion rule 18.1.1: focused tests were added before implementation. The initial focused run failed because `server/policy/collection` did not exist and the auth-boundary collection API was missing.
- Completion rule 18.1.2: current external behavior remains unchanged. The auth-boundary TLS parity test asserts the current TLS `AuthResult` still returns unchanged while collection records the check.
- Completion rule 18.1.3: new check execution records policy metrics through the policy recorder and creates `policy.check` OTel spans. Existing debug modules and structured logs remain on the current mechanisms; this step does not add a new public debug surface.
- Completion rule 18.1.4: no new config path was added. Existing `auth.policy` compiler validation for `mapstructure`, schema, `ConfigProblem`, dump, and redaction remains unchanged.
- Completion rule 18.1.5: report entries use the policy report redaction model for detail values. Internal details such as backend, reason codes, domains, and brute-force context are marked internal; Lua status messages are marked public response-message candidates.
- Completion rule 18.1.6: package-local unit tests cover collection/report behavior, and `server/core` contains an auth-boundary parity test.
- Completion rule 18.1.7: atomic reload behavior is unaffected. The request collector reads the active snapshot from the runtime store and does not mutate snapshot activation.
- Completion rule 18.1.8: active temporary adapters and planned removal are listed above.
- Phase 3 requirement 1: brute force, Lua controls, TLS, relay domains, RBL, backend, Lua filters, and account providers now emit structured check results and registered attributes.
- Phase 3 requirement 2: Lua controls and Lua filters emit one result per named script through the script sink.
- Phase 3 requirement 3: the implementation attaches to the existing compiled Lua dependency-plan execution path and records after each planned script result; `lualib.Context` deltas are still merged in the existing order.
- Phase 3 requirement 4: `run_if`, `operations`, `after`, and `require_checks` remain compiler-validated against the compiled plan from the prior step; request-time collection resolves adapters against that plan and records missing/skipped facts.
- Phase 3 requirement 5: reports now include check results plus missing, skipped, error, and unavailable facts.
- Phase 3 requirement 6: check execution emits policy metrics and OTel spans.
- Phase 3 requirement 7: collected results do not change production decisions.
- Section 17 mapping: the implemented check names and attribute IDs align with the registry and mapping tables for `brute_force`, `lua_control.<name>`, `tls_encryption`, `relay_domains`, `rbl`, `ldap_backend`, `lua_backend`, `lua_filter.<name>`, and `account_provider`.
- Review-fixed gap: Lua script results can be emitted concurrently by the existing per-level Lua execution. `DecisionContext` now guards report maps with a mutex so parallel named Lua control/filter adapters cannot race while recording facts.
- No new Go code contains a technical name, comment, or string matching `/phase/i`; this was checked with `git diff -- '*.go' | rg -n -i '^\+.*phase'`.
