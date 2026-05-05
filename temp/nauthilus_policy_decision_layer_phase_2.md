# Nauthilus Policy Decision Layer - Phase 2

## Goal

Phase 2 adds the policy configuration and snapshot compiler surface without making request-time policy evaluation authoritative. The current authentication path remains externally authoritative, while `auth.policy` can now be decoded, validated, compiled into an immutable runtime snapshot, and atomically published at startup and reload.

## Implemented Files and Modules

- `server/config/schema_v2.go`: added `auth.policy` config structs for policy mode, default policy, registry scripts, sets, report settings, checks, condition trees, decisions, response messages, obligations, advice, and decision controls.
- `server/config/dump.go`: added default dump coverage for `auth.policy`.
- `server/config/schema_index.go`: added recursion-safe schema indexing for nested policy condition trees.
- `server/policy/registry/builtin.go`: added the Go built-in policy attribute registry, including brute-force, TLS, relay-domain, RBL, backend, Lua-generated script attributes, and account-provider facts.
- `server/policy/registry/registry.go`: extended attribute definitions with category and producer metadata.
- `server/policy/compiler/*.go`: added the snapshot compiler, check-type registry, Lua attribute registry script execution, network and time-window set compilation, AST structural validation, registry-aware type checking, marker and effect validation, check ordering, and operation/stage plan construction.
- `server/policy/runtime/snapshot.go` and `server/policy/runtime/default_store.go`: expanded the immutable snapshot model, deep-copy semantics, and process-wide snapshot store.
- `server/app/bootfx/boot.go`: compiles and activates the startup snapshot during configuration setup, so `--config-check` and `-n` validate the new surface.
- `server/app/policyfx/module.go`: compiles and activates candidate snapshots during reload, keeping the old active snapshot if compilation fails.
- `server/main.go`: wires the policy reload module before the reload manager.
- `contrib/vim/syntax/nauthilus.vim`: regenerated syntax metadata for the new config keys.

## Tests and Validation

- Added config decode, exact-key rejection, default dump, and non-default dump tests in `server/config/policy_config_test.go`.
- Added compiler tests for configured snapshots, Lua registry scripts, invalid Lua registry metadata, canonical error paths, invalid network sets, missing producer checks, and atomic store preservation in `server/policy/compiler/snapshot_compiler_test.go`.
- Added runtime snapshot deep-copy coverage in `server/policy/runtime/snapshot_clone_test.go`.
- Added reload preservation coverage in `server/app/policyfx/module_test.go`.
- Added auth-boundary parity coverage in `server/core/current_behavior_parity_test.go` to prove `auth.policy` config does not alter current pre-auth control behavior.
- Validated with focused package tests, `go test ./server`, `make test`, and `make guardrails`, all with `GOEXPERIMENT=runtimesecret` and `GOCACHE=/tmp/nauthilus-go-cache`.

## Active Temporary Adapters

- The production decision path remains the existing auth implementation. This is the intentional Phase 2 migration bridge: the new policy snapshot is built and published, but policy checks and policy decisions are not executed as the request-time authority.
- The omitted `auth.policy` block compiles to an internal default snapshot with `mode: enforce` and `default_policy: standard_auth`. This preserves current behavior while later phases add explicit check-result collection and then switch authority to the compiled `standard_auth` mapping.
- Lua control and Lua filter per-script attributes are generated from configured policy checks during snapshot build. This is an internal compiler adapter for named Lua scripts until request-time Lua check adapters emit the same registered attributes.

## Planned Adapter Removal

- The current-auth authoritative bridge is removed by the later authority switch after check-result collection and decision evaluation are complete.
- The empty default snapshot behavior is replaced by compiled `standard_auth` stage plans once the mapping is implemented and validated against the parity corpus.
- Generated Lua check attributes remain as snapshot metadata, but later request-time adapters must emit real values for those registered IDs.

## Open Risks and Deliberately Not Implemented

- No request-time policy checks are executed in this phase.
- No policy decision, FSM transition, response rendering, obligation execution, advice emission, report rendering, Prometheus runtime metric, or OpenTelemetry request span is authoritative yet.
- The full `standard_auth` mapping table is not expanded into built-in policy rules in this phase; only the default policy anchor and supporting registry metadata are present.
- Lua registry scripts use `stage` as the public field in this implementation. No compatibility alias is added for older or example-only naming, in line with the hard no historical-name rule for new Go code.

## Review-Abgleich

- Completion rule 18.1.1: focused tests were added before the new behavior was fixed, including missing producer-check and Lua registry-category reproducers that failed before the compiler fixes.
- Completion rule 18.1.2: current external behavior remains unchanged; the auth-boundary parity test verifies configured policy snapshots do not alter pre-auth control output.
- Completion rule 18.1.3: no new request-time policy path is active yet. Existing Phase 1 observability primitives remain available; snapshot build failures surface through startup, config-check, and reload errors.
- Completion rule 18.1.4: `auth.policy` has `mapstructure` tags, schema-index support, structured compiler/config paths, dump defaults, and regenerated config syntax metadata.
- Completion rule 18.1.5: no policy reports are emitted yet; response-message metadata is type-checked and public detail selection is validated.
- Completion rule 18.1.6: package-local tests cover config, compiler, runtime, registry, and reload behavior; auth-boundary parity is covered in `server/core`.
- Completion rule 18.1.7: startup publishes only a successfully compiled snapshot, reload publishes only after successful candidate compilation, and failed reload compilation keeps the old snapshot active.
- Completion rule 18.1.8: active temporary adapters and their planned removal are listed above.
- Phase 2 requirement 1: `auth.policy` decodes into config structs under the existing `auth` root.
- Phase 2 requirement 2: Go built-in attributes are registered with type, category, stage, operation, detail, and producer metadata.
- Phase 2 requirement 3: Lua registry scripts execute during snapshot build and contribute to the effective registry before policy compilation.
- Phase 2 requirement 4: network and time-window sets compile into typed runtime operands.
- Phase 2 requirements 5 and 6: the condition AST is structurally validated and type-checked against the effective registry.
- Phase 2 requirement 7: response markers, FSM markers, obligations, advice, `after`, `require_checks`, producer availability, and operation/stage compatibility are validated.
- Phase 2 requirement 8: `PolicyRuntimeSnapshot` is immutable-by-convention and stored through deep-copy activation and reads.
- Phase 2 requirements 9 and 10: startup and reload activation are atomic, with tests proving failed candidates do not replace the active snapshot.
- Phase 2 requirement 11: `-d`, `-n`, and `--config-check` all include or validate the new surface via dump defaults and startup compilation.
- Phase 2 requirement 12: request-time production decisions still do not execute policy checks.
