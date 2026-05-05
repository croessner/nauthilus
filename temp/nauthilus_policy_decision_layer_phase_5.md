# Nauthilus Policy Decision Layer - Phase 5

## Goal

Phase 5 updates the legacy config conversion path so migrated installations can emit target policy configuration under `auth.policy` before the target policy path becomes mandatory.

This phase is limited to the conversion tool and converter documentation. It does not switch production decision authority, does not switch FSM authority, and does not introduce a new compiler or runtime policy surface.

## Implemented Files and Modules

- `scripts/convert-config-v1-to-v2.py`
  - Adds an internal `PolicyConversionPlanner` that derives target `auth.policy` config from the already migrated config-v2 mechanism blocks.
  - Emits `mode: enforce`, `default_policy: standard_auth`, empty registry and set defaults, report defaults, generated checks, and generated `standard_auth`-equivalent policies.
  - Converts old `when_no_auth` state into policy check `operations`, adding `lookup_identity` where the legacy mechanism was enabled for no-auth.
  - Converts old `when_authenticated` and `when_unauthenticated` state into `run_if.auth_state`.
  - Generates one `lua.control` check per Lua control script and one `lua.filter` check per Lua filter script.
  - Converts Lua `depends_on` into check-plan `after` dependencies using generated check names.
  - Removes legacy `when_*` and Lua `depends_on` keys from the emitted target YAML.
  - Generates script-specific Lua policy attributes in the produced policy rules, matching the registry/compiler convention.

- `scripts/test_convert_config_v1_to_v2.py`
  - Updates converter regression coverage so the old scheduler keys are rejected from generated output.
  - Adds focused coverage for Lua scheduler conversion, per-script checks, `after` dependencies, no aggregate Lua checks, and generated `standard_auth` policy rows.
  - Adds coverage that `server.features[].when_no_auth` survives later `server.controls` migration as target policy operation scope.

- `server/docs/config_v2_converter.md`
  - Documents that the converter now emits target `auth.policy` config.
  - Documents `when_*` and `depends_on` rewrites into policy check scheduling.

## Tests and Validation

Focused tests were added before the converter implementation. The first run failed because the old converter still emitted `when_no_auth` and did not generate `auth.policy`.

Validation run:

```bash
python3 scripts/test_convert_config_v1_to_v2.py
python3 scripts/convert-config-v1-to-v2.py scripts/testdata/legacy-monolithic-config.yml --stdout --validate
python3 -m py_compile scripts/convert-config-v1-to-v2.py scripts/test_convert_config_v1_to_v2.py
GOEXPERIMENT=runtimesecret go test ./server/config ./server/policy/compiler
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache GOMODCACHE=/tmp/nauthilus-gomod-cache make test
GOEXPERIMENT=runtimesecret GOCACHE=/tmp/nauthilus-go-cache GOMODCACHE=/tmp/nauthilus-gomod-cache make guardrails
git diff --name-only -- '*.go'
git diff -- '*.go' | rg -n -i '^\+.*phase'
```

Result: passed.

The first `GOEXPERIMENT=runtimesecret make test` attempt without cache overrides failed because the sandbox could not write to `~/go/pkg/mod` and `~/Library/Caches/go-build`. The same target passed with `GOCACHE` and `GOMODCACHE` under `/tmp`.

`make guardrails` passed. It emitted the existing warning about unknown `gomnd` entries in `//nolint` directives and then reported `0 issues`.

The Go-name check found no changed Go files and no added Go diff lines containing case-insensitive `phase`.

## Active Temporary Adapters

- Current runtime Lua scheduler fields remain in the Go config/runtime structs.
  - Purpose: preserve the existing production runtime until later phases make policy scheduling and policy decisions authoritative.
  - Target output status: the converter no longer emits these fields in generated target YAML.
  - Removal plan: remove the public mechanism-local scheduler surface when the policy check plan becomes the authoritative scheduler and the final cleanup removes migration scaffolding.

- Generated `standard_auth` config remains a migration adapter, not a separate legacy pipeline.
  - Purpose: express old behavior as target policy config for migrated installations.
  - Removal plan: keep `standard_auth` as the built-in default policy, but remove converter-only migration assumptions after the final target config cut and cleanup.

## Planned Later Removal

- Remove runtime dependence on mechanism-local Lua scheduler fields after the policy check plan becomes authoritative.
- Remove any old direct-gate or scheduler bridge code in the final cleanup once Phase 7 and Phase 8 have made `standard_auth` and the target FSM authoritative.
- Keep `standard_auth` itself as the supported built-in default policy, not as a legacy path.

## Open Risks and Deliberately Deferred Points

- The converter emits target policy config, but production auth decisions remain owned by the current runtime path in this phase.
- The Go runtime schema still contains mechanism-local Lua scheduler fields as a temporary compatibility adapter; this phase cuts the converter output, not the runtime scheduler authority.
- Unknown Lua `depends_on` values are intentionally carried into generated `after` entries so existing policy validation can surface broken dependency trees instead of silently dropping them.
- Custom policy observe/enforce modes remain later phases.
- Target FSM adapter and target FSM authority remain later phases.
- Policy observability, report generation, OTel spans, and Prometheus metrics were not changed in this phase because no new runtime policy path was introduced.

## Review-Abgleich

Second pass completed against the Phase 5 requirements, the general completion rules from section 18.1, the check/attribute/marker mapping tables from section 17, the `standard_auth` mapping checklist, and the target config model.

- Scope: implementation is limited to the conversion tool, converter tests, converter docs, and this implementation note. No compiler authority, decision authority, FSM authority, or runtime enforcement switch was started.
- Tests first: focused converter tests were added before implementation. The first run failed because the old converter still emitted `when_no_auth` and did not generate `auth.policy`.
- Config placement: generated policy config lives under `auth.policy`; no `policy_engine` or historical public root was introduced.
- `when_no_auth`: converted into policy `operations`, including `lookup_identity` where legacy no-auth scheduling was enabled. Review gap fixed: `server.features[].when_no_auth` is now preserved as an internal scheduler hint even if later `server.controls` migration overwrites `auth.controls.enabled`.
- `when_authenticated` and `when_unauthenticated`: converted into `run_if.auth_state`.
- Lua checks: the converter generates one `lua.control` check per Lua control script and one `lua.filter` check per Lua filter script. It does not generate aggregate `lua_controls` or `lua_filters` checks.
- Lua dependencies: `depends_on` is converted to `after` with generated check names. Review gap fixed: unknown dependency names are now carried into `after` so policy validation can report the broken dependency instead of silently dropping it.
- Target output cut: generated YAML strips `when_no_auth`, `when_authenticated`, `when_unauthenticated`, and Lua `depends_on`.
- `standard_auth`: generated rules cover brute force, TLS, relay-domain, RBL, Lua controls, backend technical outcomes, Lua filters, auth success/failure, lookup identity, list accounts, and final default deny where corresponding checks exist. Brute force remains a first-class policy check and policy rule, not a side path.
- Config UX: the converter emits only existing `auth.policy` schema fields with existing `mapstructure`, schema-index, dump, and `ConfigProblem` support. The `--validate` run confirms the generated target config passes current config-check.
- Observability and reports: no new runtime path was introduced, so no new logs, reports, metrics, OTel spans, or redaction surfaces were required in this phase.
- Atomic reload: no snapshot activation code changed; current atomic compiler behavior remains covered by existing compiler tests and guardrails.
- Deferred by scope: making old mechanism-local scheduler keys invalid in the runtime schema is documented as a temporary adapter because the current production Lua runtime still reads those fields until later policy-scheduler authority is in place.
