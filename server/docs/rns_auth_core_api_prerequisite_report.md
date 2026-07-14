# RNS authentication bundle Core/API prerequisite current/target report

Date: 2026-07-14

Core release commit: `76865c77260491dbaf5f512add5c55d9060922d4`

Beta tag: `v3.1.0-beta.50`

Gate status: **READY**

The Core/API prerequisite lane is complete and live. The subsequent bundle lane may start only from the exact released
Core commit and contract hashes recorded below. This lane did not implement or activate the RNS authentication bundle.
Beta.49 was published but intentionally not rolled out after the mixed Lua/native subject-order blocker was found;
beta.50 supersedes it and is the only live handoff baseline.

## Requirement status

| Required Core/API capability | Current status | Target and evidence |
| --- | --- | --- |
| Operator-owned hook scopes | Complete | `HookDescriptor.RequiredScopes` is configured by the operator, normalized, de-duplicated, defensively copied, conflict checked, and authorized with the existing any-of semantics before request construction or plugin execution. Empty lists retain the established Scope/Auth fallback. Effective scopes are visible in non-secret config and discovery diagnostics. |
| Native environment execution facts | Complete | The policy compiler generates `auth.plugin.environment.<module>.<component>.{triggered,abort,error}` from registered components. Snapshot tests cover exact definitions, producer checks, operations, details, and rejection of invalid references. |
| Exact legacy metric compatibility | Complete | A signer-gated, module-scoped compatibility facade accepts only exact operator allowlists for metric name, type, help, labels, and buckets. It safely reuses a collector already registered by Lua only when the complete contract is identical; type, help, label, or bucket drift fails closed. Shared observations do not double-register or double-count. Raw Prometheus registerers remain hidden and native metrics remain supplemental. |
| Narrow trace compatibility | Complete | The value-only tracing facade supports approved compatibility scopes, typed span kinds, and explicit status/error semantics without exposing OpenTelemetry providers. Host HTTP owns exactly one `plugin.http` client span; plugin code must not add a second client span around host HTTP, LDAP, Redis, or mail operations. |
| Declarative initialization | Complete | Operator configuration owns translation catalogs under `auth.policy.localization.catalogs` and the existing brute-force and relay-domain soft allowlists. Catalog reload is atomic, preserves Lua overlays, and has validation, failed-reload, config-dump, and precedence coverage. Allowlists are normalized, de-duplicated, validated, and defensively copied. |
| Safe LDAP endpoint metadata | Complete | `pluginapi/v1` exposes value-only LDAP endpoint metadata containing only pool name, scheme, host, and port. URI userinfo, base DN, query data, TLS material, and credentials are excluded. A shared parser also removes the prior trace-userinfo risk. |
| Deterministic country display lookup | Complete | `DeterministicHelpers.CountryName` provides the same non-secret country-name semantics as `nauthilus_misc.get_country_name`. Focused API and host-adapter tests cover known, lowercase, unknown, and empty country codes without exposing configuration or server internals. |
| Mixed Lua/native subject ordering | Complete | A policy `after:` edge from `lua.subject` to `plugin.subject` creates one deterministic native boundary: non-deferred Lua subjects, native subject bridge, then deferred Lua subjects. A real `AuthState.SubjectLua` host-path test proves `geoip_history -> geoip_reputation -> native_rns_ldap -> director_routing`; legacy configurations without a cross-source edge retain the previous whole-Lua-before-native order. A second native boundary fails closed at compile time. |
| Public API boundary | Complete | Import-boundary tests keep `pluginapi/v1` value-oriented and free of Gin, raw Prometheus registerers, raw OpenTelemetry providers, raw Viper, and server internals. |
| Operator and developer surfaces | Complete | Public API, operator, developer, working-draft, examples, schema, syntax, discovery, and config-dump documentation were updated and generated checks pass. |

## Contract hashes

The hashes are calculated from Git blob identifiers plus sorted paths at the release commit, which makes them
reproducible without timestamps or working-tree state.

| Contract | Value |
| --- | --- |
| `pluginapi/v1` Git tree object | `e0939daf73c56b7882066e3a4bb0c94c4790d1d0` |
| Non-test `pluginapi/v1` source manifest SHA-256 | `3d6a47422cc3c3c13218e7258c531fcef774cd6dc8bdc712876f77fc0f7e2fde` |
| Public plugin documentation manifest SHA-256 | `e31a055e3e001c45e41d41721a8dee08dc835755c50934e67a111975931adc9c` |
| API, config, and discovery operator contract SHA-256 | `65aa8004e4ed706070abd05333ee7a3d9460f6549b6b505d695a2dd28543ad36` |

Reproduction commands:

```sh
git rev-parse 76865c77260491dbaf5f512add5c55d9060922d4:pluginapi/v1
git ls-tree -r 76865c77260491dbaf5f512add5c55d9060922d4 pluginapi/v1 \
  | awk '$4 !~ /_test[.]go$/ {print $3 " " $4}' | shasum -a 256
git ls-tree -r 76865c77260491dbaf5f512add5c55d9060922d4 \
  server/docs/go_plugins.md server/docs/go_plugin_developer_api.md server/docs/go_plugin_api_working_draft.md \
  | awk '{print $3 " " $4}' | shasum -a 256
git ls-tree -r 76865c77260491dbaf5f512add5c55d9060922d4 \
  pluginapi/v1 server/config/schema_v2.go server/config/plugins.go server/pluginloader/discovery.go \
  | awk '$4 !~ /_test[.]go$/ {print $3 " " $4}' | shasum -a 256
```

## Release image and plugin ABI provenance

Production image:
`ghcr.io/croessner/nauthilus:v3.1.0-beta.50@sha256:436bef3423b0e605fcfee17f9225ce5f692160c38dba6464845bd963dc4ab7a1`

Shadow image:
`ghcr.io/croessner/nauthilus:dev-dbg@sha256:235cf2eb597d433ae6710b18133f5f0946e421293399cad9d87c9ce10ffeb634`

The production multi-architecture manifests are
`sha256:a63acf8ba769e1cf73709619bff5d022b7feddaec85cb44e7fdbcf1f4f65d4b3` for amd64 and
`sha256:80ac6b6d7c8fd8b76c60ccfdcb6b010c60568f8c75efa0fc59587c4b9e369cf0` for arm64. The
shadow manifests are `sha256:2bedead060fc8861a89e766eaf4b9b1a778e9d854e3f069fd59a726f21c2ec4b` for amd64
and `sha256:736917d64355d77c9127ff67414563aeca27dce22d83ad44274fe574d5c8d829` for arm64.
Production OCI labels on both architectures record revision `76865c77260491dbaf5f512add5c55d9060922d4`, version
`v3.1.0-beta.50`, and build reason `tag-push`. Extracted binaries from both production and shadow record that exact
VCS revision.

The server and bundled plugins use Go `1.26.5`, `GOEXPERIMENT=runtimesecret`, `CGO_ENABLED=1`, the `netgo` tag, and
`-trimpath`. Plugins additionally record `-buildmode=plugin`, `GOOS=linux`, the target architecture, the exact VCS
revision, and the same source timestamp. The runtime API is `nauthilus.plugin.v1`; GeoIP, ClickHouse, and
HaveIBeenPwned each register plugin version `0.1.0`.

The production arm64 plugin artifact SHA-256 values are:

| Plugin | `.so` SHA-256 | `.minisig` SHA-256 |
| --- | --- | --- |
| GeoIP | `0b42a76bb16034585d851e2bb1e0c59fa7160b9a0ba9d87e89da8bc2c92d09b8` | `ea9384aeee8aa4dd1e41e3903ca5c5ab89c7cae07abc800d06a5bb83e25b8b4f` |
| ClickHouse | `9c64928de6ccb1e8223dfc5d5ea203cdf39f802124fbd0c6ccf75c956327f5e3` | `9d630ca1c8d24f869148c07e5e91db391b143e7c61640ed54c9b4c1052538ab1` |
| HaveIBeenPwned | `250c5bd9dcb717e84999febbde4d61f31c6d45b3ba1af5b388ed34f6feeb216c` | `dd365d698326005cb26dd55659ca1608f19c7a5bd1ea295654efb1086dc08adf` |

Go build information reports `vcs.modified=true` for bundled plugins. This is an explainable image-build artifact, not
a source or ABI mismatch: after a clean checkout, the Dockerfile writes only the untracked server build output before
compiling the plugins. No source or configuration mutation occurs between checkout and plugin compilation. The OCI
revision and every plugin's `vcs.revision` match the release commit exactly. The external RNS bundle build must use a
clean exact Core archive and a clean bundle source/archive, and must record both archive hashes rather than inheriting
this image-build convention.

## Verification and reviews

Focused contract and integration tests passed with the mandatory runtime experiment across `pluginapi/v1`, config,
localization, LDAP, plugin registry/loader/runtime, policy compiler, HTTP hooks, core auth, and gRPC authority packages.
Retained reproducer-first coverage includes hook authorization order, verified-signer gating, Lua-existing metric reuse,
contract mismatches, shared observations, one host HTTP client span, deterministic country display lookup, atomic reload,
failed reload, config dumps, secret-free LDAP metadata, and the real mixed-source subject callback sequence.

The following gates passed on the exact release commit:

- `GOEXPERIMENT=runtimesecret make guardrails`
- `GOEXPERIMENT=runtimesecret make release-guardrails`
- `git diff --check`
- prompt, policy-document, Vim syntax, OpenAPI, and generated/sync checks
- `govulncheck`: zero called vulnerabilities
- Kubernetes `make validate`, including policy checks, Lua contract tests, Kustomize rendering, and SOPS validation
- all GitHub Guardrails, unit tests, Lua plugin tests, Govulncheck Main Gate, CodeQL, development builds, Production Docker Build, and Release Build

Three explicit review passes completed:

- Functional/API parity: fallback behavior, real callback order, legacy order preservation, generated facts, deterministic helpers, reload semantics, and safe metadata pass.
- Metrics/traces/logging: signer gating, exact Lua/native collector reuse, once-only observations, conflict rejection, one host HTTP client span, bounded labels, and secret redaction pass.
- Configuration/security/operations: compiler validation, discovery, config dumps, restart-only boundaries, live signature verification, immutable images, and shadow-first rollout pass.

The DRY/OOP review moved the cross-source dependency traversal into the focused `subjectschedule.BoundaryGraph` and kept
Lua scheduling, native bridging, and compiler validation as separate responsibilities. One pre-existing follow-up
candidate remains in `server/config/softallow_provider.go`: the BruteForce, Relay, and RBL forwarding methods repeat the
same provider-delegation shape. It is outside this prerequisite lane and does not affect the gate.

## Live rollout evidence

Kubernetes manifest commit: `701fdd57a2a3815bb8de5f122dd5ab03f35cb612`.

Shadow completed first at `2026-07-14T18:22:30Z`: three updated replicas, three ready, three available, zero server
container restarts, exact image ID
`sha256:235cf2eb597d433ae6710b18133f5f0946e421293399cad9d87c9ce10ffeb634`, and exact Core annotation
`76865c77260491dbaf5f512add5c55d9060922d4`. Every replica logged successful `signature_required` verification with
signer `nauthilus-plugin-build-key-2026` and registered all three bundled plugin modules. No ERROR/FATAL entry appeared
in the complete startup window.

Production completed after the shadow gate at `2026-07-14T18:25:01Z`: three updated replicas, three ready, three
available, zero server container restarts, exact image ID
`sha256:436bef3423b0e605fcfee17f9225ce5f692160c38dba6464845bd963dc4ab7a1`, and the same exact Core annotation.
GeoIP, ClickHouse, and HaveIBeenPwned started on every replica, and each replica loaded its GeoIP database. No
ERROR/FATAL entry appeared in the complete startup window.

## Scope and deviations

- No RNS bundle code or bundle/config cutover was introduced.
- Lua deployment scripts and `director.lua` remain untouched.
- No `test_context` behavior, custom Redis pool, or cacheflush parity work was added.
- The task-local scratch contract and ignored prompt pack are absent from every commit, tag, and release diff.
- Beta.49 was not rolled out because its Core lacked the final mixed-source scheduling proof; beta.50 superseded it.
- The first sandboxed `govulncheck` attempt could not resolve `vuln.go.dev`; the identical release gate passed with network access and reported zero called vulnerabilities.
- The first sandboxed Kubernetes validation could not create its temporary Valkey socket; the identical full validation passed outside that restriction.

## Bundle-lane gate

The machine-readable companion is `server/docs/rns_auth_core_api_gate.json`. The gate is ready only when this command
returns success:

```sh
jq -e '.gate.status == "ready" and .gate.prompt_b_allowed == true and
  .release.core_commit == "76865c77260491dbaf5f512add5c55d9060922d4" and
  .requirements.mixed_lua_native_subject_ordering == true and
  .rollout.shadow.ready_replicas == 3 and .rollout.production.ready_replicas == 3' \
  server/docs/rns_auth_core_api_gate.json
```

Handoff verdict: **READY for Prompt B**, subject to building the external bundle from the exact Core commit and contract
hashes above, with clean Core and bundle archives and no later bundle/config cutover assumed by this report.
