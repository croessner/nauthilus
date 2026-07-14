# RNS authentication bundle Core/API prerequisite current/target report

Date: 2026-07-14

Core release commit: `3705e407b39399c4c5b3023bf6c2e555b0a8c480`

Beta tag: `v3.1.0-beta.48`

Gate status: **READY**

The Core/API prerequisite lane is complete and live. The subsequent bundle lane may start only from the exact released
Core commit and contract hashes recorded below. This lane did not implement or activate the RNS authentication bundle.

## Requirement status

| Required Core/API capability | Ist | Soll and evidence |
| --- | --- | --- |
| Operator-owned hook scopes | Complete | `HookDescriptor.RequiredScopes` is configured by the operator, normalized, de-duplicated, defensively copied, conflict checked, and authorized with the existing any-of semantics before request construction or plugin execution. Empty lists retain the established Scope/Auth fallback. Effective scopes are visible in non-secret config and discovery diagnostics. |
| Native environment execution facts | Complete | The policy compiler generates `auth.plugin.environment.<module>.<component>.{triggered,abort,error}` from registered components. Snapshot tests cover exact definitions, producer checks, operations, details, and rejection of invalid references. |
| Exact legacy metric compatibility | Complete | A signer-gated, module-scoped compatibility facade accepts only exact operator allowlists for metric name, type, help, labels, and buckets. It does not expose a Prometheus registerer. Native metrics remain supplemental, with conflict and double-counting coverage. |
| Narrow trace compatibility | Complete | The value-only tracing facade supports approved compatibility scopes, typed span kinds, and explicit status/error semantics without exposing OpenTelemetry providers. Host HTTP owns exactly one `plugin.http` client span; plugin code must not add a second client span around host HTTP, LDAP, Redis, or mail operations. |
| Declarative initialization | Complete | Operator configuration owns translation catalogs under `auth.policy.localization.catalogs` and the existing brute-force and relay-domain soft allowlists. Catalog reload is atomic, preserves Lua overlays, and has validation, failed-reload, config-dump, and precedence coverage. Allowlists are normalized, de-duplicated, validated, and defensively copied. |
| Safe LDAP endpoint metadata | Complete | `pluginapi/v1` exposes value-only LDAP endpoint metadata containing only pool name, scheme, host, and port. URI userinfo, base DN, query data, TLS material, and credentials are excluded. A shared parser also removes the prior trace-userinfo risk. |
| Public API boundary | Complete | Import-boundary tests keep `pluginapi/v1` free of Gin, raw Prometheus registerers, raw OpenTelemetry providers, raw Viper, and server internals. |
| Operator and developer surfaces | Complete | Public API, operator, developer, working-draft, examples, schema, syntax, discovery, and config-dump documentation were updated and generated checks pass. |

## Contract hashes

The hashes are calculated from Git blob identifiers plus sorted paths at the release commit, which makes them
reproducible without timestamps or working-tree state.

| Contract | Value |
| --- | --- |
| `pluginapi/v1` Git tree object | `db833dc040c96db6ce5ae70b54dc422fc5808608` |
| Non-test `pluginapi/v1` source manifest SHA-256 | `609217feb6048bbb0ce8c6cf8b2d55b9d12e4fe351272fe9a6a436521b99b49f` |
| Public plugin documentation manifest SHA-256 | `01c7e78d575232a1779bc66a1209aa69b5c2f43ff86aed735bc9f8b5ab58b421` |
| API, config, and discovery operator contract SHA-256 | `342191eac56162cac2ea9204a955205c030615bc380a05a3ff5a2db06e53b862` |

Reproduction commands:

```sh
git rev-parse 3705e407b39399c4c5b3023bf6c2e555b0a8c480:pluginapi/v1
git ls-tree -r 3705e407b39399c4c5b3023bf6c2e555b0a8c480 pluginapi/v1 \
  | awk '$4 !~ /_test[.]go$/ {print $3 " " $4}' | shasum -a 256
git ls-tree -r 3705e407b39399c4c5b3023bf6c2e555b0a8c480 \
  server/docs/go_plugins.md server/docs/go_plugin_developer_api.md server/docs/go_plugin_api_working_draft.md \
  | awk '{print $3 " " $4}' | shasum -a 256
git ls-tree -r 3705e407b39399c4c5b3023bf6c2e555b0a8c480 \
  pluginapi/v1 server/config/schema_v2.go server/config/plugins.go server/pluginloader/discovery.go \
  | awk '$4 !~ /_test[.]go$/ {print $3 " " $4}' | shasum -a 256
```

## Release image and plugin ABI provenance

Production image:
`ghcr.io/croessner/nauthilus:v3.1.0-beta.48@sha256:52e60eebcb265b3b7ee3f255e7ce60fb8c0ff8e5b732ef65c3ff67af1b498573`

Shadow image:
`ghcr.io/croessner/nauthilus:dev-dbg@sha256:a03e3dba341d8aa302742b7017807efbb57e9148a5f76b96d3d3df626b1f6a86`

Both multi-architecture builds came from `3705e407b39399c4c5b3023bf6c2e555b0a8c480`. Production OCI labels record
`org.opencontainers.image.revision`, `org.opencontainers.image.version=v3.1.0-beta.48`, the exact Go and Alpine base
image digests, and `io.nauthilus.build.reason=tag-push` on both amd64 and arm64 manifests.

The server and bundled plugins use Go `1.26.5`, `GOEXPERIMENT=runtimesecret`, `CGO_ENABLED=1`, the `netgo` tag, and
`-trimpath`. Plugins additionally record `-buildmode=plugin`, `GOOS=linux`, the target architecture, the exact VCS
revision, and the same source timestamp. The runtime API is `nauthilus.plugin.v1`; GeoIP, ClickHouse, and
HaveIBeenPwned each register plugin version `0.1.0`.

The production arm64 plugin artifact SHA-256 values are:

| Plugin | `.so` SHA-256 | `.minisig` SHA-256 |
| --- | --- | --- |
| GeoIP | `0c0a90efd85b780f750e6876eb5adf6b475d3e950444479df7f4a903c1c70946` | `c0ffea83234f941551b62f68346a354c33c0b89e2b9c4f38b9ce544d9a9f8ba8` |
| ClickHouse | `39fdd9d8b4de76973d214f5ac275c5bc0e776ee873a933ee8205d209cde5cdfa` | `5c7df662c26cfc5e19550ba102763ef0627a9bfd28d5344a4fc7e76eb3806a46` |
| HaveIBeenPwned | `db69e019ae8a17eda98fafaf5514d16124059f1999db8e5d6724eb86f3dcce61` | `e3ce36339646252f42d1792b9301f9a97fd9074804a5146ba7b1ff24e1fb41df` |

Go build information reports `vcs.modified=true` for bundled plugins. This is an explainable image-build artifact, not
a source or ABI mismatch: after a clean checkout, the Dockerfile writes and compresses only the untracked server binary
at `server/nauthilus` before compiling the plugins. No source or configuration mutation occurs between checkout and
plugin compilation. The OCI revision and every plugin's `vcs.revision` still match the release commit exactly. The
external RNS bundle build must use a clean exact Core archive and a clean bundle source/archive, and must record both
archive hashes rather than inheriting this image-build convention.

## Verification and reviews

Focused contract and integration tests passed with the mandatory runtime experiment across `pluginapi/v1`, config,
localization, LDAP, plugin registry/loader/runtime, policy compiler, HTTP hooks, core auth, and gRPC authority packages.
The retained tests include reproducer-first coverage for authorization order, verified-signer gating, compatibility
conflicts, double counting, single host HTTP instrumentation, atomic reload, failed reload, config dumps, current config
snapshots, and secret-free LDAP metadata.

The following gates passed on the exact release commit:

- `GOEXPERIMENT=runtimesecret make guardrails`
- `GOEXPERIMENT=runtimesecret make release-guardrails`
- `git diff --check`
- prompt, policy-document, Vim syntax, OpenAPI, and other generated/sync checks
- `govulncheck`: zero called vulnerabilities
- Kubernetes `make validate`, including policy checks, Lua contract tests, Kustomize rendering, and SOPS validation
- GitHub Guardrails, unit tests, Lua plugin tests, Govulncheck Main Gate, CodeQL, Development Docker Build, Production Docker Build, and Release Build

Three explicit review passes completed:

- Functional/API parity: hook fallback and authorization order, generated facts, reload semantics, and safe metadata pass.
- Metrics/traces/logging: signer gating, exact/native once-only publication, conflicts, one host HTTP span, bounded labels, and secret redaction pass.
- Configuration/security/operations: validation, discovery, config dumps, restart-only boundaries, live signature verification, immutable images, and shadow-first rollout pass.

The DRY/OOP review consolidated compatibility metric construction, HTTP/mail facade construction, plugin identity logic,
and LDAP endpoint parsing. One pre-existing follow-up candidate remains in `server/config/softallow_provider.go`: the
BruteForce, Relay, and RBL forwarding methods repeat the same provider delegation shape. It is outside this prerequisite
lane and does not affect the gate.

## Live rollout evidence

Kubernetes manifest commit: `192fc7a2c45511b389727a785e8148b3a4e15b05`.

Shadow completed first at `2026-07-14T16:23:27Z`: three updated replicas, three ready, three available, zero server
container restarts, and exact image ID
`sha256:a03e3dba341d8aa302742b7017807efbb57e9148a5f76b96d3d3df626b1f6a86`. Every replica logged successful
`signature_required` verification with signer `nauthilus-plugin-build-key-2026` and registered all three bundled plugin
modules. No ERROR/FATAL, panic, signature, plugin-load, or ABI failure appeared in the complete startup window.

Production completed after the shadow gate at `2026-07-14T16:26:29Z`: three updated replicas, three ready, three
available, zero server container restarts, and exact image ID
`sha256:52e60eebcb265b3b7ee3f255e7ce60fb8c0ff8e5b732ef65c3ff67af1b498573`. Required signed-plugin startup succeeded;
GeoIP databases and ASN snapshots loaded on all three nodes, and ClickHouse post-actions completed successfully. No
ERROR/FATAL, panic, signature, plugin-load, or ABI failure appeared in the complete startup window.

## Scope and deviations

- No RNS bundle code or bundle/config cutover was introduced.
- Lua deployment scripts remain untouched.
- `director.lua` remains untouched.
- No `test_context` behavior, custom Redis pool, or cacheflush parity work was added.
- The task-local scratch contract and ignored prompt pack are absent from every commit, tag, and release diff.
- The first sandboxed `govulncheck` attempt could not resolve `vuln.go.dev`; the identical release gate passed with network access and reported zero called vulnerabilities.
- A generated OpenAPI check failed once only while competing parallel checks disabled module lookup; the required sequential generated check and both full guardrail runs passed.

## Bundle-lane gate

The machine-readable companion is `server/docs/rns_auth_core_api_gate.json`. The gate is ready only when this command
returns success:

```sh
jq -e '.gate.status == "ready" and .gate.prompt_b_allowed == true and
  .release.core_commit == "3705e407b39399c4c5b3023bf6c2e555b0a8c480" and
  .rollout.shadow.ready_replicas == 3 and .rollout.production.ready_replicas == 3' \
  server/docs/rns_auth_core_api_gate.json
```

Handoff verdict: **READY for Prompt B**, subject to building the external bundle from the exact Core commit and contract
hashes above, with clean Core and bundle archives and no later bundle/config cutover assumed by this report.
