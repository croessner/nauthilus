# Authentication Policy VM compatibility

Top-level `policy` is the only production authority for Lua environment sources, subject sources, and actions. A
configured callback is compiled from the candidate's immutable artifact snapshot and loaded in the stage-specific
Policy VM before that candidate can be committed. There is no legacy Lua runtime fallback.

The Policy VM intentionally exposes a narrow host surface:

- profile-compatible captured Lua modules plus deterministic base, table, string, and math operations;
- request context, request HTTP metadata, CBOR, JSON, crypto, tracing, policy-attribute emission, localized lookup,
  bounded UTC time, and password helpers;
- read-only access to the candidate-injected default Redis handle, brute-force facts, connection-target lookup, and
  bounded cache reads;
- metric updates against host-created collectors;
- backend-result projection for subject sources and HTTP response mutation only for synchronous response actions.

It does not expose environment variables, `os`, `io`, filesystem or dynamic loaders, named Redis pools, Redis writes,
Redis pipelines or scripts, arbitrary backend/LDAP/DNS targets, outbound HTTP, mail, target registration, metric
creation, or detached work. Configuration that loads a script requiring one of those capabilities is rejected before
candidate publication.

The status values below are normative for the checked-in callbacks:

- `supported`: may be selected by top-level `policy`; focused tests prove production decode, validation, and candidate
  preparation for representative callbacks.
- `test-only`: retained for the Lua callback test harness; it is not an operator configuration example.
- `reference-only`: retained as migration or design material. Do not place it in `policy.namespaces.authn`; production
  candidate preparation rejects its unavailable capability. Replace it with a generation-owned builtin or native
  provider/effect before activation.

| Callback | Status | Production boundary |
| --- | --- | --- |
| `actions/analytics.lua` | reference-only | Its legacy callback mutates request runtime context; it has not been promoted as a production Policy example. |
| `actions/bruteforce.lua` | reference-only | Requires an arbitrary TCP/HAProxy target. |
| `actions/bruteforce_header.lua` | supported | Synchronous response action only; the header name is fixed in the captured script and does not use ambient environment state. |
| `actions/clickhouse.lua` | reference-only | Requires outbound HTTP, Redis/cache writes, and legacy ambient configuration; use native `authn/plugin.clickhouse.post_action`. |
| `actions/dynamic_response.lua` | reference-only | Requires mail, Redis writes/scripts, and ambient configuration. |
| `actions/failed_login_tracker.lua` | reference-only | Requires Redis writes and a pipeline. |
| `actions/haveibeenpwnd.lua` | reference-only | Requires outbound HTTP, mail, Redis/cache writes, and ambient configuration; use native `authn/plugin.haveibeenpwnd.post_action`. |
| `actions/telegram.lua` | reference-only | Requires an outbound Telegram client and ambient credentials. |
| `actions/test_context_chain.lua` | test-only | Exercises the callback test harness and legacy diagnostic logging. |
| `environment/account_longwindow_metrics.lua` | reference-only | Requires Redis scripts/writes and ambient tuning values. |
| `environment/blocklist.lua` | reference-only | Requires arbitrary outbound HTTP. |
| `environment/failed_login_hotspot.lua` | reference-only | Requires a Redis write for snapshot gating and ambient tuning values. |
| `environment/global_pattern_monitoring.lua` | reference-only | Requires Redis scripts/writes. |
| `environment/security_metrics.lua` | reference-only | Requires a Redis pipeline and ambient tuning values. |
| `environment/test_context_chain.lua` | test-only | Exercises the callback test harness and legacy diagnostic logging. |
| `subject/account_centric_monitoring.lua` | reference-only | Requires Redis scripts/writes and ambient tuning values. |
| `subject/account_protection_mode.lua` | reference-only | Requires Redis/cache writes and response mutation from the subject stage. |
| `subject/geoip.lua` | reference-only | Requires arbitrary outbound HTTP and cache writes; use the generation-owned native GeoIP provider where applicable. |
| `subject/geoip_reputation.lua` | reference-only | Requires a Redis write pipeline and ambient tuning values. |
| `subject/idp_policy.lua` | supported | Uses request-local IdP facts and registered policy attributes only. |
| `subject/monitoring.lua` | reference-only | Requires Redis writes, a backend target, and ambient configuration. |
| `subject/soft_delay.lua` | reference-only | Requires Redis/cache writes and ambient tuning values. |
| `subject/test_context_chain.lua` | test-only | Exercises the callback test harness and legacy diagnostic logging. |

## Other checked-in Lua surfaces

The following files are exhaustive for the remaining checked-in Lua tree. Their status is separate from the
environment, subject, and action Policy VM profile:

- `backend-runtime`: sealed from candidate-captured artifact bytes and activated only by an explicit configured
  `authn/builtin/lua_backend` binding in the generation-owned catalog. Mere file presence does not activate it, and it
  is not a `lua_environment`, `lua_subject`, or Lua effect script.
- `process-owned`: loaded only by the configured initialization or custom-hook lifecycle. It cannot be selected as a
  Policy provider or effect and does not expand the Policy VM profile.
- `candidate-schema`: evaluated only while preparing the candidate schema contribution.
- `captured-library`: a shared dependency whose complete static source graph remains subject to the owning VM profile.
  A forbidden module or mutable API anywhere in that graph rejects the dependency before execution, even when the
  candidate would not call that function.
- `standalone-example`: documentation-only Lua with no production callback entry point.

| Lua file | Status | Authority boundary |
| --- | --- | --- |
| `backend/backend.lua` | backend-runtime | Lua backend implementation selected through `authn/builtin/lua_backend`. |
| `backend/proxy_backend.lua` | backend-runtime | Lua backend implementation selected through `authn/builtin/lua_backend`. |
| `backend/testing_csv_backend.lua` | backend-runtime | Test backend selected through `authn/builtin/lua_backend`. |
| `hooks/clickhouse-query.lua` | process-owned | Configured custom HTTP hook; not an authentication Policy callback. |
| `hooks/distributed-brute-force-admin.lua` | process-owned | Configured custom HTTP hook; not an authentication Policy callback. |
| `hooks/distributed-brute-force-test.lua` | process-owned | Configured custom HTTP hook; not an authentication Policy callback. |
| `hooks/dovecot-session-cleaner.lua` | process-owned | Configured custom HTTP hook; not an authentication Policy callback. |
| `hooks/dynamic-textmap-demo.lua` | process-owned | Configured custom HTTP hook; not an authentication Policy callback. |
| `hooks/hello-world-request-dump.lua` | process-owned | Configured custom HTTP hook; not an authentication Policy callback. |
| `hooks/http-head-get-demo.lua` | process-owned | Configured custom HTTP hook; not an authentication Policy callback. |
| `init/init.lua` | process-owned | Configured initialization script; not an authentication Policy callback. |
| `init/proxy-init.lua` | process-owned | Configured initialization script; not an authentication Policy callback. |
| `init/testing_csv_loader.lua` | process-owned | Configured test initialization script; not an authentication Policy callback. |
| `policy/registry.lua` | candidate-schema | Registers candidate-owned Lua attributes; it does not execute per request. |
| `share/nauthilus_geoip_bridge.lua` | captured-library | Shared bridge; availability follows the owning VM profile. |
| `share/nauthilus_keys.lua` | captured-library | Shared key helper; its `nauthilus_util` dependency makes it unavailable in Policy VMs. |
| `share/nauthilus_policy_facts.lua` | captured-library | Shared request-local Policy fact emitter. |
| `share/nauthilus_util.lua` | captured-library | Process/backend helper; its environment lookup and cache mutations make the whole module unavailable in Policy VMs. |
| `examples/otel_demo.lua` | standalone-example | Standalone OpenTelemetry API demonstration with no callback entry point. |

The supported examples are [`examples/policy-safe-idp.yml`](examples/policy-safe-idp.yml) and
[`examples/policy-safe-bruteforce-header.yml`](examples/policy-safe-bruteforce-header.yml). Paths in those repository
fixtures are relative so the contract test can seal the checked-in bytes; deployments must use the corresponding
absolute paths under their immutable configuration-artifact tree.
