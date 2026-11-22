# Lua runtimes and bundled callback status

Top-level `policy` is the only production authority for Lua environment sources, subject sources, and actions. A
configured callback is compiled from the candidate's immutable artifact snapshot before that candidate can be
committed. There is no legacy Lua runtime fallback.

## One Lua API for every runtime

Environment sources, subject sources, and actions run with the same Lua API as custom hooks and Lua backends. Since
Nauthilus 4.1.1 the authentication callbacks are no longer limited to a reduced host surface: the 4.0.0 to 4.1.0
releases rejected callbacks that wrote to Redis or the cache, opened outbound connections, used LDAP, DNS, or mail,
created metrics, selected a backend server, or loaded `os`, `io`, and other standard libraries. Every one of those
capabilities is available again.

A callback can use:

- the complete Lua standard library, including `os`, `io`, `debug`, `coroutine`, `load`, `loadstring`, `dofile`, and
  `loadfile`;
- every bundled helper library, for example `json`, `strings`, `base64`, `template`, `tcp`, `http`, `time` with any
  time zone, and `glua_crypto`;
- `nauthilus_redis` with read and write commands, pipelines, scripts, and named pools;
- `nauthilus_cache`, `nauthilus_prometheus` including `create_*_vec`, `nauthilus_brute_force` including custom
  tolerations, `nauthilus_psnet` including `register_connection_target`, and `nauthilus_misc` including
  `wait_random`;
- outbound HTTP through `glua_http`, plus `nauthilus_mail`, `nauthilus_dns`, `nauthilus_soft_whitelist`, and
  `nauthilus_ldap` when an LDAP backend is configured;
- `nauthilus_http_request` and `nauthilus_http_response` in every stage; response headers set by an environment
  source, a subject source, or a synchronous action reach the client, while status and body of an authentication
  response stay with the server;
- `nauthilus_backend` in subject sources, including `get_backend_servers`, `select_backend_server`,
  `get_selected_backend_server`, and `check_backend_connection`;
- dynamic module selection such as `require(name)`.

Three properties of the Nauthilus 4 runtime remain and are not restrictions of the API:

- **Modules come from the candidate snapshot.** `require` resolves host modules and the Lua files captured from the
  configured `package_path` when the configuration was loaded. `package.path` is empty, so a module file that is
  changed or added on disk becomes visible with the next configuration reload, not in the middle of a generation.
  `dofile` and `loadfile` read the file system directly.
- **A post-action has no live response.** POST-Actions run after the response left the server. Their
  `nauthilus_http_response` module keeps every documented function, and each call has no effect.
- **VMs are pooled.** Each callback has its own pool of pre-built VMs. The callback script runs in a fresh request
  environment on top of the VM's base environment: a global variable the script assigns, including its entry
  function, lives only for that request, and the request-bound modules are mapped into that environment. State
  outside the request environment stays in the VM and is visible to later requests of the same callback, as in
  custom hooks and in Nauthilus 3: explicit writes to `_G`, changes to shared tables such as `string`, and globals
  assigned by a module loaded with `require`. Do not keep request data there. A module loaded with `require` is
  compiled once when the configuration is loaded (since 4.1.2) and executed again for every request.

Candidate preparation compiles every configured callback and never executes it. Module-level code therefore runs
only when a request executes the callback. A script is rejected when it does not compile, or when the name of its
entry point (`nauthilus_call_environment`, `nauthilus_call_subject`, or `nauthilus_call_action`) occurs neither in
the script nor in a Lua module captured from the configured `package_path`; that catches a script configured for the
wrong stage. A module name that cannot be resolved fails when the request runs the `require`.

## Bundled authentication callbacks

Every bundled environment source, subject source, and action passes candidate preparation; the test
`TestBundledAuthnCallbacksPrepareAsPolicyProvidersAndEffects` proves it for each file. The status values are:

- `supported`: may be selected by top-level `policy`.
- `supported, native alternative`: may be selected by top-level `policy`; a bundled native Go plugin covers the same
  use case and is the maintained production path.
- `test-only`: retained for the Lua callback test harness; it is not an operator configuration example.

| Callback | Status | Notes |
| --- | --- | --- |
| `actions/analytics.lua` | supported | Records request analytics in the request runtime context. |
| `actions/bruteforce.lua` | supported | Updates an HAProxy map through a TCP target. |
| `actions/bruteforce_header.lua` | supported | Synchronous response action; the header name is fixed in the script. |
| `actions/clickhouse.lua` | supported, native alternative | Outbound HTTP plus Redis and cache writes; native path: `authn/plugin.clickhouse.post_action`. |
| `actions/dynamic_response.lua` | supported | Uses mail, Redis writes and scripts, and environment configuration. |
| `actions/failed_login_tracker.lua` | supported | Uses Redis writes and a pipeline. |
| `actions/haveibeenpwnd.lua` | supported, native alternative | Outbound HTTP, mail, Redis and cache writes; native path: `authn/plugin.haveibeenpwnd.post_action`. |
| `actions/telegram.lua` | supported | Uses an outbound Telegram client and credentials from the environment. |
| `actions/test_context_chain.lua` | test-only | Exercises the callback test harness. |
| `environment/account_longwindow_metrics.lua` | supported | Uses Redis scripts and writes and tuning values from the environment. |
| `environment/blocklist.lua` | supported | Calls an external blocklist service over HTTP. |
| `environment/failed_login_hotspot.lua` | supported | Writes a Redis snapshot gate; pairs with `actions/failed_login_tracker.lua`. |
| `environment/global_pattern_monitoring.lua` | supported | Uses Redis scripts and writes. |
| `environment/security_metrics.lua` | supported | Uses a Redis pipeline and tuning values from the environment. |
| `environment/test_context_chain.lua` | test-only | Exercises the callback test harness. |
| `subject/account_centric_monitoring.lua` | supported | Uses Redis scripts and writes and tuning values from the environment. |
| `subject/account_protection_mode.lua` | supported | Uses Redis and cache writes and sets response headers. |
| `subject/geoip.lua` | supported, native alternative | Outbound HTTP and cache writes; native path: the bundled `geoip` plugin. |
| `subject/idp_policy.lua` | supported | Uses request-local IdP facts and registered policy attributes. |
| `subject/monitoring.lua` | supported | Uses Redis writes and selects the backend server. |
| `subject/soft_delay.lua` | supported | Uses Redis and cache writes and tuning values from the environment. |
| `subject/test_context_chain.lua` | test-only | Exercises the callback test harness. |

## Other checked-in Lua surfaces

The following files are exhaustive for the remaining checked-in Lua tree:

- `backend-runtime`: a Lua backend implementation, activated only by an explicit configured
  `authn/builtin/lua_backend` binding. Mere file presence does not activate it.
- `process-owned`: loaded only by the configured initialization or custom-hook lifecycle. It cannot be selected as a
  Policy provider or effect.
- `candidate-schema`: evaluated only while preparing the candidate schema contribution. A registry script runs with
  the complete Lua standard library; request host modules are not bound because no request exists at that point.
- `shared-library`: a shared module that any runtime loads with `require`.
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
| `share/nauthilus_geoip_bridge.lua` | shared-library | Shared GeoIP bridge. |
| `share/nauthilus_keys.lua` | shared-library | Shared Redis key helper. |
| `share/nauthilus_policy_facts.lua` | shared-library | Shared request-local Policy fact emitter. |
| `share/nauthilus_redis_pool.lua` | shared-library | Shared Redis pool resolver. |
| `share/nauthilus_util.lua` | shared-library | Shared helper functions, including environment lookup. |
| `examples/otel_demo.lua` | standalone-example | Standalone OpenTelemetry API demonstration with no callback entry point. |

The checked-in example configurations are [`examples/policy-safe-idp.yml`](examples/policy-safe-idp.yml) and
[`examples/policy-safe-bruteforce-header.yml`](examples/policy-safe-bruteforce-header.yml). Paths in those repository
fixtures are relative so the test can capture the checked-in bytes; deployments must use the corresponding absolute
paths under their configuration-artifact tree.
