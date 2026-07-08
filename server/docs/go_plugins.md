# Native Go Plugins

Nauthilus can load trusted in-process Go plugins built as `.so` artifacts with Go's standard `plugin` package. Plugins
run inside the Nauthilus process, so operators should treat them like privileged server code: pin artifacts with checksums
where practical, keep artifacts in allowlisted directories, and restart the process for loader or artifact changes.

## Build

Build plugins as a `main` package with `-buildmode=plugin` and the same Go toolchain, build tags, module sources, and
shared dependency versions used by the Nauthilus binary:

```sh
GOEXPERIMENT=runtimesecret go build -buildmode=plugin -o build/geoip.so ./contrib/plugins/geoip
```

The plugin must export this factory:

```go
func NauthilusPlugin() (pluginapi.Plugin, error)
```

Nauthilus calls the factory once for each configured module instance, then validates `Metadata().APIVersion` against the
host-supported `pluginapi/v1` value.

## Configuration

Native plugin loader configuration lives at the root-level `plugins` section:

```yaml
plugins:
  verification_policy: when_present
  allowed_dirs:
    - /usr/lib/nauthilus/plugins
  modules:
    - name: geoip
      type: go
      path: /usr/lib/nauthilus/plugins/geoip.so
      checksum: sha256:replace-with-artifact-sha256
      optional: false
      config:
        database_path: /var/lib/nauthilus/geoip.json
```

`name` is the module instance namespace. Registered components become fully qualified names such as
`geoip.environment` or `customer_sql.passdb`. The plugin-owned `config` block is passed to the plugin as a read-only
`ConfigView`; Nauthilus does not interpret or dump it as a shared schema.

`allowed_dirs` must contain absolute directories, and every plugin `path` must be an absolute `.so` path inside one of
those directories after symlink resolution. Module `type` is optional and defaults to `go`; other types are rejected.

## Verification

Verification policy values:

- `off`: no checksum or signature verification.
- `when_present`: verify configured verification metadata, but allow modules without it.
- `checksum_required`: require a valid `sha256:<hex>` checksum on every module.
- `signature_required`: require a valid detached signature and a trusted signer.

SHA-256 checksum verification is implemented and runs before `plugin.Open`.

Detached minisign/signify-style Ed25519 signatures are verified before `plugin.Open`. Nauthilus validates the configured
signature file, signer reference, signer format, signer key ID, and trusted signer public key from either `public_key` or
`public_key_file`. Minisign signatures also verify the trusted-comment signature. Signatures are operational provenance
checks for trusted in-process code; they do not sandbox plugin behavior.

## Bundled Plugins And Release Image Signing

Stable and debug Docker images build these native plugins with the same Go toolchain, module source tree, and build tags
as the server binary:

- `geoip.so`
- `clickhouse.so`
- `haveibeenpwnd.so`

The artifacts are copied into `/usr/local/lib/nauthilus/plugins/` and are world-readable by the unprivileged runtime
user. When `REQUIRE_PLUGIN_SIGNATURE=true`, every bundled plugin is signed during the image build and the detached
`.minisig` files are copied beside the `.so` artifacts with the same runtime-readable mode.

The stable and debug Docker builds can sign bundled native plugins during the image build. The build uses the repo-owned
`nauthilus-plugin-sign` helper and a BuildKit secret so the Ed25519 signing seed is not written into image layers. Stable
release and features/debug image builds set `REQUIRE_PLUGIN_SIGNATURE=true`; when that flag is enabled, the Docker build
fails unless the `NAUTHILUS_PLUGIN_SIGNING_KEY_B64` GitHub Actions secret is available.

Generate the CI signing material once:

```sh
GOEXPERIMENT=runtimesecret go run ./server/pluginloader/cmd/nauthilus-plugin-sign keygen --comment "nauthilus plugin build key 2026"
```

Store the printed `NAUTHILUS_PLUGIN_SIGNING_KEY_B64` value as a GitHub Actions repository secret. The printed public key
is not secret; configure it as a trusted signer and point the module at the bundled detached signature:

```yaml
plugins:
  verification_policy: signature_required
  allowed_dirs:
    - /usr/local/lib/nauthilus/plugins
  trust:
    signers:
      - id: nauthilus-plugin-build-key-2026
        format: minisign
        public_key: |
          untrusted comment: nauthilus plugin build key 2026
          replace-with-generated-public-key-payload
  modules:
    - name: geoip
      type: go
      path: /usr/local/lib/nauthilus/plugins/geoip.so
      signature: minisign:/usr/local/lib/nauthilus/plugins/geoip.so.minisig
      signer: nauthilus-plugin-build-key-2026
```

Repeat the same module signature shape for bundled action plugins, replacing the module name and artifact path with
`clickhouse` or `haveibeenpwnd`.

For multi-architecture images, prefer signature verification for bundled plugins instead of one static SHA-256 checksum:
Go plugin artifacts are architecture-specific, so their checksums differ by platform while the trusted signer stays the
same.

## Capabilities

Plugins declare possible capabilities in metadata and request instance-required capabilities during `Register`.
`credentials` is sensitive and must be explicitly allowed:

```yaml
plugins:
  modules:
    - name: customer_sql
      path: /usr/lib/nauthilus/plugins/customer_sql.so
      allow_capabilities:
        - credentials
```

Request passwords are available only through the request-scoped `CredentialProvider`. Long-lived plugin credentials, such
as SQL DSNs, should be referenced through files or another plugin-owned secret source rather than inline config values.

Host-managed mail is also capability-gated. When a module configuration enables SMTP/LMTP sends through `Host.Mail`, the
module must allow `mail` as well as any other required capability:

```yaml
plugins:
  modules:
    - name: haveibeenpwnd
      path: /usr/lib/nauthilus/plugins/haveibeenpwnd.so
      allow_capabilities:
        - credentials
        - mail
```

## Discovery

The loader state exposes machine-readable discovery through `pluginloader.State.Discovery()`. The discovery document is
derived from safe module metadata and registered component descriptors. It includes module status, plugin metadata such as
`Metadata.Description` and `Metadata.DocsURL`, required capabilities, and component descriptors while omitting
plugin-owned `config` values.

## Runtime Services And Boundaries

Nauthilus supplies host-owned facades to loaded plugins after registration and before request-time execution is enabled:
logging, tracing, bounded metrics, Redis command handles with key/script helpers, LDAP queues, host-managed outbound
HTTP, host-managed SMTP/LMTP mail, backend-candidate discovery, connection-target observability, deterministic helper
functions, and a module-scoped process cache. These services do not require additional loader config beyond the normal
Nauthilus service config and the module's `plugins.modules[]` entry.

Runtime values that are meant for cross-plugin analytics or post-action handoff use the standard `plugin.exchange.*`
keyspace. Bundled native producers write separate top-level keys such as `plugin.exchange.geoip` and
`plugin.exchange.haveibeenpwnd`; ClickHouse consumes those exchange values plus policy facts when building analytics
rows and `decision_sources`. The older `rt` table is historical Lua runtime state. Lua scripts may still write it for
Lua-only compatibility, but `rt` is not the native Go plugin exchange standard and bundled native plugins do not depend
on it.

Some Lua helper families intentionally remain plugin-owned in the native contract:

- extra or named Redis pools;
- raw TCP sockets, dialers, and HAProxy map update clients;
- SQL drivers, Telegram clients, template libraries, and other integration-specific packages.

Plugins that own these dependencies must keep their settings in the module `config` subtree, prefer secret references
such as files over inline credentials, close resources in `Stop`, support `Reconfigure` only when they can swap state
safely, and redact DSNs, passwords, bearer tokens, message bodies, request credentials, raw SQL, and raw transport errors
from logs, metrics, traces, policy facts, and status messages.

`Host.ConnectionTargets(scope)` is observability-only. It lets a plugin register named `host:port` targets for generic
connection visibility, but it does not open sockets or manage plugin-owned network clients.

`Host.Mail(scope)` adapts value-only `pluginapi.MailMessage` requests to the host SMTP/LMTP transport. Plugins still own
message selection, rendering, and plugin-specific config validation; the host owns transport wiring and redacted
operational logs.

## Observability

The runtime emits structured logs for artifact verification, module load and registration, lifecycle start/stop, reload,
request-time calls, errors, and panics. Runtime log and metric labels identify only bounded plugin scope:

- `plugin_module`
- `plugin_component`
- `plugin_extension_point`
- `plugin_method`
- `plugin_result`

Automatic metrics:

- `plugin_calls_total{module,component,extension_point,method,result}`
- `plugin_call_duration_seconds{module,component,extension_point,method,result}`

Automatic spans use the `nauthilus/plugin/runtime` instrumentation scope and attach the same low-cardinality module,
component, extension point, method, and result attributes. The host does not put usernames, client IPs, account names,
tokens, passwords, SQL statements, or raw plugin errors into metric labels or host-created span attributes.

## Reload And Restart

SIGHUP can apply plugin-owned `config` changes only when the plugin implements `pluginapi.ReloadablePlugin`. If
`Reconfigure` returns an error, Nauthilus keeps the previous working plugin config.

These changes require a process restart:

- adding or removing modules
- replacing a `.so` artifact
- changing module `name`, `type`, `path`, `checksum`, `signature`, `signer`, `optional`, `stop_timeout`, or
  `allow_capabilities`
- changing `plugins.verification_policy`
- changing `plugins.allowed_dirs`
- changing `plugins.trust.signers`
- changing API version or loader contract fields

Go plugin code cannot be unloaded or replaced after `plugin.Open`; SIGUSR1 does not attempt restartless code replacement.

## Reference Plugin

The GeoIP/ASN reference plugin in `contrib/plugins/geoip` demonstrates an environment source, init-time database loading,
MaxMind `.mmdb` lookup support, optional secondary MaxMind ASN database lookup, local ASN routing snapshot lookups,
optional delegated ASN registry metadata refresh, runtime facts, bounded metrics/traces, and config-only reload. Its
example config is available in
`server/docs/examples/go_plugin_geoip.yml`.

GeoIP plugin config highlights:

- `database_path`: absolute path to a JSON fixture or MaxMind `.mmdb` database.
- `database_format`: optional `auto`, `json`, or `mmdb`; `auto` selects `mmdb` for `.mmdb` paths.
- `asn_database_path`: optional absolute path to a JSON fixture or MaxMind ASN `.mmdb` database. When set, ASN and
  autonomous-system organization facts are filled from this secondary database while primary location data still comes
  from `database_path`.
- `asn_database_format`: optional `auto`, `json`, or `mmdb`; `auto` selects `mmdb` for `.mmdb` paths.
- `refresh_interval`: optional local database reload interval.
- `lookup_timeout`: optional request lookup timeout, default `50ms`.
- `asn_lookup.enabled`: opt-in local ASN routing snapshot lookup.
- `asn_lookup.refresh_interval`: optional routing snapshot refresh interval, default `720h` (30 days).
- `asn_lookup.timeout`: optional per-source fetch timeout, default `30s`.
- `asn_lookup.source_urls`: optional HTTP(S) routing snapshot sources. Direct `.pfx2as`/`.pfx2as.gz` files and CAIDA
  RouteViews `pfx2as-creation.log` files are supported; when omitted with lookup enabled, the plugin uses the CAIDA IPv4
  and IPv6 RouteViews creation logs.
- `asn_registry.enabled`: opt-in delegated RIR stats refresh for ASN allocation metadata.
- `asn_registry.refresh_interval`: optional registry refresh interval, default `720h` (30 days).
- `asn_registry.timeout`: optional per-feed fetch timeout, default `30s`.
- `asn_registry.source_urls`: optional HTTP(S) delegated stats feeds; when omitted with registry refresh enabled, the
  plugin uses AfriNIC, APNIC, ARIN, LACNIC, and RIPE NCC extended delegated stats feeds.

## Native Action Plugins

Bundled native action plugins register policy effect IDs through the normal native plugin registry. Use these IDs in
policy obligations after the module is configured and loaded:

| Lua action | Native module | Native effect ID | Example |
| --- | --- | --- | --- |
| `actions/clickhouse.lua` | `clickhouse` | `clickhouse.post_action` | `server/docs/examples/go_plugin_clickhouse.yml` |
| `actions/haveibeenpwnd.lua` | `haveibeenpwnd` | `haveibeenpwnd.post_action` | `server/docs/examples/go_plugin_haveibeenpwnd.yml` |

Config highlights:

- ClickHouse uses `insert_url`, optional `user` and `password`, `batch_size`, `cache_key`, `timeout`,
  `max_response_bytes`, and `auth_dedup_ttl`.
- Have I Been Pwned uses `api_base_url`, HTTP/cache/Redis TTL settings, `redis_pool` for Lua config parity, and a `mail`
  block with `enabled`, `use_lmtp`, `server`, `port`, `helo_name`, `tls`, `starttls`, `username`, `password`,
  `mail_from`, `website`, `template_path`, and `subject_template`.
- HIBP requires `allow_capabilities: [credentials]` so it can read the request password through the request-scoped
  credential provider. When `mail.enabled: true`, add `mail` to `allow_capabilities` before restart.
- Empty `mail.template_path` uses the builtin Lua-compatible body template. A custom path is parsed as Go
  `text/template` during registration and `Reconfigure`, is limited to 64 KiB, and rejects the new config on read or
  parse failure. Empty `mail.subject_template` falls back to
  `Password leak detected for your account <{{ .Account }}>`.

Observability:

- Both action plugins use `Host.HTTP(scope)` for outbound HTTP and `Host.ConnectionTargets(scope)` to register redacted
  remote endpoints.
- HIBP mail uses `Host.Mail("haveibeenpwnd")` for SMTP/LMTP sends and records bounded
  `haveibeenpwnd_mail_attempts_total{result}` values such as `disabled`, `gate_skipped`, `template_error`, `send_error`,
  and `sent`.
- Metrics and spans use bounded result labels only; they do not expose usernames, client IPs, account names, passwords,
  SQL query text, raw response bodies, recipients, rendered subjects, rendered bodies, bearer tokens, or raw transport
  errors.

Migration notes:

- Replace policy effects that enqueue `actions/clickhouse.lua` with the native `clickhouse.post_action` effect after the
  `clickhouse` module is configured.
- Replace policy effects that enqueue `actions/haveibeenpwnd.lua` with `haveibeenpwnd.post_action` after the
  `haveibeenpwnd` module is configured and the required capabilities are allowed.
- Adding or removing either module, changing the module name, or replacing the `.so` artifact requires a process restart.
  Changing `allow_capabilities` also requires restart. Config-only changes inside `plugins.modules[].config` can be
  applied by SIGHUP when validation succeeds. Enabling HIBP mail for a module that was registered with
  `mail.enabled: false` requires restart so the plugin can acquire `CapabilityMail`.
- Native and Lua post-actions run inside one detached plan in final-obligation order. A step's
  `PostActionEnqueueResult.RuntimeDelta` is host-validated and visible only to later post-action steps in that same
  plan. Post-action deltas do not mutate the already-selected policy decision, client response, response mutation state,
  or live request runtime after the plan finishes; invalid deltas are rejected with bounded diagnostics.
- Order `haveibeenpwnd.post_action` before `clickhouse.post_action` when ClickHouse rows should include
  `plugin.exchange.haveibeenpwnd.hash_info` as `pwnd_info`. If ClickHouse is ordered first, the row is written without
  that value. The ClickHouse plugin does not read or write `rt`, does not write the Lua `rt.post_clickhouse = true`
  marker back to live request runtime, and the HIBP plugin intentionally does not set the legacy
  `rt.action_haveibeenpwnd = true` marker.
- HIBP SMTP/LMTP notification is supported through the host mail facade. Mail is attempted only after a fresh positive
  HIBP HTTP lookup, after the positive Redis count is written. The native plugin deliberately does not run the Lua
  `nauthilus_send_mail_hash` script because that script returns `send_email` while `haveibeenpwnd.lua` checks
  `send_mail`; native duplicate suppression uses a direct Redis `HSETNX` on the `send_mail` hash field instead.
