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

## Release Image Signing

The stable Docker build can sign bundled native plugins during the image build. The build uses the repo-owned
`nauthilus-plugin-sign` helper and a BuildKit secret so the Ed25519 signing seed is not written into image layers. Stable
release builds set `REQUIRE_PLUGIN_SIGNATURE=true`; when that flag is enabled, the Docker build fails unless the
`NAUTHILUS_PLUGIN_SIGNING_KEY_B64` GitHub Actions secret is available.

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

## Discovery

The loader state exposes machine-readable discovery through `pluginloader.State.Discovery()`. The discovery document is
derived from safe module metadata and registered component descriptors. It includes module status, plugin metadata such as
`Metadata.Description` and `Metadata.DocsURL`, required capabilities, and component descriptors while omitting
plugin-owned `config` values.

## Runtime Services And Boundaries

Nauthilus supplies host-owned facades to loaded plugins after registration and before request-time execution is enabled:
logging, tracing, bounded metrics, Redis command handles with key/script helpers, LDAP queues, host-managed outbound
HTTP, backend-candidate discovery, connection-target observability, deterministic helper functions, and a module-scoped
process cache. These services do not require additional loader config beyond the normal Nauthilus service config and the
module's `plugins.modules[]` entry.

Some Lua helper families intentionally remain plugin-owned in the native contract:

- extra or named Redis pools;
- SMTP and LMTP mail transports;
- raw TCP sockets, dialers, and HAProxy map update clients;
- SQL drivers, Telegram clients, template libraries, and other integration-specific packages.

Plugins that own these dependencies must keep their settings in the module `config` subtree, prefer secret references
such as files over inline credentials, close resources in `Stop`, support `Reconfigure` only when they can swap state
safely, and redact DSNs, passwords, bearer tokens, message bodies, request credentials, raw SQL, and raw transport errors
from logs, metrics, traces, policy facts, and status messages.

`Host.ConnectionTargets(scope)` is observability-only. It lets a plugin register named `host:port` targets for generic
connection visibility, but it does not open sockets or manage plugin-owned network clients.

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
