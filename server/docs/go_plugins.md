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
derived from module metadata and registered component descriptors, not from `Metadata.Description` or `Metadata.DocsURL`.
It includes module status, plugin metadata, required capabilities, and component descriptors while omitting plugin-owned
`config` values.

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
MaxMind `.mmdb` lookup support, Rspamd-compatible DNS ASN lookups, optional delegated ASN registry metadata refresh,
runtime facts, bounded metrics/traces, and config-only reload. Its example config is available in
`server/docs/examples/go_plugin_geoip.yml`.

GeoIP plugin config highlights:

- `database_path`: absolute path to a JSON fixture or MaxMind `.mmdb` database.
- `database_format`: optional `auto`, `json`, or `mmdb`; `auto` selects `mmdb` for `.mmdb` paths.
- `refresh_interval`: optional local database reload interval.
- `lookup_timeout`: optional request lookup timeout, default `50ms`.
- `asn_lookup.enabled`: opt-in request-time ASN DNS lookup.
- `asn_lookup.provider_type`: optional provider type, currently only `rspamd`.
- `asn_lookup.ipv4_zone`: optional IPv4 DNS zone, default `asn.rspamd.com`.
- `asn_lookup.ipv6_zone`: optional IPv6 DNS zone, default `asn6.rspamd.com`.
- `asn_lookup.timeout`: optional per-query DNS timeout, default `1s`.
- `asn_lookup.cache_ttl`: optional positive cache TTL, default `12h`.
- `asn_lookup.negative_cache_ttl`: optional negative cache TTL, default `5m`.
- `asn_registry.enabled`: opt-in delegated RIR stats refresh for ASN allocation metadata.
- `asn_registry.refresh_interval`: optional registry refresh interval, default `720h` (30 days).
- `asn_registry.timeout`: optional per-feed fetch timeout, default `30s`.
- `asn_registry.source_urls`: optional HTTP(S) delegated stats feeds; when omitted with registry refresh enabled, the
  plugin uses AfriNIC, APNIC, ARIN, LACNIC, and RIPE NCC extended delegated stats feeds.
