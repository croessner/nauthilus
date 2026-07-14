# GeoIP/ASN Reference Plugin

This directory contains a small native Go plugin that demonstrates the Nauthilus `pluginapi/v1` environment source path.
It enriches pre-auth requests from a local JSON fixture or MaxMind `.mmdb` GeoIP/ASN database and emits policy facts
under `plugin.environment.geoip.*`.

Runtime debug output is controlled with `server.log.debug_modules`. The module-level selector `plugin.geoip` is
registered automatically; the plugin currently does not declare additional local debug selectors.

The JSON reference database format is intentionally tiny so tests and examples stay license-free:

```json
{
  "records": [
    {
      "cidr": "203.0.113.0/24",
      "country_iso": "DE",
      "country_name": "Germany",
      "city_name": "Berlin",
      "asn": 64500,
      "asn_org": "Example Access GmbH"
    }
  ]
}
```

Production deployments should point `database_path` at a real MaxMind DB, such as GeoLite2 City or GeoLite2 Country.
When `asn_database_path` points at GeoLite2 ASN, the plugin keeps the location lookup and ASN organization lookup local
without replacing the primary city or country data. ASN routing facts can also be resolved from a local routing-prefix
snapshot that is refreshed by a supervised background job. The test fixture `testdata/geoip-test.mmdb` is deliberately
not a real MaxMind database; it exists only so unit tests can verify `.mmdb` path handling without committing licensed
database contents.

MaxMind databases are read completely during plugin initialization or reload and opened with
`maxminddb.FromBytes`. The request path therefore reads a process-owned memory buffer instead of an mmap-backed file,
avoiding demand paging from the database volume during authentication. Operators should budget approximately the
combined primary and ASN MMDB file sizes per Nauthilus process. A reload temporarily holds the current and replacement
database buffers until the atomic swap completes and the previous readers are released.

## Build

```sh
GOEXPERIMENT=runtimesecret go build -buildmode=plugin -o build/geoip.so .
```

The `build/` directory and local `.so` artifacts are ignored by Git.

## Configuration

The plugin-owned config subtree accepts:

- `database_path`: absolute path to a local JSON fixture or MaxMind `.mmdb` database.
- `database_format`: optional `auto`, `json`, or `mmdb`; `auto` is the default and selects `mmdb` for `.mmdb` paths.
- `asn_database_path`: optional absolute path to a local JSON fixture or MaxMind ASN `.mmdb` database. When set, ASN and
  autonomous-system organization facts are filled from this secondary database without replacing the primary location
  data.
- `asn_database_format`: optional `auto`, `json`, or `mmdb`; `auto` is the default and selects `mmdb` for `.mmdb` paths.
- `refresh_interval`: optional duration for periodic local database reloads, for example `1h`.
- `lookup_timeout`: optional request-time lookup bound, default `50ms`.
- `asn_lookup.enabled`: optional boolean. When true, ASN data is resolved from a local routing-prefix snapshot.
- `asn_lookup.refresh_interval`: optional routing snapshot refresh interval, default `720h` (30 days).
- `asn_lookup.timeout`: optional per-source fetch timeout, default `30s`.
- `asn_lookup.source_urls`: optional list of HTTP(S) routing snapshot sources. Direct `.pfx2as`/`.pfx2as.gz` files and
  CAIDA RouteViews `pfx2as-creation.log` files are supported; when omitted with lookup enabled, the plugin uses the
  CAIDA IPv4 and IPv6 RouteViews creation logs.
- `asn_registry.enabled`: optional boolean. When true, a supervised background job fetches delegated ASN registry data
  from the worldwide RIR feeds to enrich resolved ASNs with allocation metadata.
- `asn_registry.refresh_interval`: optional registry refresh interval, default `720h` (30 days).
- `asn_registry.timeout`: optional per-feed fetch timeout, default `30s`.
- `asn_registry.source_urls`: optional list of HTTP(S) delegated stats feeds. When omitted and
  `asn_registry.enabled` is true, the plugin uses the AfriNIC, APNIC, ARIN, LACNIC, and RIPE NCC extended delegated stats
  feeds.

### Free network privacy intelligence

`privacy_intelligence` is disabled by default. When enabled, it extends this same environment source with local,
immutable evidence about Tor exits, known VPN exits, community VPN exits, public proxies, privacy relays, shared public
egress, and hosting networks. It does not make authentication decisions, and it does not perform network or file I/O
while evaluating a request. Policy remains the only decision authority.

VPN coverage is necessarily incomplete. A negative result means that the address was not present in the configured,
valid snapshots; it is not proof that the client is not using a VPN. Likewise, a hosting or cloud match is only network
classification. Hosting evidence never implies a VPN match and should not be treated as proof of abuse.

The `shared_egress` class is reserved for operator-approved public prefixes known to represent carrier-grade or managed
corporate NAT gateways. The plugin does not infer this class from a complete ASN or organization name because those
signals are too broad to prove address sharing. RFC 6598 `100.64.0.0/10` is provider-internal shared space and normally
is not the public source observed by an Internet-facing Nauthilus deployment.

The complete example in
[server/docs/examples/go_plugin_geoip.yml](../../../server/docs/examples/go_plugin_geoip.yml) shows every config group.
The main settings are:

- `enabled`: enables the optional subsystem; default `false`.
- `lookup_timeout`: bounds the in-memory privacy lookup and may not exceed the parent `lookup_timeout`; default `10ms`.
- `max_snapshot_entries`: bounds entries accepted from one source; default `1000000`.
- `max_download_bytes`: bounds one remote response and persistent-cache load; default 32 MiB.
- `public_log_fields`: emits only the approved bounded central fields for `evaluated` or `stale` lookups; default
  `false`.
- `refresh.cache_dir`: optional absolute directory for atomically written mode-0600 remote-source caches.
- `refresh.max_concurrent_downloads`: shared remote download bound, default `2`, maximum `8`.
- `refresh.startup_jitter`: initial worker jitter, default `30s`.
- `refresh.default_refresh_interval`, `default_min_refresh_interval`, and `default_max_refresh_backoff`: generic source
  defaults of `6h`, `1h`, and `24h`.
- `sources`: official, operator, community, or derived sources. A source configures exactly one absolute `path` or
  credential-free HTTPS `url`. Generic `cidr_list` and `cidr_csv` sources also configure `provider`, `classes`, and
  CSV column/header options where applicable.
- `hosting`: optional derived classification from configured CIDRs, ASNs, and disabled-by-default organization
  patterns. Its confidence is capped at 60.
- `overrides`: operator-owned prefix additions or suppressions with optional expiry. Official evidence can be suppressed
  only with the explicit `suppress_official: true` flag.

Remote sources share one refresh implementation. It uses the host HTTP facade, conditional `ETag` and `Last-Modified`
requests, `Cache-Control` and `Expires` lower bounds, `Retry-After`, bounded jitter, exponential failure backoff,
per-source refresh coalescing, and a global download semaphore. A response is parsed and validated completely before an
atomic snapshot swap. A failed refresh retains the last known good snapshot. A validated persistent cache can satisfy
startup; an expired cache remains usable only as explicitly stale evidence.

Privacy refreshes build their replacement immutable index before a short publication lock, so request lookup continues
against the last complete state during construction. Exact IPv4 and IPv6 addresses use a direct address index, while
broader networks use terminating prefix tries. Database reloads likewise publish a new database owner immediately;
in-flight requests retain a short-lived lease on the previous in-memory readers until their lookup completes.

Tor sources use `kind: tor_exit_list`, `authority: official`, and support complete bare-address lists,
TorDNSEL/CollecTor 1.0 exit records, and bounded Onionoo details responses containing running relays with the `Exit`
flag. The plugin never sends the request client address to Tor. Destination-dependent Tor bulk queries are not built by
this source contract; normalize such data outside Nauthilus or use a complete TorDNSEL, CollecTor, or Onionoo snapshot.

Operator, provider, community, proxy, relay, and hosting feeds can use one of three vendor-independent contracts:

- `kind: normalized_json` for the versioned metadata and entry schema below;
- `kind: cidr_list` for one public prefix per line, with blank lines and `#` comments allowed;
- `kind: cidr_csv` for RFC 4180-style records, using zero-based `cidr_column` and optional `has_header`.

The two generic CIDR formats require configured `provider` and `classes`. Their prefixes are validated, deduplicated,
and losslessly collapsed before class expansion, which avoids retaining source-specific location segmentation when the
classification coverage is identical. For example:

```yaml
- id: official_privacy_relay
  kind: cidr_csv
  authority: official
  url: https://provider.example.invalid/egress-prefixes.csv
  provider: example_relay
  classes:
    - privacy_relay
    - shared_egress
  cidr_column: 0
  has_header: true
  confidence: 100
```

Normalized JSON remains the richer contract when source timestamps and per-entry provider or confidence values are
required:

```json
{
  "schema_version": 1,
  "source": {
    "id": "community_vpn",
    "description": "Operator-approved community VPN snapshot",
    "authority": "community",
    "license": "CC-BY-4.0",
    "license_url": "https://feeds.example.invalid/license",
    "generated_at": "2026-07-11T10:00:00Z",
    "valid_until": "2026-07-12T10:00:00Z"
  },
  "entries": [
    {
      "network": "203.0.113.7/32",
      "classes": ["community_vpn_exit"],
      "provider": "example",
      "confidence": 70
    }
  ]
}
```

Schema version, source ID and authority, timestamps, classes, CIDRs, confidence caps, entry count, and payload size are
validated atomically. Community sources always require `license` and `license_url` in operator config; normalized
community JSON must also contain license metadata.
No third-party data is bundled. Operators must review each feed's current license, attribution, automation terms, and
redistribution limits before enabling it, retain required notices outside public request logs, and remove a source when
its terms are incompatible. No commercial source, including MaxMind GeoIP Anonymous IP, is required.

Lookup state preserves tri-state semantics:

- `evaluated`: one or more valid snapshots were evaluated; explicit false classification facts are meaningful.
- `stale`: data was evaluated but at least one contributing or required source exceeded `max_age`.
- `unavailable`: configured sources have no valid snapshot; no negative classifications are fabricated.
- `no_sources`: there is no usable configured source state.
- `invalid_ip`: the request client address was invalid; classification booleans are omitted.

Public request logs are intentionally narrower than policy facts and exchange values. When enabled, they may contain only
`policy_fact_geoip_privacy_primary_class`, `policy_fact_geoip_privacy_confidence`,
`policy_fact_geoip_privacy_data_stale`, `policy_fact_geoip_is_tor_exit_node`,
`policy_fact_geoip_is_known_vpn_exit`, `policy_fact_geoip_is_public_proxy`, and
`policy_fact_geoip_is_hosting_network`, and `policy_fact_geoip_is_shared_egress`. They are emitted only for `evaluated`
or `stale` state and never include source
IDs, provider names, URLs, license data, override reasons, or raw evidence.

See [server/docs/go_plugins.md](../../../server/docs/go_plugins.md) for operations guidance and
[server/docs/examples/go_plugin_geoip.yml](../../../server/docs/examples/go_plugin_geoip.yml) for a complete loader and
policy example.

## Emitted Facts

- `plugin.environment.geoip.matched`
- `plugin.environment.geoip.country_iso`
- `plugin.environment.geoip.country_name`
- `plugin.environment.geoip.city_name`
- `plugin.environment.geoip.asn`
- `plugin.environment.geoip.asn_org`
- `plugin.environment.geoip.asn_prefix`
- `plugin.environment.geoip.asn_registry`
- `plugin.environment.geoip.asn_country_iso`
- `plugin.environment.geoip.asn_allocated`
- `plugin.environment.geoip.asn_status`
- `plugin.environment.geoip.privacy_lookup_state`
- `plugin.environment.geoip.privacy_detected`
- `plugin.environment.geoip.privacy_classes`
- `plugin.environment.geoip.privacy_primary_class`
- `plugin.environment.geoip.privacy_confidence`
- `plugin.environment.geoip.privacy_source_authorities`
- `plugin.environment.geoip.privacy_data_stale`
- `plugin.environment.geoip.privacy_data_age_seconds`
- `plugin.environment.geoip.is_tor_exit_node`
- `plugin.environment.geoip.is_known_vpn_exit`
- `plugin.environment.geoip.is_community_vpn_exit`
- `plugin.environment.geoip.is_public_proxy`
- `plugin.environment.geoip.is_privacy_relay`
- `plugin.environment.geoip.is_hosting_network`
- `plugin.environment.geoip.is_shared_egress`

The runtime delta is stored at `plugin.exchange.geoip` and contains only JSON-compatible values. Policy facts remain
under `plugin.environment.geoip.*` because policy facts are the decision authority, while runtime exchange is the
plan-local analytics surface for later post-action steps.
The historical Lua `rt` table is not part of the native Go exchange standard; native consumers should use
`plugin.exchange.geoip` and policy facts.

The same privacy suffixes are added to `plugin.exchange.geoip` without replacing location, ASN, or GUID values. The
native ClickHouse plugin consumes the typed exchange values first and compatible policy facts second. Before deploying
plugin artifacts that emit privacy values, apply the additive `geoip_privacy_*` and `geoip_is_*` columns from
`contrib/clickhouse-kubernetes/schema.sql`; see
[the Kubernetes ClickHouse guide](../../clickhouse-kubernetes/README.md) for schema-first ordering and verification SQL.

## Request-Time Tracing

The plugin adds child spans below `geoip.environment.evaluate` so lookup costs can be attributed without exposing
request values:

- `geoip.database.primary.lookup`
- `geoip.asn.routing.lookup`
- `geoip.database.asn.lookup`
- `geoip.asn.registry.lookup`
- `geoip.privacy.lookup`

Each executed child span sets `geoip.lookup.result` to `matched`, `miss`, or `error`. Optional child spans are
absent when their corresponding lookup source is not configured, and a primary database miss ends location enrichment
before the ASN steps.
