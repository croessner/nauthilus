# GeoIP/ASN Reference Plugin

This directory contains a small native Go plugin that demonstrates the Nauthilus `pluginapi/v1` environment source path.
It enriches pre-auth requests from a local JSON fixture or MaxMind `.mmdb` GeoIP/ASN database and emits policy facts
under `plugin.environment.geoip.*`.

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

Production deployments should point `database_path` at a real MaxMind DB, such as GeoLite2 City or GeoLite2 Country. ASN
facts can be resolved through the Rspamd-compatible DNS provider, which returns TXT records such as
`15169 | 8.8.8.0/24 | US | arin |` from zones backed by registry data. The test fixture `testdata/geoip-test.mmdb` is
deliberately not a real MaxMind database; it exists only so unit tests can verify `.mmdb` path handling without
committing licensed database contents.

## Build

```sh
GOEXPERIMENT=runtimesecret go build -buildmode=plugin -o build/geoip.so .
```

The `build/` directory and local `.so` artifacts are ignored by Git.

## Configuration

The plugin-owned config subtree accepts:

- `database_path`: absolute path to a local JSON fixture or MaxMind `.mmdb` database.
- `database_format`: optional `auto`, `json`, or `mmdb`; `auto` is the default and selects `mmdb` for `.mmdb` paths.
- `refresh_interval`: optional duration for periodic local database reloads, for example `1h`.
- `lookup_timeout`: optional request-time lookup bound, default `50ms`.
- `asn_lookup.enabled`: optional boolean. When true, request-time ASN data is resolved through a Rspamd-compatible DNS
  TXT provider.
- `asn_lookup.provider_type`: optional provider type, currently only `rspamd`.
- `asn_lookup.ipv4_zone`: optional IPv4 DNS zone, default `asn.rspamd.com`.
- `asn_lookup.ipv6_zone`: optional IPv6 DNS zone, default `asn6.rspamd.com`.
- `asn_lookup.timeout`: optional per-query DNS timeout, default `1s`.
- `asn_lookup.cache_ttl`: optional positive cache TTL, default `12h`.
- `asn_lookup.negative_cache_ttl`: optional negative cache TTL, default `5m`.
- `asn_registry.enabled`: optional boolean. When true, a supervised background job fetches delegated ASN registry data
  from the worldwide RIR feeds to enrich resolved ASNs with allocation metadata.
- `asn_registry.refresh_interval`: optional registry refresh interval, default `720h` (30 days).
- `asn_registry.timeout`: optional per-feed fetch timeout, default `30s`.
- `asn_registry.source_urls`: optional list of HTTP(S) delegated stats feeds. When omitted and
  `asn_registry.enabled` is true, the plugin uses the AfriNIC, APNIC, ARIN, LACNIC, and RIPE NCC extended delegated stats
  feeds.

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

The runtime delta is stored at `plugin.environment.geoip` and contains only JSON-compatible values.
