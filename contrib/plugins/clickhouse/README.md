# ClickHouse Native Post-Action Plugin

When this plugin is configured as module `clickhouse`, the generation-owned authn catalog exposes its
authentication-shaped post-action only as `authn/plugin.clickhouse.post_action` for explicit Policy selection.

Builds from the stable and debug Dockerfiles bundle this plugin at
`/usr/local/lib/nauthilus/plugins/clickhouse.so`. When `REQUIRE_PLUGIN_SIGNATURE=true`, the image build also writes
`/usr/local/lib/nauthilus/plugins/clickhouse.so.minisig`.

The debug Dockerfile is an image build variant. Runtime debug logs are controlled separately with
`server.log.debug_modules`; this plugin supports `plugin.clickhouse` and the local selector
`plugin.clickhouse.batch`.

```yaml
plugins:
  modules:
    - name: clickhouse
      type: go
      path: /usr/local/lib/nauthilus/plugins/clickhouse.so
      config:
        insert_url: http://clickhouse.auth.svc.cluster.local:8123/?query=INSERT%20INTO%20nauthilus.logins%20FORMAT%20JSONEachRow
        user: ""
        password: ""
        batch_size: 100
        cache_key: clickhouse:batch:logins
        timeout: 10s
        max_response_bytes: 8192
        auth_dedup_ttl: 300s
```

The plugin writes newline-delimited JSONEachRow payloads with the same row field names as the Lua action. It uses the
module-scoped host cache for batching, the host Redis facade for authenticated request deduplication, and the host HTTP
facade for inserts.

The analytics consumer reads standard `plugin.exchange.*` values, standard feature markers, and policy facts to populate
the existing ClickHouse row fields, including `decision_sources`. Canonical `plugin.geoip.*` facts alone populate the
GeoIP location, ASN, and privacy columns; no `plugin.exchange.geoip` value or environment-source execution is required.
The older `plugin.exchange.geoip` and `plugin.environment.geoip.*` shapes remain accepted only as consumer-side
projections of their public plugin API contracts. The historical Lua `rt` table is not part of the native exchange
standard and is not read by the plugin.

The optional `deployment` and `instance` module config fields are serialized into each ClickHouse row so mixed writers
can be separated in analytics. Kubernetes deployments should normally set them from `${NAUTHILUS_ENV}` and
`${NAUTHILUS_RUNTIME_INSTANCE_NAME}`.

`status_msg` is taken from the core request snapshot, which preserves selected policy/failure text and fills terminal
success or authentication-failure defaults before native post-actions run. `client_net` is the brute-force client
network selected by the core brute-force path, with post-action fallback from brute-force policy-report details.
`geoip_guid` is populated only when an input exchange producer supplies that legacy analytics field; the generic GeoIP
provider does not synthesize a request GUID.

Privacy intelligence uses the same typed analytics projection. Valid exchange values take precedence over compatible
canonical or older facts; malformed optional exchange values fall back to facts and do not discard the login row.
Nullable columns preserve unavailable versus explicit `false` or zero, while privacy classes and source authorities are
always emitted as JSON arrays. Privacy evidence is observational and does not add itself to `decision_sources`.

The typed columns are `geoip_privacy_lookup_state`, `geoip_privacy_detected`, `geoip_privacy_classes`,
`geoip_privacy_primary_class`, `geoip_privacy_confidence`, `geoip_privacy_source_authorities`,
`geoip_privacy_data_stale`, `geoip_privacy_data_age_seconds`, `geoip_is_tor_exit_node`,
`geoip_is_known_vpn_exit`, `geoip_is_community_vpn_exit`, `geoip_is_public_proxy`, `geoip_is_privacy_relay`, and
`geoip_is_hosting_network`, and `geoip_is_shared_egress`. Unavailable scalar values remain SQL `NULL`; missing class and
authority lists remain non-null empty arrays. Bounded mapping diagnostics contain only malformed field names and never
raw values.

Apply and verify the additive privacy columns from `contrib/clickhouse-kubernetes/schema.sql` before deploying a plugin
version that emits them. ClickHouse can accept rows from the old plugin after the schema grows, while a new JSONEachRow
writer can fail against an old schema. The Kubernetes ClickHouse README contains the schema and row readback queries.

## Top-Level Policy Boundary

This component does not register `DecisionEffectProvider` and is never exposed to non-authn targets. Top-level `policy`
may select the authn-only effect `authn/plugin.clickhouse.post_action`; the generation-owned adapter preserves the public
`PostActionRequest` snapshot, credentials, and plan-local runtime exchange instead of translating it into the narrower
generic `DecisionEffectRequest`.

The registered `PostActionTarget` remains isolated behind the authentication-shaped generation binding. Adding or
removing the module, changing its name or config, changing its capabilities, or replacing the `.so` artifact requires a
process restart. A Policy reload may select or stop selecting the frozen canonical effect without changing the plugin
object.

Observability is host-integrated: the plugin registers the remote ClickHouse endpoint through
`Host.ConnectionTargets("clickhouse")`, sends inserts through `Host.HTTP("batch")`, and records bounded queue/flush
metrics and spans. Logs, labels, and spans do not include row bodies, raw SQL query strings, usernames, client IPs, or
credentials.

Known parity gaps:

- Authentication-shaped native and Lua post-actions can exchange runtime deltas with later steps in the same detached
  plan. Those deltas do not mutate the already-selected decision, client response, or live request runtime after the
  plan finishes.
- In one Policy obligation list, order `authn/plugin.haveibeenpwnd.post_action` before
  `authn/plugin.clickhouse.post_action` when rows should include `plugin.exchange.haveibeenpwnd.hash_info` as
  `pwnd_info`.
- The Lua read-only ClickHouse query hook is not implemented by this native action plugin.
