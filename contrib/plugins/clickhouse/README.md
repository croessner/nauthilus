# ClickHouse Native Post-Action Plugin

This plugin replaces `server/lua-plugins.d/actions/clickhouse.lua` with the native effect
`clickhouse.post_action` when the module is configured as `clickhouse`.

Builds from the stable and debug Dockerfiles bundle this plugin at
`/usr/local/lib/nauthilus/plugins/clickhouse.so`. When `REQUIRE_PLUGIN_SIGNATURE=true`, the image build also writes
`/usr/local/lib/nauthilus/plugins/clickhouse.so.minisig`.

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

Input runtime exchange values use the native Go standard `plugin.exchange.*` keyspace. The plugin reads
`plugin.exchange.geoip`, `plugin.exchange.haveibeenpwnd`, standard feature markers, and policy facts to populate the
existing ClickHouse row fields, including `decision_sources`. The historical Lua `rt` table is not part of this native
exchange standard and is not read by the plugin.

Policy migration:

```yaml
then:
  obligations:
    - id: clickhouse.post_action
```

Use this native effect ID instead of a Lua action dispatch to `clickhouse.lua` after the module is configured. Adding or
removing the module, changing the module name, or replacing the `.so` artifact requires a process restart. Config-only
changes inside `plugins.modules[].config` can be applied by SIGHUP when validation succeeds.

Observability is host-integrated: the plugin registers the remote ClickHouse endpoint through
`Host.ConnectionTargets("clickhouse")`, sends inserts through `Host.HTTP("clickhouse")`, and records bounded queue/flush
metrics and spans. Logs, labels, and spans do not include row bodies, raw SQL query strings, usernames, client IPs, or
credentials.

Known parity gaps:

- Native and Lua post-actions can exchange runtime deltas with later steps in the same detached plan. Those deltas do
  not mutate the already-selected policy decision, client response, or live request runtime after the plan finishes.
- Order `haveibeenpwnd.post_action` before `clickhouse.post_action` when ClickHouse rows should include
  `plugin.exchange.haveibeenpwnd.hash_info` as `pwnd_info`.
- The Lua read-only ClickHouse query hook is not implemented by this native action plugin.
