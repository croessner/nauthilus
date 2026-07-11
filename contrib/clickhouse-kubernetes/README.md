# Nauthilus ClickHouse setup for Kubernetes (namespace: auth)

This contrib package helps you create the ClickHouse database and table required by the Lua action plugin
`server/lua-plugins.d/actions/clickhouse.lua` and the native Go replacement `clickhouse.post_action`.

It assumes a standalone ClickHouse server is running inside your Kubernetes cluster, typically exposed as a Service named `clickhouse` in the `auth` namespace.

## What gets created

- Database: `nauthilus`
- Table: `nauthilus.logins`
  - Column schema: `ts` is `DateTime64(3, 'UTC')`, repeated low-cardinality dimensions use `LowCardinality(String)`, counters use nullable numeric types, and boolean flags use nullable booleans.
  - Engine: `MergeTree` with `ORDER BY (ts)`.

Schema file: `schema.sql`

## Privacy intelligence schema rollout

Apply the additive schema before deploying GeoIP and ClickHouse plugin artifacts that emit `geoip_privacy_*` or
`geoip_is_*` JSONEachRow fields. Existing plugin versions continue to insert rows after the columns are added and the
new columns receive their defaults. Deploying the new writer against an old schema is unsupported because ClickHouse
can reject unknown JSONEachRow fields. The plugin does not perform schema discovery or DDL.

After applying `schema.sql`, verify exact column types:

```sql
SELECT
  name,
  type
FROM system.columns
WHERE database = 'nauthilus'
  AND table = 'logins'
  AND (name LIKE 'geoip_privacy%' OR name LIKE 'geoip_is_%')
ORDER BY name;
```

After deploying the plugin artifacts, read back representative rows:

```sql
SELECT
  ts,
  geoip_privacy_lookup_state,
  geoip_privacy_classes,
  geoip_privacy_primary_class,
  geoip_privacy_confidence,
  geoip_privacy_data_stale,
  geoip_is_tor_exit_node,
  geoip_is_known_vpn_exit,
  geoip_is_public_proxy,
  geoip_is_hosting_network
FROM nauthilus.logins
WHERE ts >= now() - INTERVAL 1 HOUR
ORDER BY ts DESC
LIMIT 50;
```

## Grafana dashboard

The ClickHouse login analytics dashboard is available as:

- `nauthilus-logins-grafana-dashboard.json`

It is built for the official Grafana ClickHouse data source (`grafana-clickhouse-datasource`) and queries `nauthilus.logins` directly. The dashboard includes:

- Executive login KPIs: attempts, success/failure counts, success rate, unique users, unique source IPs, p95 latency, and defense-event volume.
- Outcome and performance trends by time bucket, HTTP status class, protocol, and authentication method.
- Identity and source-risk views for failed identities, source IPs, a country outcome world map, country rankings, known-vs-unknown users, and user agents.
- GeoIP reputation views for reputation decisions over time, score percentiles, hot source IPs, and ASN/country aggregates.
- Network privacy intelligence views for Tor, known/community VPN, public proxy, privacy relay, hosting-network, stale-evidence, and recent attributed-request analytics. Hosting remains separate from VPN evidence.
- Defense-signal views for decision sources, account protection, dynamic response, brute-force buckets, repeat/replay markers, and OIDC/SAML client activity.
- Investigation tables for recent high-risk events and the recent login stream.

Import it through Grafana's dashboard import flow and select the ClickHouse data source that can read the `nauthilus` database when Grafana asks for `ClickHouse datasource`. The selected data source pre-fills the dashboard's data-source variable, which remains visible for later switching. The dashboard exposes filters for service, protocol, method, status message, country, ASN, ASN country, reputation decision, and a ClickHouse-native exclude-identities filter. The exclude filter defaults to `zabbix_mail`; clear it to include every identity. Multiple exact identities can be excluded as a comma-separated list.

The large raw-event tables (`Recent high-risk events` and `Recent login stream`) use server-side ClickHouse pagination through the `Rows/page` and `Table page` variables. Changing those variables changes the SQL `LIMIT` and `OFFSET`, so Grafana only receives the selected slice instead of loading the full result set and paging it in the browser. The aggregated Top-N tables stay capped by their own small `LIMIT` values.

If the dashboard imports but initially shows no rows, check the dashboard variables first. The service, protocol, method, status message, and country variables should start at `All`; selecting unrelated concrete values across those independent filters can produce an empty intersection even when the table contains data.

For a read-only Grafana user, keep the grants limited to `SELECT`, but allow Grafana to adjust the safe query settings used by the ClickHouse data source. `additional_table_filters` is only required if you enable Grafana's generic ad-hoc filters manually:

```sql
ALTER USER grafana_ro SETTINGS
  readonly = 1,
  max_execution_time CHANGEABLE_IN_READONLY,
  additional_table_filters CHANGEABLE_IN_READONLY;
```

Grafana's generic ad-hoc regex operators such as `!~` are intentionally not used by this dashboard because ClickHouse does not support that operator syntax directly. Use the dashboard's `Exclude identities` textbox instead.

## Apply in Kubernetes

A simple ConfigMap + Job is provided to apply the schema using `clickhouse-client`.

- File: `k8s-job.yaml`
- Namespace: `auth` (change if you run ClickHouse elsewhere)

Apply it:

```bash
kubectl -n auth apply -f contrib/clickhouse-kubernetes/k8s-job.yaml
# Wait until the Job completes successfully, then you can delete it if you like
kubectl -n auth delete job nauthilus-clickhouse-init
```

Environment variables inside the Job (adjust in the YAML if needed):
- CLICKHOUSE_HOST: Service DNS of your ClickHouse (default: `clickhouse`)
- CLICKHOUSE_NATIVE_PORT: 9000 (native TCP for clickhouse-client)
- CLICKHOUSE_HTTP_PORT: 8123 (HTTP port; used if protocol is http or as fallback)
- CLICKHOUSE_PROTOCOL: `native` or `http` (default `native`; the job will fall back to HTTP if native is unreachable)
- WAIT_TIMEOUT_SECONDS: how long to wait for readiness (default 180)
- CLICKHOUSE_USER / CLICKHOUSE_PASSWORD: optional (supply via Secret if required)

Notes:
- Some ClickHouse Services expose only HTTP (8123) and not the native TCP (9000). In that case, set `CLICKHOUSE_PROTOCOL=http` or rely on the built-in fallback to HTTP.
- Ensure the `CLICKHOUSE_HOST` matches your actual Service name (for operators it might not be simply `clickhouse`).
- You can change the namespace fields in the YAML to match where your ClickHouse runs.

## Configure Nauthilus native plugin

The bundled Docker images include `/usr/local/lib/nauthilus/plugins/clickhouse.so` and, when signature enforcement is
enabled, `/usr/local/lib/nauthilus/plugins/clickhouse.so.minisig`. Configure the module under `plugins.modules[]` and
reference the native policy effect ID `clickhouse.post_action`.

```yaml
plugins:
  verification_policy: signature_required
  allowed_dirs:
    - /usr/local/lib/nauthilus/plugins
  trust:
    signers:
      - id: nauthilus-plugin-build-key-2026
        format: minisign
        public_key_file: /usr/share/nauthilus/plugin-keys/build-2026.pub
  modules:
    - name: clickhouse
      type: go
      path: /usr/local/lib/nauthilus/plugins/clickhouse.so
      signature: minisign:/usr/local/lib/nauthilus/plugins/clickhouse.so.minisig
      signer: nauthilus-plugin-build-key-2026
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

The native plugin uses host-managed HTTP, Redis, process cache, metrics, traces, and connection-target observability. It
does not implement the optional Lua `clickhouse-query.lua` read-only hook, and native post-actions cannot apply the Lua
`rt.post_clickhouse = true` runtime marker.

Adding or removing the module, changing the module name, or replacing the `.so` artifact requires a Nauthilus process
restart. Config-only changes inside `plugins.modules[].config` can be applied by SIGHUP when validation succeeds.

## Configure Nauthilus Lua plugin

The action plugin batches insert rows to ClickHouse via HTTP. Configure environment variables for your Nauthilus deployment (e.g., in your Deployment manifest):

- CLICKHOUSE_INSERT_URL: full HTTP endpoint including the INSERT and `FORMAT JSONEachRow`. Example:
  `http://clickhouse.auth.svc.cluster.local:8123/?query=INSERT%20INTO%20nauthilus.logins%20FORMAT%20JSONEachRow`
- CLICKHOUSE_USER / CLICKHOUSE_PASSWORD: optional; sent via `X-ClickHouse-User` and `X-ClickHouse-Key` headers if set.
- CLICKHOUSE_BATCH_SIZE: optional (default 100)
- CLICKHOUSE_CACHE_KEY: optional (default `clickhouse:batch:logins`)

Example (Kubernetes container env):
```yaml
env:
  - name: CLICKHOUSE_INSERT_URL
    value: "http://clickhouse.auth.svc.cluster.local:8123/?query=INSERT%20INTO%20nauthilus.logins%20FORMAT%20JSONEachRow"
  - name: CLICKHOUSE_USER
    valueFrom:
      secretKeyRef:
        name: clickhouse-auth
        key: username
  - name: CLICKHOUSE_PASSWORD
    valueFrom:
      secretKeyRef:
        name: clickhouse-auth
        key: password
```

## Optional: Read-only query hook

If you enable `server/lua-plugins.d/hooks/clickhouse-query.lua`, set:
- CLICKHOUSE_SELECT_BASE: e.g. `http://clickhouse.auth.svc.cluster.local:8123`
- CLICKHOUSE_TABLE: `nauthilus.logins` (default)
- CLICKHOUSE_USER / CLICKHOUSE_PASSWORD: optional

Then you can use endpoints like:
- `.../api/v1/custom/clickhouse-query?action=recent&limit=100`
- `.../api/v1/custom/clickhouse-query?action=by_user&username=alice@example.com&limit=100`
- `.../api/v1/custom/clickhouse-query?action=by_ip&ip=203.0.113.10&limit=100`

## Notes

- The timestamp `ts` stored as `String` is ISO8601-like (e.g., `2025-08-26T08:00:00 +02:00`). If you need chronological ordering across timezones in ClickHouse queries, you can `ORDER BY parseDateTimeBestEffort(ts)` or materialize an extra DateTime column.
- The provided Kubernetes Job uses the native client (`clickhouse-client`) with `--multiquery` and a `ConfigMap`-mounted SQL file.


## Image note

This Job now uses the unified image `clickhouse/clickhouse:24.8`, which includes the client binary. If you prefer a different tag:
- Pin to a specific minor/patch (e.g., `clickhouse/clickhouse:24.8.x` or `24.x`).
- Or use the standalone client image (`clickhouse/clickhouse-client:<tag>`) and keep the command lines the same; the manifest’s script auto-detects whether `clickhouse-client` exists and falls back to `clickhouse client`.

Edit `contrib/clickhouse-kubernetes/k8s-job.yaml` and adjust the `image` field under the `apply-schema` container if needed.
