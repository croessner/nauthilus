# Nauthilus ClickHouse setup for Kubernetes (namespace: auth)

This contrib package helps you create the ClickHouse database and table required by the Lua action plugin `server/lua-plugins.d/actions/clickhouse.lua`.

It assumes a standalone ClickHouse server is running inside your Kubernetes cluster, typically exposed as a Service named `clickhouse` in the `auth` namespace.

## What gets created

- Database: `nauthilus`
- Table: `nauthilus.failed_logins`
  - Column schema: all fields are `String` for schema stability and match exactly what the Lua plugin inserts via `FORMAT JSONEachRow`.
  - Engine: `MergeTree` with `ORDER BY (ts)`.

Schema file: `schema.sql`

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

## Configure Nauthilus Lua plugin

The action plugin batches insert rows to ClickHouse via HTTP. Configure environment variables for your Nauthilus deployment (e.g., in your Deployment manifest):

- CLICKHOUSE_INSERT_URL: full HTTP endpoint including the INSERT and `FORMAT JSONEachRow`. Example:
  `http://clickhouse.auth.svc.cluster.local:8123/?query=INSERT%20INTO%20nauthilus.failed_logins%20FORMAT%20JSONEachRow`
- CLICKHOUSE_USER / CLICKHOUSE_PASSWORD: optional; sent via `X-ClickHouse-User` and `X-ClickHouse-Key` headers if set.
- CLICKHOUSE_BATCH_SIZE: optional (default 100)
- CLICKHOUSE_CACHE_KEY: optional (default `clickhouse:batch:failed_logins`)

Example (Kubernetes container env):
```yaml
env:
  - name: CLICKHOUSE_INSERT_URL
    value: "http://clickhouse.auth.svc.cluster.local:8123/?query=INSERT%20INTO%20nauthilus.failed_logins%20FORMAT%20JSONEachRow"
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
- CLICKHOUSE_TABLE: `nauthilus.failed_logins` (default)
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
