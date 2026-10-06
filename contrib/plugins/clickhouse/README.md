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
        max_buffer_rows: 10000
        flush_interval: 30s
        cache_key: clickhouse:batch:logins
        timeout: 10s
        max_response_bytes: 8192
        dedup_success: true
        dedup_failure: false
        auth_dedup_ttl: 300s
```

The plugin writes newline-delimited JSONEachRow payloads with the same row field names as the Lua action. It uses the
module-scoped host cache for batching, the host Redis facade for configurable login-context deduplication, and the host HTTP
facade for inserts.

## Login Deduplication

`dedup_success` (default `true`) and `dedup_failure` (default `false`) independently enable deduplication for requests
whose `Runtime.Authenticated` flag is true or false. Set both to `false` to retain every login event, or both to `true`
to aggregate successes and failures separately. Both settings reload on SIGHUP. The existing `auth_dedup_ttl`
(default `300s`) applies to either enabled outcome; it is a fixed window starting at the first accepted event, not
extended by skipped repetitions.

The key combines username, client IP, protocol, service, authentication method, client ID, OIDC client projections,
SAML entity ID, OIDC grant, MFA method/completion, authentication and authorization outcomes, HTTP status, and status
message. Different contexts or failure reasons therefore remain separate. Request/session IDs, source ports and timing
are excluded deliberately: equivalent new requests inside the window still aggregate. Missing username or client IP
bypasses deduplication. Credentials and password hashes are never part of this key.

The fields are encoded with unambiguous boundaries and SHA-256 hashed under `clickhouse:authdedup:v2:`, with the host
Redis prefix applied as usual. Older keys are not reused and expire naturally; deployment starts a fresh dedup window.
Redis errors continue to fail open so analytics can proceed. The reservation still happens before buffer admission and
HTTP delivery; it is not a delivery acknowledgement or an exactly-once guarantee.

## Batching and Delivery

The batch lives in the module-scoped host cache, which is process-local memory. It is not stored in Redis and is not
shared between processes: every Nauthilus process or Kubernetes pod collects and flushes its own batch under
`cache_key`. Each process buffers at most `max_buffer_rows` rows (default `10000`), plus at most one in-flight batch of
that size. The limit must be positive; zero selects the default. Lowering it on reload discards excess queued rows.

A batch is flushed when one of the following happens:

- **Size:** the request that makes the local batch reach `batch_size` rows (default `100`), or the lower buffer limit, attempts an inline flush.
- **Interval:** when `flush_interval` is a positive duration such as `30s`, one background worker per process flushes
  the local batch at that interval if it holds any rows. The default `0` (or `0s`) disables the worker and keeps
  size-only batching; negative or unparsable values are rejected at startup. Without the worker, a quiet process can
  hold rows for a long time, so production deployments should set it; during healthy delivery, a row's delay is then roughly
  `flush_interval` plus one insert.
- **Stop:** when the plugin stops, for example during process shutdown or a rollout, it ends the worker and attempts to flush the
  pending batch once if the insert gate permits, bounded by `timeout`. A failed final insert is logged with bounded fields (`result`,
  `trigger`) and does not block shutdown; those rows are lost with the process.

All flush triggers share a nonblocking insert gate: at most one HTTP insert runs per plugin instance. Other
post-actions only enqueue and return, without waiting for that insert. The size-triggering post-action still spends
up to `timeout` on its insert. Failed inserts are requeued subject to the same buffer limit. When the buffer is full,
new arrivals (including requeued rows) are discarded and counted with `result=dropped`; analytics overflow does not
return a post-action error. The limit counts rows, not bytes. It is an in-memory best-effort buffer, not a durable queue.

After a failed insert or a missing `insert_url`, every trigger observes an exponential retry pause: 1, 2, 4, 8, 16, 32,
then at most 60 seconds after completion. Successful delivery resets the pause. Reload preserves the pause. Shutdown
also respects an active pause or insert; it does not start a competing request. A retry occurs on the next eligible
size or interval trigger, so configure `flush_interval` to recover without further authentication traffic.
An interval insert already in progress finishes within `timeout`. Ambiguous transport failures can still cause duplicate
rows if ClickHouse accepted the original batch before the response was lost.

A SIGHUP reload applies a changed `flush_interval`: the plugin stops the running worker and starts one with the new
interval, or stops it for `0s`. An unchanged interval keeps the running worker. Each start or stop is logged as
`clickhouse flush worker updated` with `flush_worker=running` or `flush_worker=stopped`.

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
removing the module, changing its name or capabilities, or replacing the `.so` artifact requires a process restart. A
Policy reload may select or stop selecting the frozen canonical effect without changing the plugin object.

Every key under the module `config` reloads on SIGHUP. The plugin validates the candidate before the reload is
committed, so an invalid value rejects the whole reload and keeps the running settings. After the commit it swaps the
settings atomically, restarts the flush worker only when `flush_interval` changed, and re-registers the connection target.
Rows that are already batched stay queued: after a `cache_key` change they move to the new key, and a changed
`insert_url` or credentials apply to the next flush, including rows queued before the reload.

Observability is host-integrated: the plugin registers the remote ClickHouse endpoint through
`Host.ConnectionTargets("clickhouse")`, sends inserts through `Host.HTTP("batch")`, and records bounded queue/flush
metrics and spans. Logs, labels, and spans do not include row bodies, raw SQL query strings, usernames, client IPs, or
credentials.

## Metrics

The plugin registers these metrics through the host metrics facade, which adds the `nauthilus_plugin_clickhouse_`
prefix and the `plugin_scope` label:

| Metric | Type | `result` values |
|---|---|---|
| `clickhouse_queued_rows_total` | counter | `queued`, `skipped` (no-auth request), `dedup_skipped` (Redis deduplication), `encode_error`, `dropped` (buffer full) |
| `clickhouse_flush_batches_total` | counter | `success`, `http_error`, `status_error`, `no_url`, `requeued` |
| `clickhouse_flush_duration_seconds` | histogram | same as the flush counter |

Every `result` series of both counters exists from startup with value `0`, so `increase()` and `rate()` also see the
first flush after a restart and alerts such as "no successful flush in the last hour" do not misfire after a rollout.
Histogram series appear with their first observation. Because batches are per process, compare flush metrics per pod
or sum them; with `flush_interval` unset, a quiet pod legitimately reports no flush for long periods.

Known parity gaps:

- Authentication-shaped native and Lua post-actions can exchange runtime deltas with later steps in the same detached
  plan. Those deltas do not mutate the already-selected decision, client response, or live request runtime after the
  plan finishes.
- In one Policy obligation list, order `authn/plugin.haveibeenpwnd.post_action` before
  `authn/plugin.clickhouse.post_action` when rows should include `plugin.exchange.haveibeenpwnd.hash_info` as
  `pwnd_info`.
- The Lua read-only ClickHouse query hook is not implemented by this native action plugin.
