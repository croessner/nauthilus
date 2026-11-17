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
        max_brute_force_reject_rows: 5000
        flush_interval: 30s
        cache_key: clickhouse:batch:logins
        timeout: 10s
        max_response_bytes: 8192
        dedup_success: true
        dedup_failure: false
        auth_dedup_ttl: 300s
        # Optional step-event stream (second-factor verifications, OIDC code issuance and redemption) into
        # nauthilus.auth_events.
        events_insert_url: http://clickhouse.auth.svc.cluster.local:8123/?query=INSERT%20INTO%20nauthilus.auth_events%20FORMAT%20JSONEachRow
        events_cache_key: clickhouse:batch:auth_events
        events_flush_interval: 10s
```

The stored data, its NULL/default semantics, the terminal outcome, the step events, and the version and migration
rules are defined in [DIAGNOSTIC_CONTRACT.md](DIAGNOSTIC_CONTRACT.md). Rows written under that contract carry
`contract_version = 1`; older rows read `0`.

The plugin writes newline-delimited JSONEachRow payloads with the same row field names as the Lua action. It uses the
module-scoped host cache for batching, the host Redis facade for configurable login-context deduplication, and the host HTTP
facade for inserts.

## Login Deduplication

`dedup_success` (default `true`) and `dedup_failure` (default `false`) independently enable deduplication for requests
whose host-sealed terminal outcome (`PostActionRequest.Outcome`) is `ok` or `fail`. Temporary failures and unknown
outcomes are never deduplicated, because they are diagnostic evidence. Set both to `false` to retain every login event, or both to `true`
to aggregate successes and failures separately. Both settings reload on SIGHUP. The existing `auth_dedup_ttl`
(default `300s`) applies to either enabled outcome; it is a fixed window starting at the first accepted event, not
extended by skipped repetitions.

The key combines username, client IP, protocol, service, authentication method, client ID, OIDC client projections,
SAML entity ID, OIDC grant, MFA method/completion, authentication and authorization outcomes, HTTP status, and status
message, the terminal outcome with its Policy operation, outcome marker, response marker, and presenting rule, and the
IdP flow reference. Different contexts or failure reasons therefore remain separate, and the password row of every IdP
browser flow is kept so that its step events can be joined. Request/session IDs, source ports and timing
are excluded deliberately: equivalent new requests inside the window still aggregate. Missing username or client IP
bypasses deduplication. Credentials and password hashes are never part of this key.

The fields are encoded with unambiguous boundaries and SHA-256 hashed under `clickhouse:authdedup:v3:`, with the host
Redis prefix applied as usual. Older keys are not reused and expire naturally; deployment starts a fresh dedup window.
Redis errors continue to fail open so analytics can proceed. The reservation still happens before buffer admission and
HTTP delivery; it is not a delivery acknowledgement or an exactly-once guarantee.

## Batching and Delivery

The batch lives in the module-scoped host cache, which is process-local memory. It is not stored in Redis and is not
shared between processes: every Nauthilus process or Kubernetes pod collects and flushes its own batch under
`cache_key`. Each process buffers at most `max_buffer_rows` rows (default `10000`), plus at most one in-flight batch of
that size. The limit must be positive; zero selects the default. Lowering it on reload discards excess queued rows.

Rows of requests rejected because of an active brute-force ban (outcome marker `auth.outcome.brute_force_reject`) may
fill at most `max_brute_force_reject_rows` of that buffer (default: half of `max_buffer_rows`, at least one). The rest
stays reserved for other login rows, so an attack against a banned network cannot crowd out successes and ordinary
failures while ClickHouse is slow or unavailable. The share must be smaller than `max_buffer_rows`; only a one-row
buffer, which cannot reserve anything, keeps a share of one. Reject rows beyond it
are dropped and counted with `result=dropped_reject_limit`; the share is recounted when failed batches are requeued or
moved on reload. Every ban hit is also recorded in the separate `bruteforce_attempts` stream.

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

`decision_sources` also lists the host-owned built-in controls: `tls_encryption` when a request arrived without TLS
context outside the cleartext networks, `relay_domains` when the login name carries a domain part that is not a
configured relay domain, `rbl` when the RBL threshold was reached, and `brute_force` when a brute-force bucket
triggered. The host publishes them as the standard `plugin.exchange.feature.<name>` markers, so other exchange
consumers see them too. Like the Lua builtin set, a marker records that the control fired, even when a configured
policy still lets the request continue; allowlisted, soft-allowlisted, tolerated, skipped, or failed checks publish no
marker. A login name without domain part or with a configured domain never publishes `relay_domains`.

A brute-force bucket can be over its limit while a toleration policy suppresses the block. Such rows keep
`brute_force_bucket`, carry no `brute_force` source, and set `brute_force_tolerated = true`.

`decision_sources` keeps explicit exchange entries first, then feature markers in the standard order (`blocklist`,
`tls_encryption`, `relay_domains`, `rbl`, `brute_force`, …), then sources derived from exchange maps and policy facts. The order can differ from rows written by
the retired Lua action, so query membership instead of exact strings, for example
`has(splitByChar(',', decision_sources), 'rbl')`.

`rbl_lists` (`Array(LowCardinality(String))`) records every configured RBL list that listed the client IP, in
configuration order and also below the RBL threshold, from `RequestSnapshot.Diagnostics.RBLMatchedLists`. Requests
without RBL matches write an empty array. Existing tables need the repeatable
`ALTER TABLE ... ADD COLUMN IF NOT EXISTS rbl_lists` statement from `contrib/clickhouse-kubernetes/schema.sql`.

`status_msg` and `http_status` describe the answered terminal result. Native post-actions are prepared while Policy
selects their effect, before the response is finalized, so the host binds the sealed terminal outcome when the
post-action executes after the response boundary (`PostActionRequest.Outcome`) and refreshes the snapshot diagnostics
from it. A TLS-required or backend temporary failure therefore reads `outcome = 'tempfail'`, `http_status = 500` and
its tempfail text instead of a credential failure. `transport_status` holds the committed HTTP status separately,
because header and nginx modes answer rejections with HTTP 200. `client_net` is the brute-force client
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

Apply and verify the additive columns from `contrib/clickhouse-kubernetes/migrations/diagnostic-contract.sql` (and the
earlier ALTER statements in `contrib/clickhouse-kubernetes/schema.sql`) before deploying a plugin version that emits
them. ClickHouse accepts rows from the old plugin after the schema grows. A new JSONEachRow writer against an old schema
is accepted too, but ClickHouse drops the unknown fields silently (`input_format_skip_unknown_fields = 1` is the
default); append `&input_format_skip_unknown_fields=0` to the insert URLs after the migration to turn future schema
drift into visible insert errors. The Kubernetes ClickHouse README contains the schema and row readback queries.

Reputation assessments published by the native reputation plugin as decision records are projected into
`reputation_assessments` (one named tuple per fact and subject, NULL measurements for `not_found` and `unavailable`,
at most 64 tuples). When the host dropped record facts to keep the post-action within its work bounds, or the plugin
reached the tuple cap, `reputation_truncated` is `true`. The plugin no longer exports the ten flat legacy
`reputation_*` columns of the removed GeoIP reputation map, nor `gp_*`, `prot_*`, and `dyn_*`; rows still insert into
tables that keep these columns. Fresh tables from `contrib/clickhouse-kubernetes/schema.sql` omit them, and the marked
`retire-legacy-columns` block of that file drops them from existing tables as a separate, approved step (see
`DIAGNOSTIC_CONTRACT.md` section 9).

## Step Events

With `events_insert_url` set, the plugin also registers a host step-event sink and writes second-factor verification
events (TOTP, recovery codes, WebAuthn) and OIDC authorization-code completion events (code issuance to the browser,
code redemption at the token endpoint) into `nauthilus.auth_events`: one row per observed step with result, stable
reason, flow effect, fail-latched state, and the non-authorizing `flow_ref` that joins the password row of the same
IdP flow. The completion events need no schema change (`DIAGNOSTIC_CONTRACT.md` section 7.6). The host delivers
second-factor and completion events from two separate bounded queues (1024 events each per process), so a burst of
silent SSO renewals never evicts second-factor evidence; a full queue drops events and counts them in
`nauthilus_plugin_auth_events_total{outcome="dropped",lane="mfa|oidc_completion"}`. The plugin buffers all step events
in one stream (`max_buffer_rows`) and flushes them every `events_flush_interval` (default `10s`, must be positive);
events never flush inline and are never deduplicated. The event payload never contains credentials, OTPs, recovery
codes, authorization codes, PKCE verifiers, tokens, cookies, handles, or WebAuthn data.

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

## Brute-Force Evidence

With `bruteforce_lifecycle_insert_url` and/or `bruteforce_attempts_insert_url` set, the plugin registers a host
brute-force event sink. Ban activations, unconfirmed activations, administrative releases, and counter resets go to
`nauthilus.bruteforce_lifecycle` (400 days, no claimed login names and no client address). Counted increments, tolerated thresholds, and ban
hits go to `nauthilus.bruteforce_attempts` (14 days, raw) with an hourly materialized summary
(`nauthilus.bruteforce_attempt_summary`, 400 days, distinct-name counts as HLL states). Each kind uses its own bounded
host lane and plugin stream buffer. Counted and hit streams flush inline from their host lane goroutine once a stream
holds `batch_size` rows, within the host delivery deadline; failed rows stay for the ticker worker, and
`bruteforce_flush_interval` (default `10s`) flushes quiet streams. Apply
`contrib/clickhouse-kubernetes/migrations/bruteforce-evidence.sql` first. The data contract, attribution rules, and
completeness proof are in [DIAGNOSTIC_CONTRACT.md](DIAGNOSTIC_CONTRACT.md) section 13.

```yaml
        bruteforce_lifecycle_insert_url: http://clickhouse.auth.svc.cluster.local:8123/?query=INSERT%20INTO%20nauthilus.bruteforce_lifecycle%20FORMAT%20JSONEachRow
        bruteforce_attempts_insert_url: http://clickhouse.auth.svc.cluster.local:8123/?query=INSERT%20INTO%20nauthilus.bruteforce_attempts%20FORMAT%20JSONEachRow
        bruteforce_flush_interval: 10s
```

## Metrics

The plugin registers these metrics through the host metrics facade, which adds the `nauthilus_plugin_clickhouse_`
prefix and the `plugin_scope` label:

| Metric | Type | `result` values |
|---|---|---|
| `clickhouse_queued_rows_total` | counter | `queued`, `skipped` (no-auth request), `dedup_skipped` (Redis deduplication), `encode_error`, `dropped` (buffer full) |
| `clickhouse_flush_batches_total` | counter | `success`, `http_error`, `status_error`, `no_url`, `requeued` |
| `clickhouse_flush_duration_seconds` | histogram | same as the flush counter |
| `clickhouse_event_queued_rows_total` | counter | step-event stream: `queued`, `skipped` (no `events_insert_url`), `encode_error`, `dropped` |
| `clickhouse_event_flush_batches_total` | counter | step-event stream flush results, same values as the login flush counter |
| `clickhouse_event_flush_duration_seconds` | histogram | step-event stream flush duration |
| `clickhouse_bruteforce_{lifecycle,counted,hits}_queued_rows_total` | counter | brute-force stream enqueue outcomes, same values as the event stream |
| `clickhouse_bruteforce_{lifecycle,counted,hits}_flush_batches_total` | counter | brute-force stream flush results |
| `clickhouse_bruteforce_{lifecycle,counted,hits}_flush_duration_seconds` | histogram | brute-force stream flush duration |

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
