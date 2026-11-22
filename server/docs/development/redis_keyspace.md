# Redis Keyspace Reference

This document is the developer reference for every Redis key the Nauthilus
server and its bundled Lua and native plugins create, read, or delete. It
lists each key pattern with its Redis type, lifetime, owning code, and
purpose, grouped by application area, followed by all Redis Lua scripts and
the Redis usage that is not tied to a key.

Code is the authority. Every entry names the Go constant, builder function,
or Lua helper that constructs the key, so it can be found with `grep`. When
you add, rename, or remove a key, update this document in the same change.

Related documents:

- `README_REDIS_CLUSTER.md`: client topology (standalone, Sentinel, Cluster).
- `server/docs/bruteforce_protection.md`, `server/docs/adaptive_toleration.md`,
  `server/docs/distributed_brute_force_detection.md`: brute-force semantics.
- `server/docs/identity_cache.md`: LDAP identity cache.
- `server/docs/development/browser_session_contract.md`: browser-session model.
- `IDP.md`: identity-provider operations, including retired IdP keys.
- `server/docs/development/clickhouse_data_model.md`: ClickHouse tables.

## 1. Conventions

### 1.1 Notation

- `<prefix>` is `storage.redis.prefix` (default `nt:`, see
  `defaultRedisKeyPrefix` in `server/config/dump.go`). Keys shown without
  `<prefix>` are written without it; section 1.4 lists them.
- Angle brackets mark variable parts with a concrete derivation, for example
  `<network>`, `<account>`, or `<sha256_hex(identity)>`. Each area states how
  its variable parts are derived.
- Braces are literal Redis Cluster hash tags, for example
  `<prefix>pw_hist:{<account>:<ip>}:...`. Only the text between the first
  `{` and the following `}` selects the Cluster slot.
- "Sliding" TTL means the expiry is refreshed on every write. "Set once"
  means it is set when the key is created and never extended.

### 1.2 Hash Tags and Redis Cluster

Keys that a single script or transaction touches together share one hash
tag, so they land in one slot:

| Tag | Keys that share it |
|---|---|
| `{<network>[\|p=<protocol>][\|oidc=<client_id>]}` | current and previous brute-force bucket windows |
| `{<account>:<ip>}`, `{<ip>}` | one password-history set each |
| `{<scoped_ip>}` | positive and negative toleration sets of one address |
| `{<prefix>affected_accounts}` | the affected-account set (by its full name), its retention, maintenance, and lease keys |
| `{<shard>}` | all fields of one account-mapping shard |
| `{<sha256_hex(identity)>}` | one MFA attempt budget |
| `{<subject_slot>}` | every OIDC token record, index, and the revocation epoch of one subject |
| `{<token_ref>}` | one token locator (deliberately in its own slot) |
| `{<client_id>}` | one dynamic client record and its tombstone |
| `{registry}` | the DCR client index and all registration rate limits |
| `{<hmac(session)>}` | all browser-session records of one session |
| `{<subject_tag>}`, `{manifest-<shard>}`, `{manifest-meta}` | reputation plugin state of one subject, one manifest shard, the manifest metadata |
| `{acm-<md5_hex(username)>}` | per-account keys of the bundled Lua monitoring plugins (`nauthilus_keys.account_tag`, `Host.Helpers().AccountTag`) |
| `{acm-global}` | global pattern keys of the bundled Lua monitoring plugins (`nauthilus_keys.global_tag`) |

Multi-key scripts that run on a Cluster client and whose keys do not already
share a tag are normalized to one tag before execution and again after a
`CROSSSLOT` error: an existing tag is replaced, a key without a tag gets the
tag plus `:` prepended. The tags are `{nauthilus}` for the server registry
(`ensureKeysInSameSlot`, `keyWithHashTag` in `server/rediscli/scripts.go`),
`{nauthilus-plugin}` for native plugins, and `{lua-nauthilus}` for Lua
`redis_run_script`. The normalized keys have different names from the ones
non-script readers use, so every multi-key caller must build keys that
already share a tag. All Go callers in the server and the reputation plugin
do, and so do the bundled Lua scripts (section 3.15).

A prefix that contains its own hash tag (for example `{nt}:`) overrides the
tags above for every key that embeds the prefix before its own braces. This
is not supported for production use.

### 1.3 Value Encoding and Secrets

- **Encrypted values** use `rediscli.SecurityManager.Encrypt`
  (`server/security/manager.go`): ChaCha20-Poly1305 keyed with
  SHA-256(`storage.redis.encryption_secret`), stored as standard base64.
  Without a secret the value is stored as plaintext.
- **Keyed digests** in key names use `security.Manager.IndexDigest(namespace, value)`:
  lowercase hex HMAC-SHA256 keyed with `storage.redis.encryption_secret`
  (unkeyed SHA-256 without a secret). Rotating the secret makes every state
  addressed by such a digest unreachable.
- **Prepared password hashes** (`<pw_hash>`) are lowercase hex
  SHA-256(`storage.redis.password_nonce` || 0x00 || password)
  (`util.PreparedPasswordHashWithConfig`).
- **Browser-session digests** use a key derived from
  `identity.frontend.encryption_secret` (section 3.11).
- **Browser-session payloads** are sealed with the same ChaCha20-Poly1305
  scheme, but through a strict `security.Manager` that never accepts a
  plaintext value once `storage.redis.encryption_secret` is set
  (`canonicalPayloadCipher`). A payload that does not open is purged and read
  as missing (section 3.11).

### 1.4 Keys Outside the Configured Prefix

These keys and channels ignore `storage.redis.prefix`. Deployments that share
one Redis database must not rely on the prefix to separate them.

| Key or channel | Area |
|---|---|
| `bf:blocks` (Pub/Sub channel) | Brute force (section 5) |
| `grpc:authority:backend_ref:<opaque_token>` | gRPC authority (section 3.13) |
| `<token_cache.key_prefix><authority>:<client_id>` and `:lock` (default `grpc:authority_tokens:`) | gRPC authority (section 3.13) |
| keys returned by the Lua `cache_flush` hook | Admin flush (section 3.5) |
| literal key strings passed to `nauthilus_redis` without `get_redis_key`, and native plugin keys sent without `Keys().Key` | Lua and native plugins (sections 3.14, 3.15) |
| keys rewritten to `{lua-nauthilus}:<prefix>...` or `{nauthilus-plugin}:<prefix>...` on Redis Cluster | Plugin script slot normalization (section 1.2) |
| `PW_HIST:*`, `PW_HIST_META:*`, `bf:TR:*` | Retired keys without a code path (section 3.16) |

### 1.5 Operational Requirements

- Run Redis with `maxmemory-policy noeviction`. Several keys have no TTL by
  design and must never be evicted: the OIDC subject epochs, the identity
  cache epoch, account mappings, the ban index, the affected-account state,
  DCR indexes, and the signing keys.
- Reads that must not see replica lag use the write handle (identity cache,
  OIDC token records, browser sessions, affected-account maintenance,
  consuming code and consent reads, device-code transitions, plugin scripts).
  Reads that tolerate lag use the read handle: positive cache, WebAuthn cache,
  account-mapping `HGET`, ban checks, bucket counters, password-history
  loads, non-consuming code, consent, device-code, and user-code lookups,
  signing keys, gRPC backend references, and the edge token cache.

### 1.6 Adding a Key

1. Put the key segment into a named constant (usually in
   `server/definitions/const.go`) and build the key in exactly one helper.
   Readers, deleters, and flush paths call that helper; they never rebuild
   the format. The user flush in `server/core/rest.go` follows this rule and
   uses the writers' builders. The key literals `UCI:`, `webauthn:user:`,
   `async:job:`, and `mfa:attempt:` have no `definitions` constant; do not
   copy that pattern.
2. Prepend `<prefix>`. A key that must ignore the prefix needs a documented
   reason.
3. Choose hash tags for every group of keys that one script, transaction, or
   multi-key command touches.
4. Give the key a TTL, or document why it has none and who removes it.
5. Encrypt values that contain credentials, tokens, or personal data, and
   use keyed digests for secret-derived key segments.
6. Add the key to this document.

## 2. Key Overview

One line per key pattern. Details, value layouts, and code references follow
in section 3.

| Area | Key pattern | Type | TTL |
|---|---|---|---|
| Brute force | `<prefix>bf:{<tag>}:<period_s>:<cidr>:<failed_requests>:<ip_proto>:<network>[:<protocol>][:oidc:<client_id>]:win:<window_index>` | STRING | 2 × period, set once |
| Brute force | `<prefix>bf:ban:<network>` | STRING | `ban_time` (8h), set once |
| Brute force | `<prefix>bf:bans:<shard>` (16 shards) | ZSET | none |
| Brute force | `<prefix>bf:burst:<sha1_hex>` | STRING | 1 s, sliding |
| Brute force | `<prefix>bf:rwp:allow:<rwp_ip>:<username>\|<protocol>\|<oidc_cid>` | ZSET | `rwp_window` (15m), sliding |
| Brute force | `<prefix>pw_hist:{<account>:<rwp_ip>}:<account>:<rwp_ip>` | SET | negative cache TTL (1h), sliding |
| Brute force | `<prefix>pw_hist:{<rwp_ip>}:<rwp_ip>` | SET | negative cache TTL (1h), sliding |
| Brute force | `<prefix>pw_hist_ips:<account>` | SET | negative cache TTL (1h) |
| Brute force | `<prefix>bf:tr:{<tol_ip>}:P` | ZSET | `tolerate_ttl`, sliding |
| Brute force | `<prefix>bf:tr:{<tol_ip>}:N` | ZSET | `tolerate_ttl`, sliding |
| Brute force | `<prefix>affected_accounts` | SET | none |
| Brute force | `<prefix>affected_accounts:index` | ZSET | none |
| Brute force | `<prefix>{<prefix>affected_accounts}:retention` | ZSET | none |
| Brute force | `<prefix>{<prefix>affected_accounts}:maintenance` | HASH | 10 min, sliding |
| Brute force | `<prefix>{<prefix>affected_accounts}:maintenance:lease` | STRING | 45 s |
| Auth caches | `<prefix>UCP:<cache_name>:<account>` | HASH | positive cache TTL (1h) |
| Auth caches | `<prefix>UCP:__default__:<account>` | HASH | positive cache TTL (1h) |
| Auth caches | `<prefix>UCP:\x00plugin.<module>.<backend>:<account>` | HASH | positive cache TTL (1h) |
| Auth caches | `<prefix>UCI:<cache_name>:<username>` | STRING | identity cache TTL (1 min) |
| Auth caches | `<prefix>UCI:epoch` | STRING | none |
| Auth caches | `<prefix>webauthn:user:<unique_user_id>` | HASH | positive cache TTL (1h) |
| Account mapping | `<prefix>user:{<shard>}` (256 shards) | HASH | none |
| MFA | `<prefix>mfa:attempt:{<sha256_hex(identity)>}` | STRING | 300 s, set once |
| Admin jobs | `<prefix>async:job:<job_id>` | HASH | negative cache TTL (1h) |
| Statistics | `<prefix>counter_<INSTANCE_NAME>` | HASH | none |
| OIDC tokens | `<prefix>oidc:subject:{<subject_slot>}:epoch` | STRING | none |
| OIDC tokens | `<prefix>oidc:subject:{<subject_slot>}:access_token:<access_ref>` | STRING | access-token lifetime |
| OIDC tokens | `<prefix>oidc:subject:{<subject_slot>}:access_tokens` | SET | longest member |
| OIDC tokens | `<prefix>oidc:subject:{<subject_slot>}:static_refresh_token:<static_refresh_ref>` | STRING | refresh-token lifetime |
| OIDC tokens | `<prefix>oidc:subject:{<subject_slot>}:static_refresh_tokens` | SET | longest member |
| OIDC tokens | `<prefix>oidc:subject:{<subject_slot>}:refresh_token:<dynamic_refresh_ref>` | STRING | DCR refresh lifetime |
| OIDC tokens | `<prefix>oidc:subject:{<subject_slot>}:refresh_tokens` | SET | refresh lifetime |
| OIDC tokens | `<prefix>oidc:subject:{<subject_slot>}:refresh_family:<family_id>` | STRING | refresh lifetime |
| OIDC tokens | `<prefix>oidc:subject:{<subject_slot>}:refresh_consumed:<dynamic_refresh_ref>` | STRING | refresh lifetime |
| OIDC tokens | `<prefix>oidc:subject:{<subject_slot>}:refresh_revoked:<family_id>` | STRING | 30 days |
| OIDC tokens | `<prefix>oidc:token:{<token_ref>}:subject` | STRING | token lifetime |
| OIDC tokens | `<prefix>oidc:account:{<account_slot>}:subjects` | SET | longest bound token lifetime |
| OIDC tokens | `<prefix>oidc:denied_access_token:sha256:<hex>` | STRING | access-token lifetime |
| OIDC tokens | `<prefix>oidc:denied_access_token:<raw_jwt>` (legacy dual write) | STRING | access-token lifetime |
| OIDC tokens | `<prefix>oidc:client_assertion:replay:<hex>` | STRING | assertion `exp` + 30 s |
| OIDC flows | `<prefix>oidc:code:<code_ref>` | STRING | 10 min |
| OIDC flows | `<prefix>oidc:consent:<challenge_ref>` | STRING | 10 min |
| OIDC flows | `<prefix>oidc:device_code:{<device_ref>}` | STRING | device code expiry (10 min) |
| OIDC flows | `<prefix>oidc:device_user_code:{<user_code_ref>}` | STRING | device code expiry (10 min) |
| OIDC DCR | `<prefix>oidc:dcr:client:{<client_id>}` | STRING | `lifecycle.maximum_ttl` (365d) |
| OIDC DCR | `<prefix>oidc:dcr:client:{<client_id>}:tombstone` | STRING | `lifecycle.tombstone_ttl` (30d) |
| OIDC DCR | `<prefix>oidc:dcr:{registry}:clients` | ZSET | none |
| OIDC DCR | `<prefix>oidc:dcr:{registry}:rate:source:<source_hash>` | STRING | `limits.source_window` (10 min) |
| OIDC DCR | `<prefix>oidc:dcr:{registry}:rate:source-day:<source_hash>` | STRING | 24h |
| OIDC DCR | `<prefix>oidc:dcr:{registry}:rate:global` | STRING | `limits.global_window` (1 min) |
| OIDC keys | `<prefix>oidc:keys` | HASH | none |
| OIDC keys | `<prefix>oidc:active_kid` | STRING | none |
| OIDC keys | `<prefix>oidc:ed_keys` | HASH | none |
| OIDC keys | `<prefix>oidc:active_ed_kid` | STRING | none |
| Browser sessions | `<prefix>:browser-session:{<hmac(session)>}:session_anchor:<hmac(session)>` | HASH | 30 min sliding idle / absolute cap |
| Browser sessions | `<prefix>:browser-session:{<hmac(session)>}:oidc_flow:<hmac(flow)>` | HASH | 10 min, capped by anchor |
| Browser sessions | `<prefix>:browser-session:{<hmac(session)>}:saml_flow:<hmac(flow)>` | HASH | 10 min, capped by anchor |
| Browser sessions | `<prefix>:browser-session:{<hmac(session)>}:self_service_flow:<hmac(flow)>` | HASH | 10 min, capped by anchor |
| Browser sessions | `<prefix>:browser-session:{<hmac(session)>}:required_mfa_enrollment:<hmac(record)>` | HASH | 15 min, capped by anchor |
| Browser sessions | `<prefix>:browser-session:{<hmac(session)>}:step_up:<hmac(record)>` | HASH | 15 min, capped by anchor |
| Browser sessions | `<prefix>:browser-session:{<hmac(session)>}:webauthn_ceremony:<hmac(record)>` | HASH | 5 min, capped by anchor |
| Browser sessions | `<prefix>:browser-session:{<hmac(session)>}:totp_recovery:<hmac(record)>` | HASH | 15 min, capped by anchor |
| Browser sessions | `<prefix>:browser-session:{<hmac(session)>}:consent_logout_indexes:<hmac(session)>` | HASH | anchor lifetime |
| Browser sessions | `<prefix>:browser-session:{<hmac(identity_handle)>}:consent_logout_indexes:<hmac(client_handle)>` | HASH | consent TTL (30d) |
| SAML | `<prefix>idp:saml:slo:replay:<hex>` | STRING | `identity.saml.default_expire_time` (1h) |
| SAML | `<prefix>idp:saml:slo:fanout:tx:<transaction_id>` | STRING | SLO replay TTL |
| SAML | `<prefix>idp:saml:slo:fanout:req:<hex>` | STRING | SLO replay TTL |
| SAML | `<prefix>idp:saml:slo:index:<account>` | SET | longest participant |
| SAML | `<prefix>idp:saml:slo:participant:<account>:<hex>` | STRING | SAML session lifetime |
| gRPC authority | `grpc:authority:backend_ref:<opaque_token>` | STRING | payload expiry (15 min) |
| gRPC authority | `grpc:authority_tokens:<authority>:<client_id>` | STRING | token expiry |
| gRPC authority | `grpc:authority_tokens:<authority>:<client_id>:lock` | STRING | `refresh_lock_ttl` (10 s) |
| Native plugins | `<prefix>reputation:{<subject_tag>}:state:<model_id>` | HASH | `retention`, sliding on ingestion |
| Native plugins | `<prefix>reputation:{<subject_tag>}:seen:<model_id>` | ZSET | until the latest seen expiry |
| Native plugins | `<prefix>reputation:{<subject_tag>}:override` | HASH | operator TTL or none |
| Native plugins | `<prefix>reputation:{<subject_tag>}:operator-audit` | HASH | 90 days, sliding |
| Native plugins | `<prefix>reputation:event:{manifest-meta}:allocation` | HASH | none (enforced) |
| Native plugins | `<prefix>reputation:event:{manifest-meta}:models` | HASH | none (enforced) |
| Native plugins | `<prefix>reputation:event:{manifest-<shard>}:control` (16 shards) | HASH | none (enforced) |
| Native plugins | `<prefix>reputation:event:{manifest-<shard>}:manifest:<allocation_tag>` | STRING | `event_manifest_ttl`, set once |
| Native plugins | `<prefix>reputation:event:{manifest-<shard>}:subjects:<source_tag>` | ZSET | 1h, sliding |
| Native plugins | `<prefix>reputation:event:{manifest-<shard>}:events:<source_tag>` | ZSET | `event_manifest_ttl`, sliding |
| Native plugins | `<prefix>clickhouse:authdedup:v3:<sha256_hex>` | STRING | `auth_dedup_ttl` (300 s) |
| Native and Lua plugins | `<prefix>HAVEIBEENPWND:<md5_hex(account)>` | HASH | 1h after a hit, 24h otherwise |
| Native and Lua plugins | `<prefix>HAVEIBEENPWND:GATE:<md5_hex(account)>:<sha1_prefix5>` | STRING | 5 min |
| Lua plugins | `<prefix>multilayer:account:<acct_tag><username>:proto:<protocol>:ips:<window>` | ZSET | 2 × window, sliding |
| Lua plugins | `<prefix>multilayer:account:<acct_tag><username>:proto:<protocol>:fails:<window>` | ZSET | 2 × window, sliding |
| Lua plugins | `<prefix>multilayer:account:<acct_tag><username>:proto:<protocol>:metrics:<window>` | HASH | 2 × window, sliding |
| Lua plugins | `<prefix>multilayer:distributed_attack:accounts:proto:<protocol>` | ZSET | 2 × `GPM_ATTACK_TTL_SEC` |
| Lua plugins | `<prefix>multilayer:global:<global_tag>auth_attempts:<window>` | ZSET | 2 × window, sliding |
| Lua plugins | `<prefix>multilayer:global:<global_tag>unique_ips:<window>` | ZSET | 2 × window, sliding |
| Lua plugins | `<prefix>multilayer:global:<global_tag>unique_users:<window>` | ZSET | 2 × window, sliding |
| Lua plugins | `<prefix>multilayer:global:<global_tag>current_metrics` | HASH | none |
| Lua plugins | `<prefix>multilayer:global:<global_tag>historical_metrics:<YYYY-MM-DD-HH>` | HASH | 7 days, set once |
| Lua plugins | `<prefix>multilayer:global:<global_tag>metrics:<unix_seconds>` | HASH | 1h |
| Lua plugins | `<prefix>hll:acct:<acct_tag><username>:proto:<protocol>:ips:86400` | STRING (HLL) | 48h, sliding |
| Lua plugins | `<prefix>hll:acct:<acct_tag><username>:proto:<protocol>:ips:604800` | STRING (HLL) | 14 days, sliding |
| Lua plugins | `<prefix>z:acct:<acct_tag><username>:proto:<protocol>:fails` | ZSET | 14 days, sliding |
| Lua plugins | `<prefix>acct:<acct_tag><username>:proto:<protocol>:longwindow` | HASH | 24h, sliding |
| Lua plugins | `<prefix>z:spray:pw:86400`, `<prefix>z:spray:pw:604800` | ZSET | 48h / 14 days, sliding |
| Lua plugins | `<prefix>top_failed_logins` | ZSET | none (top 100) |
| Lua plugins | `<prefix>environment:failed_login_hotspot:last_snapshot` | STRING | `FAILED_LOGIN_SNAPSHOT_SEC` (30 s) |
| Lua plugins | `<prefix>acct:<acct_tag><username>:proto:<protocol>:protection` | HASH | `PROTECT_MODE_TTL_SEC` (1h) |
| Lua plugins | `<prefix>acct:protection_active:proto:<protocol>` | SET | `PROTECT_MODE_TTL_SEC` (1h) |
| Lua plugins | `<prefix>acct:<acct_tag><username>:proto:<protocol>:stepup` | HASH | `PROTECT_MODE_TTL_SEC` (1h) |
| Lua plugins | `<prefix>alerts:last_sent:<subject>` | STRING | `ADMIN_ALERT_COOLDOWN_SECONDS` (900 s) |
| Lua plugins | `<prefix>multilayer:global:settings` | HASH | none |
| Lua plugins | `<prefix>multilayer:global:blocked_regions` | SET | 1h, sliding |
| Lua plugins | `<prefix>multilayer:global:captcha_accounts` | SET | 1h or 15 min |
| Lua plugins | `<prefix>multilayer:global:rate_limited_ips` | SET | 1h, sliding |
| Lua plugins | `<prefix>multilayer:global:country:<country_code>` | STRING | 24h, sliding |
| Lua plugins | `<prefix>multilayer:global:countries` | SET | 24h, sliding |
| Lua plugins | `<prefix>multilayer:bootstrap:first_seen_ts` | STRING | none |
| Lua plugins | `<prefix>multilayer:global:ok_streak` | STRING | 1h, sliding |
| Lua plugins | `<prefix>clickhouse:authdedup:<username>:<client_ip>` (retired action) | STRING | 300 s |
| Lua plugins | `<prefix>DS:<account>` | HASH | none |
| Lua plugins | `<prefix>DS_ACCOUNT` | HASH | none |
| Lua plugins | `<prefix>demo:textmap:content`, `<prefix>demo:textmap:last_modified` | STRING | `TEXTMAP_DEMO_TTL_SECONDS` (60 s) |
| Lua plugins | `<prefix>demo:textmap:version` | STRING | none |

## 3. Keys by Area

### 3.1 Brute-Force Protection

Brute-force protection keeps per-rule sliding-window failure counters for
each client network, one ban key per banned network plus a sharded ban index,
a one-second burst gate, the repeated-wrong-password (RWP) window, bounded
password-hash histories, per-address toleration sets, and the
affected-account management state. Most of it is network- or IP-keyed and
expires through its TTL. The affected-account set and its index have no TTL;
a background maintainer ages out their members
(`server/app/loopsfx/affected_accounts_service.go`,
`server/bruteforce/affected_accounts_maintenance.go`). The admin REST handlers
in `server/core/rest.go` list and flush this state.

Derivations:

- `<network>`: the client IP masked with the rule's
  `auth.controls.brute_force.buckets[].cidr`, as `net.IPNet.String()` (for
  example `192.0.2.0/24`, `2001:db8::/64`). IPv4-mapped IPv6 addresses are
  unmapped first (`getNetwork`, `preparedCIDRNetwork`).
- `<tag>`: `<network>`, plus `|p=<protocol>` and `|oidc=<client_id>` when the
  rule filters by protocol or OIDC client and the request matches.
- `<ip_proto>`: `4` when the rule has `ipv4`, else `6` when it has `ipv6`,
  else empty.
- `<rwp_ip>`: the raw client IP, or for IPv6 the network `<ip>/<n>` when
  `auth.controls.brute_force.ip_scoping.rwp_ipv6_cidr` is greater than 0.
  `<tol_ip>`: the same rule with `ip_scoping.tolerations_ipv6_cidr`
  (`server/ipscoper`).
- `<account>`: the resolved backend account name, not hashed.
- `<pw_hash>`: the prepared password hash (section 1.3).

| Key pattern | Type | TTL / lifetime | Code | Purpose |
|---|---|---|---|---|
| `<prefix>bf:{<tag>}:<period_s>:<cidr>:<failed_requests>:<ip_proto>:<network>[:<protocol>][:oidc:<client_id>]:win:<window_index>` | STRING | `2 × <period_s>`, set once when `SlidingWindowCounter` creates the key | `getBruteForceBucketBaseKey`, `slidingWindowFor`, `SaveBruteForceBucketCountersToRedis` (`server/bruteforce/bruteforce.go`), `definitions.RedisBruteForceBucketPrefix` | Failed authentications of one rule network in one fixed window. `<period_s>` is `buckets[].period` in whole seconds (at least 1), `<window_index>` is `floor(unix_now / period_s)`. The decision compares `current + previous × (1 − (now mod period)/period)` with `failed_requests − 1`, raised by the positive reputation count. Requests whose password the RWP commit classifies as repeated are not counted. |
| `<prefix>bf:ban:<network>` | STRING | `buckets[].ban_time` (default 8h, `definitions.DefaultBanTime`), set once by `SET NX EX` | `rediscli.GetBruteForceBanKey` (`server/rediscli/ban_keys.go`), `definitions.RedisBruteForceBanPrefix`; written by `setPreResultBruteForceRedis` | Active ban of one network. The value is the bucket (rule) name. Not scoped by protocol, OIDC client, or rule: rules with the same CIDR share one ban key, and the first rule wins. |
| `<prefix>bf:bans:<shard>` | ZSET | none; members are removed on ban deletion and lazily by the list endpoint | `rediscli.GetBruteForceBanIndexShardKey`, `definitions.RedisBruteForceBanIndexPrefix`; `addBanToIndex` (`ZADD NX`) | Paged listing index of banned networks. `<shard>` is the upper-case hex nibble `0`–`F` of `CRC32-IEEE(<network>) & 0x0F` (`definitions.BanIndexShardCount` = 16). No hash tag, so shards spread across Cluster slots. |
| `<prefix>bf:burst:<sha1_hex>` | STRING | 1 s, sliding (`IncrementAndExpire`) | `bfBurstKey`, `burstLeaderGate`, `definitions.RedisBFBurstPrefix` | Burst leader gate for blocked requests: the caller that sees count 1 records the password hash. `<sha1_hex>` is SHA-1 of `<protocol or "-">\0<username or account>\0<rwp_ip>\0<oidc_cid>`. Script errors fail open. |
| `<prefix>bf:rwp:allow:<rwp_ip>:<username>\|<protocol>\|<oidc_cid>` (with an empty username: `...:<rwp_ip>:<account>`) | ZSET | `auth.controls.brute_force.rwp_window` (default 15m), sliding | `bruteforce.RWPAllowanceRedisKey` (`server/bruteforce/redis_keys.go`), `buildRWPKeyAndHash`, `CommitRWPSlidingWindow`, `definitions.RedisBFRWPAllowPrefix`; the identity segment is `accountcache.GetAccountMappingField` (`rwpIdentity`) | Recently confirmed wrong-password hashes for one address and login identity. A hash already in the window is a repeated wrong password and does not increase the bucket counters. |
| `<prefix>pw_hist:{<account>:<rwp_ip>}:<account>:<rwp_ip>` | SET | `storage.redis.negative_cache_ttl` (default 3600 s), refreshed on every successful add | `bruteforce.PasswordHistoryRedisKey` (`server/bruteforce/redis_keys.go`), `saveFailedPasswordHash`, `definitions.RedisPwHashKey` | Distinct failed password hashes of one account from one address (`passwords_account_seen`, `login_attempts`). Bounded by `auth.pipeline.password_history.max_entries` (default 100). Written only by the burst leader of a blocked request. |
| `<prefix>pw_hist:{<rwp_ip>}:<rwp_ip>` | SET | same as above | same as above | Distinct failed password hashes from one address across all accounts (`passwords_total_seen`). Same bound. |
| `<prefix>pw_hist_ips:<account>` | SET | `storage.redis.negative_cache_ttl`, set when a new IP is added | `GetPWHistIPsRedisKey`, `storePasswordHistoryIP`, `definitions.RedisPWHistIPsKey` | Raw client IPs that produced failed logins for a known account. Drives the user flush and affected-account retention. |
| `<prefix>bf:tr:{<tol_ip>}:P` | ZSET | `max(1 s, tolerate TTL)` from `auth.controls.brute_force.tolerate_ttl` or a matching `custom_tolerations[].tolerate_ttl`, sliding; nothing is written with TTL 0 (default) | `tolerate.RedisKeys`, `recordTolerationEvent` (`server/bruteforce/tolerate/tolerate.go`), `definitions.RedisBFTolerationPrefix` | Distinct accounts with a verified successful login from the address. Raises the toleration allowance and scales bucket limits. |
| `<prefix>bf:tr:{<tol_ip>}:N` | ZSET | same as `:P` | same as `:P` | One member per counted failed login from the address (RWP repeats excluded), capped to the newest 10000; a count at the cap means saturated and is never tolerated. |
| `<prefix>affected_accounts` | SET | none; members age out through the retention ZSET | `rediscli.GetAffectedAccountsKey`, `addAffectedAccount`, `definitions.RedisAffectedAccountsKey` | Accounts with a counted failed login or a blocked request, for management listings. |
| `<prefix>affected_accounts:index` | ZSET | none | `rediscli.GetAffectedAccountsIndexKey`, `definitions.RedisAffectedAccountsIndexKey` | Same members, scored by first-seen Unix seconds, for stable paging. Lives in another slot and is repaired best effort. |
| `<prefix>{<prefix>affected_accounts}:retention` | ZSET | none | `rediscli.GetAffectedAccountsRetentionKey`, `rediscli.SlotSiblingKey` | Retain-until deadline per account: now + max(`affected_accounts.retention` (24h), negative cache TTL, `rwp_window`, `tolerate_ttl`, max `ban_time` + 2 × max `period`, every custom `tolerate_ttl`) (`AffectedAccountRetention`). The tag equals the set's full name, so both share a slot. |
| `<prefix>{<prefix>affected_accounts}:maintenance` | HASH | 10 min (`affectedAccountsHeartbeatTTL`), refreshed on every leased tick | `server/bruteforce/affected_accounts.go` | Maintenance heartbeat and scan cursors shared by all instances. A missing hash re-arms the lifecycle before anything is removed. |
| `<prefix>{<prefix>affected_accounts}:maintenance:lease` | STRING | 45 s (`affectedAccountsLeaseTTL`), `SET NX PX` | `acquireLease` | Tick lease, so normally one instance runs the maintenance per minute. |

Value layout:

- Bucket window: decimal integer, changed only by `INCRBY` inside
  `SlidingWindowCounter`.
- `bf:ban:<network>`: bucket name as plain text. The list endpoint derives
  `banned_at = now − (ban_time − TTL)`.
- `bf:bans:<shard>`: member `<network>`, score = ban creation in Unix seconds
  (sort order only).
- `bf:burst:*`: `INCR` counter; only the value 1 (leader) matters.
- `bf:rwp:allow:*`: member `<pw_hash>`, score = Unix seconds of the last
  commit; at most `auth.controls.brute_force.rwp_allowed_unique_hashes`
  members (default 3), oldest removed first.
- `pw_hist:*`: members `<pw_hash>`. `pw_hist_ips:*`: members are raw IPs.
- `bf:tr:*:P`: member = lower-cased account (or typed username), score =
  Unix seconds of the last success. `bf:tr:*:N`: member =
  `<unix_nanos base36>:<16 random hex>`, score = Unix seconds of the failure.
- `affected_accounts:index`: score = first-seen Unix seconds.
  `:retention`: score = retain-until Unix seconds.
- `:maintenance` fields (decimal strings): `armed_at`, `rearm_done`
  (`"0"`/`"1"`), `rearm_cursor`, `adopt_cursor`, `index_cursor`.
- `:maintenance:lease`: Unix nanoseconds of the lease holder.

Flush paths (`server/core/rest.go`):

- The **brute-force flush** removes ban keys and their index members, the
  current and previous bucket windows, and the toleration sets. It does not
  touch RWP windows: they are keyed by login identity, so finding them by
  address alone would need a keyspace scan. They expire through
  `rwp_window`.
- The **user flush** runs the brute-force flush for every address in the
  `pw_hist_ips` sets of the flushed accounts and additionally removes those
  sets, the password histories, the affected-account members, and the RWP
  windows. For every address, raw and RWP-scoped, it deletes the window of
  each login identity: the account-mapping fields that the flushed login
  name owns (section 3.3, read with `AccountMappingReader`) and every
  flushed account name, which covers the empty-username fallback. All keys
  come from the writers' builders (`bruteforce.RWPAllowanceRedisKey`,
  `bruteforce.PasswordHistoryRedisKey`). When the Lua `cache_flush` hook
  returns an account, the owned mapping fields are still read, best effort:
  a read failure leaves them and their RWP windows in place until
  `rwp_window` expires. Windows of other login names that map to the same
  account are removed only when those names are flushed themselves.

### 3.2 Authentication Caches

The positive password cache (`UCP:`) stores one hash per cache namespace and
account after a successful backend authentication, so later requests can be
verified against the stored prepared-password digest without calling the
backend. The identity cache (`UCI:`) stores encrypted LDAP attribute
snapshots for passwordless (`NoAuth`) lookups, fenced by a prefix-wide epoch.
The WebAuthn user cache holds a backend user's credential list.

There is no negative user cache in Redis. `storage.redis.negative_cache_ttl`
is used only by brute-force bookkeeping and async admin jobs; the LDAP
negative cache is process-local.

| Key pattern | Type | TTL / lifetime | Code | Purpose |
|---|---|---|---|---|
| `<prefix>UCP:<cache_name>:<account>` | HASH | `storage.redis.positive_cache_ttl` (default 3600 s), set on every write; hits do not refresh it | `backend.PositivePasswordCacheKey` (`server/backend/plugin_password_cache.go`), `SaveUserDataToRedis` (`server/backend/cache.go`), `definitions.RedisUserPositiveCachePrefix` | Positive password cache of one account in one LDAP or Lua cache namespace (`cache_name` of the search protocol). Written only when the `cache` backend is ordered before the backend that authenticated. |
| `<prefix>UCP:__default__:<account>` | HASH | same | same; fallback in `backend.GetCacheNames` | Namespace used when no LDAP, Lua, or plugin cache name applies. The user flush always deletes it. |
| `<prefix>UCP:\x00plugin.<module>.<backend>:<account>` | HASH | same | `backend.PluginPasswordCacheName` | Positive cache of a native plugin backend. `\x00` is a literal NUL byte, so it cannot collide with printable operator cache names. |
| `<prefix>UCI:<cache_name>:<username>` | STRING | `storage.redis.identity_cache.ttl` (default 1 min), set once | `backend.IdentityCacheKey`, `IdentityCache.Store` (`server/backend/identity_cache.go`); literal `UCI:` | LDAP identity snapshot for passwordless lookups. `<username>` is the raw request login name. Only active with `storage.redis.identity_cache.enabled`, outside IdP and master-user flows. Read on the write handle. |
| `<prefix>UCI:epoch` | STRING | none (must never expire) | `IdentityCache.Generation` (`SETNX`), `IdentityCache.Invalidate` (`SET`) | Prefix-wide invalidation fence. Entries store the epoch they were written under; one `SET` invalidates every identity entry. Rotated by every cache purge and user flush. |
| `<prefix>webauthn:user:<unique_user_id>` | HASH | TTL argument of `SaveWebAuthnToRedis`: the positive cache TTL, except after a credential rename in the IdP frontend, where the Redis write timeout is passed | `SaveWebAuthnToRedis`, `GetWebAuthnFromRedis`, `DeleteWebAuthnFromRedis` (`server/backend/cache.go`); literal `webauthn:user:` in each of the three functions, no single builder | Cached WebAuthn user and credential list of a backend user. |

Value layout:

- `UCP:*` HASH fields (`buildPositiveCacheHashFields`); "enc" means encrypted:
  `backend` (backend enum as integer), `password` (enc, 64-hex prepared hash),
  `plugin_result` (enc, opaque plugin payload), `account_field`,
  `totp_secret_field` (enc), `totp_recovery_field` (enc),
  `webauth_userid_field` (spelling as in code), `display_name_field`,
  `backend_name`, `attributes` (enc, JSON attribute mapping), `groups` (enc,
  JSON array), `group_dns` (enc, JSON array). Empty values are not written.
- `UCI:<cache_name>:<username>`: enc(JSON `identityCacheEnvelope`) with
  `generation` (epoch at lookup start), `scope` (hex SHA-256 over pool,
  protocol, OIDC client, SAML entity, and the expanded LDAP search config),
  and `data` (JSON `{attributes, groups, group_dns}`).
- `UCI:epoch`: random base32 string from `crypto/rand.Text()`.
- `webauthn:user:*`: `id`, `name`, `display_name`, and `credentials` (enc,
  JSON array of `mfa.PersistentCredential`).

The positive-cache write is a plain pipeline (`HSET`, `EXPIRE`), not a
transaction.

### 3.3 Account Mapping

Authentication records which backend account a submitted login name maps to,
in 256 sharded hashes. Brute-force attribution, cache purges, the user flush,
the brute-force list, and support history read it back. The mapping never
expires and is not re-validated against the backend. An in-process
`account_local_cache` (`storage.redis.account_local_cache.*`, default TTL
60 s) sits in front of it and is not invalidated by flushes.

| Key pattern | Type | TTL / lifetime | Code | Purpose |
|---|---|---|---|---|
| `<prefix>user:{<shard>}` | HASH | none | `rediscli.GetUserHashKey` (`server/rediscli/sharding.go`), `definitions.RedisUserHashKey`; written by `backend.SetUserAccountMapping` | Login name to account mapping. `<shard>` is the lowercase two-digit hex of `crc32.ChecksumIEEE(<username>) % 256`. Read with `HGET` (`LookupUserAccountFromRedis`) and with `HSCAN MATCH <username>\|*` on the primary (`AccountMappingReader`). |

Value layout: field `<username>|<protocol>|<oidc_client_id>`
(`accountcache.GetAccountMappingField`; the OIDC client ID is empty outside
OIDC); value = account name (several account attribute values are sorted and
joined with `:`). The user flush also removes a legacy bare `<username>`
field that no current writer creates.

### 3.4 MFA Attempt Budget

TOTP and recovery-code verification share one reservation budget per
account identity. A slot is reserved atomically before any verifier runs.

| Key pattern | Type | TTL / lifetime | Code | Purpose |
|---|---|---|---|---|
| `<prefix>mfa:attempt:{<sha256_hex(identity)>}` | STRING | 300 s (`mfaAttemptWindow`), set by the `INCR` that creates the key; a fixed window | `ConsumeMFAAttempt`, `mfaAttemptScript` (`server/core/mfa_attempts.go`); literal `mfa:attempt:` | Account-wide MFA code budget, limit 10 per window (`mfaAttemptLimit`). The identity is the IdP selection identity reference or, for the gRPC authority, the unique user ID or account name. IP, method, and challenge are not part of it. Success does not reset the budget. |

### 3.5 Administrative Flush and Async Jobs

`DELETE .../cache/flush` and the async variants (including the brute-force
flush) remove a user's cached state: they rotate the identity-cache epoch,
remove the account-mapping fields, unlink positive-cache and identity keys,
flush the OIDC tokens of every flushed account
(`TokenFlusher.FlushAccountTokens`, section 3.7), and delete the
brute-force keys of section 3.1. Async variants record their state in Redis;
`GET .../async/jobs/:jobId` reads it.

| Key pattern | Type | TTL / lifetime | Code | Purpose |
|---|---|---|---|---|
| `<prefix>async:job:<job_id>` | HASH | `storage.redis.negative_cache_ttl`, set at creation and again on completion | `asyncJobKey`, `createAsyncJob`, `applyAsyncJobTransition` (`server/core/rest.go`); literal `async:job:` | Status of one background admin job. `<job_id>` is `<unix_nanos>-<32 random hex>`. State changes use `WATCH`/`MULTI` with up to three retries. |
| keys returned by the Lua `cache_flush` hook | any | set by their creator | `unlinkLuaAdditionalKeys` (`server/core/rest.go`), `server/lualib/cacheflush` | Construction rule: the optional Lua `cache_flush` script returns key names that are unlinked unchanged. Nothing prefixes them; the script must build them from `request.redis_prefix`. |

Value layout of `async:job:*`: `status` (`QUEUED`, `INPROGRESS`, `DONE`,
`ERROR`), `type` (`CACHE_FLUSH`, `BF_FLUSH`), `createdAt`, `startedAt`,
`finishedAt` (RFC 3339 with nanoseconds, UTC), `resultCount` (keys removed),
`error` (only on failure).

### 3.6 Statistics

The Prometheus login counters are persisted every 60 s and at shutdown and
loaded back at startup, so they survive restarts.

| Key pattern | Type | TTL / lifetime | Code | Purpose |
|---|---|---|---|---|
| `<prefix>counter_<INSTANCE_NAME>` | HASH | none | `SaveStatsToRedis`, `LoadStatsFromRedis` (`server/core/statistics.go`), `definitions.RedisMetricsCounterHashKey` | Persisted login counters. `<INSTANCE_NAME>` is `server.instance_name` upper-cased (default key `nt:counter_NAUTHILUS`). Fields `success` and `failure`, float64 as decimal strings. Replicas that share an instance name share the hash. |

### 3.7 OIDC Token Storage

`RedisTokenStorage` (`server/idp/redis_storage.go`, key layout in
`oidcTokenKeys` / `oidcSubjectKeys` in `server/idp/redis_storage_keys.go`)
stores opaque access tokens, static refresh tokens, and dynamic (DCR)
refresh-token families. Every token is bound to the per-subject revocation
epoch, and all state one script touches shares the subject tag. Bearer
lookups only know the token, so a single-key locator in its own slot points
to the owning subject.

Derivations:

- `<subject_slot>`: unkeyed hex SHA-256(`"nauthilus-oidc-token-subject\x00" + subject`)
  (`oidcSubjectSlot`), where `subject` is `OIDCSession.UserID` (the backend
  unique user ID, or the `client_id` for `client_credentials` tokens). It is
  unkeyed on purpose so it survives a secret rotation.
- `<account_slot>`: unkeyed hex SHA-256(`"nauthilus-oidc-token-account\x00" + account`)
  (`oidcAccountSlot`), where `account` is `OIDCSession.Username` (the backend
  account name). Unkeyed for the same reason.
- `<access_ref>`, `<static_refresh_ref>`, `<dynamic_refresh_ref>`,
  `<token_ref>`: keyed digests (section 1.3) in the namespaces
  `oidc-static-access`, `oidc-dynamic-access`, `oidc-static-refresh`,
  `oidc-dynamic-refresh`.

| Key pattern | Type | TTL / lifetime | Code | Purpose |
|---|---|---|---|---|
| `<prefix>oidc:subject:{<subject_slot>}:epoch` | STRING | none (requires `noeviction`) | `advanceDynamicUserEpoch` (`subjectEpochAdvanceScript`), `DynamicUserEpoch` | Subject-wide revocation epoch. A missing key means the floor `1000000000000`. Tokens carry the epoch (claim `nauthilus_user_epoch`) and stay valid only while it is current. `FlushUserTokens` and `FlushAccountTokens` advance it. |
| `<prefix>oidc:subject:{<subject_slot>}:access_token:<access_ref>` | STRING | access-token lifetime (`identity.oidc.clients[].access_token_lifetime`, else `identity.oidc.tokens.default_access_token_lifetime` = 1h; DCR clients 15 min), set once | `StoreAccessToken` → `storeEpochBoundToken` | Encrypted session of one opaque access token (`na_at_…`). |
| `<prefix>oidc:subject:{<subject_slot>}:access_tokens` | SET | raised to the longest member TTL | `dynamicTrackedStoreScript` | Reverse index of opaque access-token references per subject (session list, user-wide flush). |
| `<prefix>oidc:subject:{<subject_slot>}:static_refresh_token:<static_refresh_ref>` | STRING | refresh lifetime (`identity.oidc.clients[].refresh_token_lifetime`, else `identity.oidc.tokens.default_refresh_token_lifetime` = 30d), set once | `StoreRefreshToken` → `storeEpochBoundToken` | Encrypted session of a static-client refresh token (`na_rt_…`), single-use claim via `staticRefreshConsumeScript`. |
| `<prefix>oidc:subject:{<subject_slot>}:static_refresh_tokens` | SET | raised to the longest member TTL | `dynamicTrackedStoreScript` | Reverse index of static refresh references per subject. |
| `<prefix>oidc:subject:{<subject_slot>}:refresh_token:<dynamic_refresh_ref>` | STRING | `identity.oidc.dynamic_client_registration.refresh_token_lifetime` (30d), set at initial store and on every rotation | `StoreInitialDynamicRefreshToken`, `RotateDynamicRefreshToken` | Encrypted session of the active refresh token of one DCR family. |
| `<prefix>oidc:subject:{<subject_slot>}:refresh_tokens` | SET | raised to the token TTL; rotation sets it unconditionally | `dynamicInitialRefreshStoreScript`, `dynamicRefreshRotateScript` | Reverse index of active dynamic refresh references per subject. |
| `<prefix>oidc:subject:{<subject_slot>}:refresh_family:<family_id>` | STRING | refresh lifetime, rewritten on rotation | same scripts | Pointer from a refresh family to its active token reference. `<family_id>` is a raw `dcr_family_<random>` value. |
| `<prefix>oidc:subject:{<subject_slot>}:refresh_consumed:<dynamic_refresh_ref>` | STRING | rotation TTL, set once | `dynamicRefreshRotateScript` | Marks a rotated predecessor; replaying it revokes the whole family (reuse detection). Value: the family ID. |
| `<prefix>oidc:subject:{<subject_slot>}:refresh_revoked:<family_id>` | STRING | 30 days (`oidcDynamicRefreshRevokedTTL`) | rotate and resolve scripts, `revokeDynamicRefreshSession` | Keeps a revoked family rejecting its tokens. Value `"1"`. |
| `<prefix>oidc:token:{<token_ref>}:subject` | STRING | same TTL as the token record | `evalWithLocators` | Locator from a bearer reference (any of the four namespaces) to its 64-hex subject slot. Other values are treated as absent. |
| `<prefix>oidc:account:{<account_slot>}:subjects` | SET | raised to the longest lifetime bound through it: the access-token lifetime, or with `offline_access` the refresh lifetime | `BindAccountSubject` (`accountSubjectBindScript`, `server/idp/redis_storage_account.go`), called by `bindAccountSubject` before every user token issuance (code, device, static and dynamic refresh) | Subject slots that received tokens for one backend account, so the admin user flush (`FlushAccountTokens`) finds the subject when the unique user ID differs from the account name. Written only when they differ and never for service tokens; a failed write fails the issuance. The flush also revokes the subject named like the account, removes the flushed members, and fails when the set cannot be read. Members are 64-hex subject slots; other values are ignored. Tokens issued before this binding existed are reachable only through the subject named like the account and expire through their TTL. |
| `<prefix>oidc:denied_access_token:sha256:<hex>` | STRING | full access-token lifetime | `DenyJWTAccessToken`, `IsJWTAccessTokenDenied` (`server/idp/redis_storage_denylist.go`) | JWT access-token denylist (old tokens on refresh). `<hex>` = unkeyed SHA-256(`"nauthilus-oidc-denied-access-token\x00" + jwt`), so a secret rotation cannot revive a revoked token. Value `"1"`. |
| `<prefix>oidc:denied_access_token:<raw_jwt>` | STRING | same | same (dual write) | **Legacy** denylist key that embeds the raw JWT. Written and read next to the digest key for rollback safety. |
| `<prefix>oidc:client_assertion:replay:<hex>` | STRING | `exp − now + 30 s` (`clientauth.DefaultPrivateKeyJWTClockSkew`) | `ReserveClientAssertionJWTID` (`SET NX`) | `private_key_jwt` `jti` replay protection. `<hex>` = SHA-256(`client_id + "\x1f" + audience + "\x1f" + jti`). Value `"1"`. |

Token record values are encrypted JSON `OIDCSession` with the fields
`scopes`, `access_token_resources`, `client_id`, `user_id`, `username`,
`display_name`, `redirect_uri`, `mfa_method`, `nonce`, `code_challenge`,
`code_challenge_method`, `access_token`, `access_token_audience`,
`access_token_issuer`, `refresh_family_id`, `dynamic_user_epoch`,
`diagnostic_flow_ref`, `id_token_claims`, `access_token_claims`, `auth_time`,
`access_token_issued_at`, `access_token_expires_at`, `required_mfa_level`,
`mfa_completed`, `service_token`. Index sets hold 64-hex references; the
epoch is a decimal int64.

### 3.8 OIDC Authorization Codes, Consent Challenges, and Device Flow

Single-use or short-lived protocol records. Codes and consent challenges use
separate key families and digest namespaces (`oidc-authorization-code`,
`oidc-consent-challenge`), so a browser-visible consent challenge can never
be redeemed as a code. Device requests keep the device code inside the
encrypted value; keys only contain digests (`oidc-device-code`,
`oidc-device-user-code`, the user code normalized first).

| Key pattern | Type | TTL / lifetime | Code | Purpose |
|---|---|---|---|---|
| `<prefix>oidc:code:<code_ref>` | STRING | 10 min (`canonicalOIDCAuthorizationCodeTTL`) | `StoreSession`, `ConsumeSession` (`GETDEL`) | Authorization-code session (encrypted `OIDCSession`). |
| `<prefix>oidc:consent:<challenge_ref>` | STRING | 10 min (`canonicalOIDCAuthorizationTTL`) | `StoreConsentSession`, `ConsumeConsentSession` (`GETDEL`) | Pending authorization behind one consent page (encrypted `OIDCSession`). |
| `<prefix>oidc:device_code:{<device_ref>}` | STRING | `identity.oidc.device_flow.code_expiry` (default 10 min), kept by transitions (`KEEPTTL`) | `StoreDeviceCode`, `persistDeviceCodeTransition`, `UpdateDeviceCode` (`server/idp/device_code.go`) | RFC 8628 device authorization request. Transitions use `WATCH`/`MULTI` on this single key. |
| `<prefix>oidc:device_user_code:{<user_code_ref>}` | STRING | same | `StoreDeviceCode` (`SET NX`; a collision regenerates the user code) | Locator from a normalized user code to the 64-hex device reference. |

`oidc:device_code:*` holds encrypted JSON `deviceCodeEnvelope{request, device_code}`;
`request` (`DeviceCodeRequest`) carries `client_id`, `scopes`, `resources`,
`user_code`, `status` (`pending`, `authorized`, `denied`), user identity and
claims, `mfa_completed`, `mfa_method`, `expires_at`, `interval`, `last_poll`,
and `verification_locked`.

### 3.9 OIDC Dynamic Client Registration

`dcr.Repository` (`server/idp/dcr/repository.go`) stores RFC 7591 dynamic
clients. A client record and its tombstone share the slot `{<client_id>}`;
the active-client index and the registration rate limits are pinned to the
global `{registry}` slot. No script spans both; consistency comes from
ordered writes, compensation, and index repair in `CleanupExpired`.

| Key pattern | Type | TTL / lifetime | Code | Purpose |
|---|---|---|---|---|
| `<prefix>oidc:dcr:client:{<client_id>}` | STRING | `identity.oidc.dynamic_client_registration.lifecycle.maximum_ttl` (365d), set once by `SETNX`; touches keep it. Logical expiry is earlier (`unused_ttl` 24h, `inactivity_ttl` 30d). | `createRecord`, `touchRecordScript` | Dynamic client record (plain JSON `DynamicClientRecord`). `<client_id>` = `dcr_` + base64url(32 random bytes). |
| `<prefix>oidc:dcr:client:{<client_id>}:tombstone` | STRING | `lifecycle.tombstone_ttl` (30d) | `expire` | Marker that the client expired or was revoked. Value `"expired"`. Write-only. |
| `<prefix>oidc:dcr:{registry}:clients` | ZSET | none | `registrationScript`, `touchIndexScript`, `cleanupClient` | Active-client index and quota counter (`ZCARD`). Member = client ID, score = next expiry deadline in Unix ms. |
| `<prefix>oidc:dcr:{registry}:rate:source:<source_hash>` | STRING | `limits.source_window` (10 min), set on the first `INCR` | `registrationAttemptScript` | Per-source registration counter. |
| `<prefix>oidc:dcr:{registry}:rate:source-day:<source_hash>` | STRING | 24h, set on the first `INCR` | `registrationAttemptScript` | Per-source daily registration counter. |
| `<prefix>oidc:dcr:{registry}:rate:global` | STRING | `limits.global_window` (1 min) | `registrationAttemptScript` | Global registration counter. |

`<source_hash>` = base64url(HMAC-SHA256(`identity.oidc.dynamic_client_registration.source_hmac_key`, client IP)).

### 3.10 OIDC Signing Keys

`oidckeys.Manager` (`server/idp/oidckeys/manager.go`) stores generated RS256
and EdDSA signing keys when `identity.oidc.auto_key_rotation` is enabled.
Static keys from `identity.oidc.signing_keys` never go to Redis. Verification
keys are served from a process-local cache.

| Key pattern | Type | TTL / lifetime | Code | Purpose |
|---|---|---|---|---|
| `<prefix>oidc:keys` | HASH | none; per field a logical expiry in the JSON (`created_at` + `identity.oidc.key_max_age`, default 7d). `CleanupOldKeys` removes inactive fields that passed their expiry or are older than the current `key_max_age` | `storeKeyInRedis`, `RedisKeyOIDCKeys` | RSA signing keys by `kid`. |
| `<prefix>oidc:active_kid` | STRING | none | `storeKeyInRedis`, `RedisKeyOIDCActive` | Active RSA `kid`. |
| `<prefix>oidc:ed_keys` | HASH | as `oidc:keys` | `storeKeyInRedis`, `RedisKeyOIDCEdKeys` | Ed25519 signing keys by `kid`. |
| `<prefix>oidc:active_ed_kid` | STRING | none | `storeKeyInRedis`, `RedisKeyOIDCEdActive` | Active EdDSA `kid`. |

Hash field = `kid` (KSUID); value = encrypted JSON
`KeyMetadata{id, pem, algorithm, created_at, expires_at}` (PKCS#1 for RSA,
PKCS#8 for Ed25519). Rotation runs on every instance
(`identity.oidc.key_rotation_interval`, default 24h) without a distributed
lock; the last `SET` of the active kid wins. An interval that is not shorter
than `key_max_age` is replaced by half the maximum age (`rotationInterval`), so
the active key never expires before its successor. `CleanupOldKeys` removes
every inactive field older than `key_max_age`, whatever expiry its JSON
carries.

### 3.11 Browser Sessions and Flows

`sessionstate.RedisStores` (`server/sessionstate/redis_store.go`) holds the
canonical browser session: one session anchor, typed child records owned by
it (OIDC, SAML, and self-service flows, required-MFA enrollment, step-up,
WebAuthn ceremony, TOTP/recovery operation, logout index), and long-lived
OIDC consent grants per identity.

Key construction (`Keyspace.Key` in `server/sessionstate/keyspace.go`):
`<keyspace>:{<hmac(session)>}:<owner>:<hmac(record)>`.

- `<keyspace>` is `<prefix> + ":browser-session"` with only leading and
  trailing colons trimmed (`server/core/cookie/runtime.go`). With the default
  prefix `nt:` the keys therefore start with `nt::browser-session:` (double
  colon). Changing this orphans every live session.
- `<hmac(x)>` is hex HMAC-SHA256 keyed with
  SHA-256(`identity.frontend.encryption_secret` || `"/browser-session-keyspace/v1"`).
  Handles are 256-bit random base64url values. Rotating the frontend secret
  orphans all session records and consent grants.
- `<owner>` is one of the `sessionstate.Owner*` literals
  (`server/sessionstate/inventory.go`).
- Child TTLs are always capped at the anchor's remaining lifetime.

| Key pattern | Type | TTL / lifetime | Code | Purpose |
|---|---|---|---|---|
| `<prefix>:browser-session:{<hmac(session)>}:session_anchor:<hmac(session)>` | HASH | 30 min idle (`canonicalIdleTTL`), sliding: every request that opens the session extends idle expiry, PTTL, and the logout index to now + 30 min, at most once per 5 min (`TouchSession`, `redisTouchScript`, without a revision change) and never beyond the absolute expiry; absolute = 7d, or the remember-me TTL capped at 30d after login completion; revocation leaves a 5 min tombstone | `RedisRepository.Commit`, `RedisStores.Commit`, `CanonicalRuntime.Open`, `redisRevokeScript` | Session anchor: identity, backend affinity, assurance, and bounded child indexes (at most 16 handles per family). Login completion rotates the handle and tombstones the old anchor. |
| `<prefix>:browser-session:{<hmac(session)>}:oidc_flow:<hmac(flow_id)>` | HASH | 10 min, capped | `CommitOIDCFlow`, `ConsumeOIDCFlow` | OIDC authorization flow state (`OIDCFlow`). |
| `<prefix>:browser-session:{<hmac(session)>}:saml_flow:<hmac(flow_id)>` | HASH | 10 min (`canonicalSAMLSSOTTL`), capped | `CommitSAMLFlow`, `ConsumeSAMLFlow` | SAML SSO/SLO flow state, including the AuthnRequest binding. |
| `<prefix>:browser-session:{<hmac(session)>}:self_service_flow:<hmac(flow_id)>` | HASH | 10 min, capped | `CommitSelfServiceFlow` | Primary-login flow of the MFA self-service portal. |
| `<prefix>:browser-session:{<hmac(session)>}:required_mfa_enrollment:<hmac(record)>` | HASH | 15 min (`canonicalEnrollmentTTL`), capped | `CommitEnrollment` (`server/idp/mfastate`) | Required-factor enrollment state machine. |
| `<prefix>:browser-session:{<hmac(session)>}:step_up:<hmac(record)>` | HASH | 15 min (`canonicalStepUpTTL`), capped | `CommitStepUp`, `ConsumeStepUp` | Dynamic-assurance or self-service proof operation. |
| `<prefix>:browser-session:{<hmac(session)>}:webauthn_ceremony:<hmac(record)>` | HASH | 5 min (`webAuthnCeremonyTTL`), capped | `CommitCeremony`, `ConsumeCeremony` (`server/core/canonical_webauthn_ceremony_store.go`) | Single-use WebAuthn registration or login ceremony. |
| `<prefix>:browser-session:{<hmac(session)>}:totp_recovery:<hmac(record)>` | HASH | 15 min, capped | `CommitTOTPRecovery` | Pending TOTP secret or recovery-code operation. |
| `<prefix>:browser-session:{<hmac(session)>}:consent_logout_indexes:<hmac(session)>` | HASH | anchor remaining TTL, extended with every anchor touch | `CommitLogoutIndex` (`server/core/cookie/composition.go`), `TouchSession` | Per-browser logout index: OIDC client IDs (at most 16) that received sessions, for front-channel logout. |
| `<prefix>:browser-session:{<hmac(identity_handle)>}:consent_logout_indexes:<hmac(client_handle)>` | HASH | `identity.oidc.clients[].consent_ttl`, else `identity.oidc.consent.ttl` (30d); not capped | `Consent.Commit` (`server/sessionstate/consent_grant.go`) | Long-lived OIDC consent grant per identity and client. The tag derives from the identity (`consent-identity-v1`), the record from identity and client (`consent-client-v1`). Survives session revocation and token flushes; expires by TTL. |

Every record is a revision-checked HASH with the fields `schema_version`
(`"1"`), `owner`, `revision` (CAS counter), `payload` (JSON of the typed
record, sealed with `storage.redis.encryption_secret`; see section 1.3),
`expires_at_ms`, `created_at_ms`, `idle_expires_at_ms`,
`absolute_expires_at_ms`, `last_touched_at_ms`, `revoked`, and `tombstone`.

A payload that does not open or decode (`ErrPayloadUnreadable`), for example a
plaintext record or one sealed under a different
`storage.redis.encryption_secret`, is deleted with a revision check and reported
as not found. Callers then restart the affected state: the browser gets a fresh
anonymous session, and a stored consent is asked for again.

### 3.12 SAML Single Logout

SAML Single Logout state below `<prefix>idp:saml:slo`: LogoutRequest replay
markers, fan-out transactions with a request correlation index, and the
participant registry used to find service providers to notify. There is no
AuthnRequest or assertion replay key in Redis; AuthnRequest binding lives in
the `saml_flow` record.

| Key pattern | Type | TTL / lifetime | Code | Purpose |
|---|---|---|---|---|
| `<prefix>idp:saml:slo:replay:<hex>` | STRING | `identity.saml.default_expire_time` (1h fallback `defaultSLOReplayTTL`) | `checkAndRememberLogoutRequestID` (`SET NX`, `server/handler/frontend/idp/saml_slo_protocol.go`) | Inbound LogoutRequest replay protection. `<hex>` = SHA-256(`issuer + "\x1f" + request_id`). Value `"1"`. |
| `<prefix>idp:saml:slo:fanout:tx:<transaction_id>` | STRING | SLO replay TTL, re-set on every response | `storeSLOFanoutTransactionState`, `commitSLOFanoutResponse` (`saml_slo_fanout_state.go`) | Fan-out transaction state (plain JSON: pending requests, outcomes, counters). `<transaction_id>` is URL-query-escaped. Each LogoutResponse updates it with a `WATCH`/`MULTI` compare-and-swap and retries on conflict, so concurrent responses keep every outcome. Expires by TTL. |
| `<prefix>idp:saml:slo:fanout:req:<hex>` | STRING | SLO replay TTL; deleted after its response is committed | `storeSLOFanoutTransactionState`, `finishSLOFanoutResponse` | Correlation from an outbound LogoutRequest ID (`<hex>` = SHA-256(request_id)) to the transaction ID. |
| `<prefix>idp:saml:slo:index:<account>` | SET | raised to the longest participant (`EXPIRE NX`/`GT`) | `SessionRegistry.UpsertParticipant` (`server/idp/slo/registry.go`) | Per-account index; members are the full key names of participant keys. `<account>` is URL-query-escaped. |
| `<prefix>idp:saml:slo:participant:<account>:<hex>` | STRING | SAML session lifetime (`identity.saml.default_expire_time`) | `SessionRegistry.UpsertParticipant` | Active service-provider session for SLO fan-out (plain JSON `ParticipantSession{account, sp_entity_id, name_id, session_index, authn_instant}`). `<hex>` = SHA-256(SP entity ID). |

### 3.13 gRPC Authority

In split deployments the authority issues opaque backend references to edge
nodes, and edge nodes cache the OIDC bearer token they use to call an
authority. None of these keys uses `storage.redis.prefix`. The authority's
MFA idempotency store is in memory, not in Redis.

| Key pattern | Type | TTL / lifetime | Code | Purpose |
|---|---|---|---|---|
| `grpc:authority:backend_ref:<opaque_token>` | STRING | payload `ExpiresAt`, else 15 min (`defaultBackendRefTTL`) | `RedisBackendRefStore.Issue`, `Validate` (`server/handler/grpcauthority/backend_ref_store.go`), `defaultBackendRefKeyPrefix` | Authority-side payload (encrypted JSON `BackendRefPayload`) behind an opaque backend reference. `<opaque_token>` is base64url(32 random bytes). Only with `runtime.servers.grpc.authority.backend_refs.enabled`. |
| `<key_prefix><authority>:<client_id>` (default `grpc:authority_tokens:<authority>:<client_id>`) | STRING | until the token's `expires_at` (at least 1 s), rewritten on every fetch | `writeCachedToken`, `readCachedToken`, `cacheKey`, `tokenCacheCodec` (`server/grpcclient/authority/token_source.go`) | Edge-side caller bearer token shared by replicas. JSON `{token_digest, sealed}`: `token_digest` = `IndexDigest("authority-caller-token-cache-v1", access_token)`, `sealed` = encrypted JSON `{access_token, expires_at, issued_at}`. Records that do not open, including plaintext records of earlier releases, count as a cache miss. `key_prefix` is `runtime.clients.grpc.nauthilus_authorities.<name>.caller_auth.oidc_bearer.token_cache.key_prefix`. |
| `<key_prefix><authority>:<client_id>:lock` | STRING | `token_cache.refresh_lock_ttl` (10 s), `SET NX` | `acquireRefreshLock`, `releaseRefreshLock`, `lockKey` | Refresh lock so that one edge replica fetches a new token at a time. Value: a random token per acquisition (`crypto/rand.Text`); release runs `UnlockIfTokenMatches`, so a refresh that outlived the lock TTL keeps the lock of the next holder. |

### 3.14 Native Plugins

Native Go plugins reach Redis only through `Host.Redis()`
(`pluginapi/v1/services.go`, implemented by `server/pluginruntime/redis.go`):
read and write handles, pipelines, a key builder, and a named script
registry. The facade owns no keys. Construction rules:

- **Prefix**: `Keys().Key(...)` returns `<prefix>` + plugin key
  (`redisKeyBuilder`, `rediscli.BuildKey`; prefix wired by
  `pluginruntime.WithRedisPrefix` in `server/main_wiring.go`). There is no
  per-plugin namespace; bundled plugins avoid collisions by convention
  (`reputation:`, `clickhouse:authdedup:v3:`, `HAVEIBEENPWND:`). Keys sent on
  the raw handles without `Keys().Key` are not prefixed.
- **Slot helpers**: `SameSlot(keys, tag)` rewrites keys that do not share a
  tag to the caller's tag (`{nauthilus-plugin}` when the tag is empty).
  `Scripts().Run` always normalizes multi-key calls on Cluster with
  `{nauthilus-plugin}` (`defaultPluginScriptHashTag`), the same way as
  section 1.2.
- **Account tag**: `Host.Helpers().AccountTag(username)` returns
  `{acm-<md5_hex(username)>}`, identical to the Lua `nauthilus_keys.account_tag`
  (`pluginapi/v1/helpers/helpers.go`).
- Native backend plugins can hand an opaque payload to the core positive
  cache; it is stored in the `plugin_result` field of the `UCP:` hash
  (section 3.2).

The GeoIP plugin and the shared packages under `contrib/plugins/internal`
use no Redis.

**Reputation plugin** (`contrib/plugins/reputation`, keys built by
`stateKeyspace` in `storage_keys.go`). Every atomic step runs as one named
script, and all keys of one call share a tag (`{<subject_tag>}`,
`{manifest-<shard>}`, or `{manifest-meta}`), so no rewrite happens. The
in-process plugin and the standalone worker share this keyspace.

| Key pattern | Type | TTL / lifetime | Code | Purpose |
|---|---|---|---|---|
| `<prefix>reputation:{<subject_tag>}:state:<model_id>` | HASH | `retention` (required config), refreshed by every applied ingestion; reads never refresh | `stateKeyspace.subject`, `reputation.ingestion.v1` | Decayed risk and trust accumulators of one model for one subject (at most 96 fields). |
| `<prefix>reputation:{<subject_tag>}:seen:<model_id>` | ZSET | until `max(now + subject_seen_ttl, manifest expiry, previous)`; expired members pruned (at most 512 per call) | `reputation.ingestion.v1` | Replay protection: one entry per admitted event and model. |
| `<prefix>reputation:{<subject_tag>}:override` | HASH | operator TTL (`PEXPIRE`) or `PERSIST`; the logical `expires_at` is also enforced on read | `reputation.override.v1` | Model-independent operator override (`blocked`, `trusted`, `neutral`). |
| `<prefix>reputation:{<subject_tag>}:operator-audit` | HASH | 90 days, refreshed on every audited override change | `stateKeyspace.audit`, `reputation.override.v1` | Last operator receipt of the subject's override. |
| `<prefix>reputation:event:{manifest-meta}:allocation` | HASH | none; scripts reject the key when it has a TTL | `stateKeyspace.metadata`, `reputation.metadata.v1` | Allocation identity, generation, and drain fence of the whole manifest layer. |
| `<prefix>reputation:event:{manifest-meta}:models` | HASH | none (enforced) | `reputation.metadata.v1` | Registered immutable model fingerprints (at most 64). |
| `<prefix>reputation:event:{manifest-<shard>}:control` | HASH | none (enforced) | `stateKeyspace.control`, `reputation.control.v1` | Per-shard writer fence checked by every admission. `<shard>` is `00`–`0f`. |
| `<prefix>reputation:event:{manifest-<shard>}:manifest:<allocation_tag>` | STRING | `event_manifest_ttl` (required config), set once | `stateKeyspace.manifest`, `reputation.manifest.v1` | Immutable admitted event plan that binds subjects and contributions. |
| `<prefix>reputation:event:{manifest-<shard>}:subjects:<source_tag>` | ZSET | 1h, refreshed on every admission | `reputation.manifest.v1` | Per-source, per-shard new-subject quota (`maximum_new_subjects_per_source_hour` divided over 16 shards). |
| `<prefix>reputation:event:{manifest-<shard>}:events:<source_tag>` | ZSET | `event_manifest_ttl`, refreshed on every admission | `reputation.manifest.v1` | Per-source, per-shard live-manifest quota. |

Reputation derivations and values:

- `<subject_tag>`: opaque tag `hmac-sha256-v1:<key_version>:<43-char base64url HMAC>`
  of the canonical subject (kind `ip`, `network`, `asn`, `dns_domain`,
  `account`, or `service`) under `subject_scope`
  (`pluginapi/v1/opaque_identifier.go`). A key rotation addresses a different
  keyset.
- `<model_id>`: configured model identifier; the active and an optional
  shadow model each get their own `state` and `seen` keys.
- `<allocation_tag>`, `<source_tag>`: opaque tags under `manifest_scope`.
  `<shard>` = `sha256(allocation_tag)[0] mod 16` as two hex digits.
- `state:*` fields: `schema_version` (`reputation-state.v1`),
  `model_fingerprint`, `kind`, `expires_at`, `seen_until`,
  `last_independent_risk_at`, `last_independent_trust_at`,
  `last_authoritative_risk_at`, `<profile>_updated_at`, and
  `<profile>_<class>_risk|trust|samples` for the profiles `fast`,
  `operational`, `baseline` and each configured source class.
- `seen:*`: member = seen tag, score = manifest expiry (Redis time, seconds).
- `override`: `schema`, `tag`, `kind`, `band`, `reason`, `creator`,
  `created_at`, `expires_at` (0 = none), `audit_id`, `origin`.
  `operator-audit`: `schema`, `tag`, `kind`, `operation`
  (`override_put`, `override_delete`), `reason`, `creator`, `audit_id`,
  `previous_audit`, `origin`, `created_at`.
- `allocation`: `schema`, `identity`, `shards`, `generation`, `mode`
  (`active`, `draining`), `retention`, `previous_identity`, and drain audit
  fields. `models`: model ID to 64-hex fingerprint. `control`: `schema`,
  `identity`, `mode`.
- `manifest:*`: JSON `{schema, payload, fingerprint, created, expires, retention}`;
  no raw subject or event ID is stored. `subjects:*`: member = subject tag,
  score = admission + 3600. `events:*`: member = allocation tag, score =
  manifest expiry.

**ClickHouse and HaveIBeenPwned plugins.**

| Key pattern | Type | TTL / lifetime | Code | Purpose |
|---|---|---|---|---|
| `<prefix>clickhouse:authdedup:v3:<sha256_hex>` | STRING | `auth_dedup_ttl` (default 300 s), `SET NX` | `loginDedupKey` (`contrib/plugins/clickhouse/dedup.go`), `allowLoginWrite`, `dedupKeyPrefix` | Writes at most one ClickHouse login row per login context and outcome per window (success by default, failure only with `dedup_failure`). The digest covers username, client IP, protocol, service, method, client IDs, SAML entity, grant type, MFA state, authentication flags, HTTP status, status message, outcome, operation, markers, policy rule, and flow reference. Value `"1"`. Redis errors fail open. Row buffers are process-local, not Redis. |
| `<prefix>HAVEIBEENPWND:<md5_hex(account)>` | HASH | `redis_positive_ttl` (1h) after a positive count; `redis_negative_ttl` (24h) after a negative count or a sent mail; each write resets the key TTL | `redisHashKey`, `writeRedisHashCount` (`contrib/plugins/haveibeenpwnd/post_action.go`), `mail.go` | Cached HIBP k-anonymity counts. Field `<sha1_prefix5>` (first five hex characters of SHA-1 of the password) holds the leak count (`0` = not leaked); field `send_mail` = `"1"` once the notification was claimed (`HSETNX`). Shared with the Lua action `haveibeenpwnd.lua`. |
| `<prefix>HAVEIBEENPWND:GATE:<md5_hex(account)>:<sha1_prefix5>` | STRING | `gate_ttl` (default 5 min), `SET NX` | `claimLookupGate`, `redisGateKeyPrefix` | Single-flight gate before the outbound range lookup. Value `"1"`. |

### 3.15 Lua Plugins

The `nauthilus_redis` module (`server/lualib/redislib`) exposes raw commands,
pipelines, named pools, and a script registry to Lua. It owns no keys and
**never prefixes keys**. Construction rules:

- **Prefix**: bundled plugins build keys with
  `nauthilus_util.get_redis_key(request, key)`, which prepends
  `request.redis_prefix` (`definitions.LuaRequestRedisPrefix`, set from
  `storage.redis.prefix`). A literal key string is used verbatim.
- **Key builder**: the monitoring, protection, and response plugins and the
  brute-force hooks build their keys with `share/nauthilus_keys.lua`, so
  writers and readers share one layout: per-account keys
  `<prefix><namespace>:<acct_tag><username>:proto:<protocol>:<suffix>`,
  per-protocol sets `<prefix><name>:proto:<protocol>`, and global pattern keys
  `<prefix>multilayer:global:<global_tag><name>`.
- **Account tag**: `<acct_tag>` = `nauthilus_keys.account_tag(username)` =
  `{<KEY_HASHTAG_PREFIX><md5_hex(username)>}` (env `USE_KEY_HASHTAGS`, default
  `true`; `KEY_HASHTAG_PREFIX`, default `acm-`); empty when disabled. The tag
  is placed directly before the username segment.
- **Global tag**: `<global_tag>` = `nauthilus_keys.global_tag()` =
  `{<KEY_HASHTAG_PREFIX>global}` (default `{acm-global}`), empty when
  `USE_KEY_HASHTAGS` is disabled. It is placed directly after
  `multilayer:global:` in every key that `GPM_TrackAndCurrent` touches. All
  global pattern state therefore lives in one Cluster slot.
- **Cluster rewrite**: on a Cluster client, multi-key `redis_run_script`
  calls whose keys do not share one tag are rewritten with `{lua-nauthilus}`
  (`server/lualib/redislib/scripts.go`): an existing tag is replaced, a key
  without a tag gets `{lua-nauthilus}:` prepended in front of `<prefix>`.
  Plain commands and pipelines are never rewritten. The bundled scripts pass
  keys that share one tag, so they are sent unchanged:
  `ACM_TrackAndAggregate` and `ALM_TrackAndSnapshot` receive only keys with
  the account tag, and `GPM_TrackAndCurrent` only keys with the global tag.
  The global sets that a per-account script would otherwise mix in, the
  attacked-accounts ZSET and the password-spray ZSETs, are written with
  separate single-key `ZAddRemExpire` calls. With `USE_KEY_HASHTAGS=false`
  both tags are empty and the rewrite applies again, so keep hash tags
  enabled on Redis Cluster.
- **Write access**: the full module (writes, pipelines, scripts, named
  pools) is bound in every Lua runtime: init scripts, custom HTTP hooks, the
  cache-flush hook, Lua backends, and the authentication callbacks (subject
  and environment sources, Lua actions). The 4.0.0 to 4.1.0 releases gave the
  authentication callbacks a read-only allowlist; 4.1.1 removed it
  (`server/lua-plugins.d/POLICY_VM_COMPATIBILITY.md`).
- **Named pools**: `register_redis_pool` can create clients for other Redis
  servers; keys written through such a pool live there. `init/init.lua`
  optionally registers `CUSTOM_REDIS_POOL_NAME` and uploads its scripts there.
  The bundled plugins and the brute-force hooks resolve their handle with
  `share/nauthilus_redis_pool.lua`: the literal `"default"` (the server picks
  its read or write handle per call) or the connection of that pool. A pool
  name string as the first argument would silently select the default handle.
- `nauthilus_cache` is process-local, not Redis.

Variables: `<username>` is `request.username` (some plugins fall back to
`request.account`), `<protocol>` is `request.protocol` or `unknown`
(`nauthilus_keys.protocol`; the hooks take it from their `protocol` query
parameter), `<window>` is a window in seconds.

**Account and global monitoring** (`subject/account_centric_monitoring.lua`,
`environment/global_pattern_monitoring.lua`,
`environment/account_longwindow_metrics.lua`,
`subject/account_protection_mode.lua`, `environment/security_metrics.lua`,
`environment/failed_login_hotspot.lua`, `actions/failed_login_tracker.lua`):

| Key pattern | Type | TTL / lifetime | Code | Purpose |
|---|---|---|---|---|
| `<prefix>multilayer:account:<acct_tag><username>:proto:<protocol>:ips:<window>` (3600, 86400, 604800) | ZSET | 2 × window, sliding; older members pruned | `account_centric_monitoring.lua`, `ACM_TrackAndAggregate` | Unique client IPs per account and window (member IP, score Unix seconds). |
| `<prefix>multilayer:account:<acct_tag><username>:proto:<protocol>:fails:<window>` (same windows) | ZSET | 2 × window, refreshed on failures | same | Failed attempts per account and window (member = request session). |
| `<prefix>multilayer:account:<acct_tag><username>:proto:<protocol>:metrics:<window>` (same windows) | HASH | 2 × window, sliding | same | Per-window snapshot: `unique_ips`, `failed_attempts`, `ip_to_fail_ratio`, `last_updated`. Write-only. |
| `<prefix>multilayer:distributed_attack:accounts:proto:<protocol>` | ZSET | 2 × `GPM_ATTACK_TTL_SEC` (default 43200 s) when an account is flagged; members older than `GPM_ATTACK_TTL_SEC` pruned | `account_centric_monitoring.lua`, separate `ZAddRemExpire` call after a suspicious verdict | Accounts flagged as targets of a distributed attack (member username, score last flagging). Read by `account_protection_mode.lua`, `soft_delay.lua`, `dynamic_response.lua`, and the admin hook; the test hook adds members. |
| `<prefix>multilayer:global:<global_tag>auth_attempts:<window>` (60, 300, 900, 3600, 86400, 604800) | ZSET | 2 × window, sliding | `global_pattern_monitoring.lua`, `GPM_TrackAndCurrent` | Global attempts per window (member = request session). Read by `security_metrics.lua`. |
| `<prefix>multilayer:global:<global_tag>unique_ips:<window>` (same windows) | ZSET | 2 × window, sliding | same | Global unique client IPs per window. Read by `security_metrics.lua`. |
| `<prefix>multilayer:global:<global_tag>unique_users:<window>` (same windows) | ZSET | 2 × window, sliding | same | Global unique usernames per window. Read by `security_metrics.lua`. |
| `<prefix>multilayer:global:<global_tag>current_metrics` | HASH | none (the test hook sets 1h) | same | Current one-hour metrics: `attempts`, `unique_ips`, `unique_users`, `attempts_per_ip`, `attempts_per_user`, `ips_per_user`, `last_updated`. Read by `dynamic_response.lua` and the admin hook. |
| `<prefix>multilayer:global:<global_tag>historical_metrics:<YYYY-MM-DD-HH>` | HASH | 7 days, set when created | same | First snapshot of each UTC hour (same fields plus `timestamp`). Read by `dynamic_response.lua`. |
| `<prefix>multilayer:global:<global_tag>metrics:<unix_seconds>` | HASH | 1h | same | Last attempt seen in that second (`client_ip`, `username`, `timestamp`, `success`). Write-only. |
| `<prefix>hll:acct:<acct_tag><username>:proto:<protocol>:ips:86400` | STRING (HyperLogLog) | 48h, sliding | `account_longwindow_metrics.lua`, `ALM_TrackAndSnapshot` | Approximate unique scoped IPs in 24h. |
| `<prefix>hll:acct:<acct_tag><username>:proto:<protocol>:ips:604800` | STRING (HyperLogLog) | 14 days, sliding | same | Approximate unique scoped IPs in 7 days. |
| `<prefix>z:acct:<acct_tag><username>:proto:<protocol>:fails` | ZSET | 14 days, refreshed on failures; older than 7 days pruned | same | Failed attempts over 7 days (member = request session). |
| `<prefix>acct:<acct_tag><username>:proto:<protocol>:longwindow` | HASH | 24h, sliding | same | Long-window snapshot: `uniq_ips_24h`, `uniq_ips_7d`, `fails_24h`, `fails_7d`, `last_updated`. Read by `account_protection_mode.lua` and `soft_delay.lua`. |
| `<prefix>z:spray:pw:86400`, `<prefix>z:spray:pw:604800` | ZSET | 48h / 14 days, sliding | `account_longwindow_metrics.lua`, one `ZAddRemExpire` call per window when the request has a password | Global password-spray tokens (member = prepared password hash, correlatable with the core password history). Write-only. |
| `<prefix>top_failed_logins` | ZSET | none; trimmed to the top 100 | `failed_login_tracker.lua` | Failure counts of unknown usernames (member username, score count). Read by `failed_login_hotspot.lua`. |
| `<prefix>environment:failed_login_hotspot:last_snapshot` | STRING | `FAILED_LOGIN_SNAPSHOT_SEC` (30 s) | `failed_login_hotspot.lua` | Rate-limit gate for the top-N metrics snapshot (Unix seconds). |
| `<prefix>acct:<acct_tag><username>:proto:<protocol>:protection` | HASH | `PROTECT_MODE_TTL_SEC` (3600 s), sliding | `account_protection_mode.lua`, `HSetMultiExpire` | Account protection state: `active`, `reason`, `backoff_level`, `until_ts`, `updated`. |
| `<prefix>acct:protection_active:proto:<protocol>` | SET | `PROTECT_MODE_TTL_SEC`, sliding on the key | `account_protection_mode.lua`, `SAddMultiExpire` | Accounts currently in protection mode. |
| `<prefix>acct:<acct_tag><username>:proto:<protocol>:stepup` | HASH | `PROTECT_MODE_TTL_SEC`, sliding | `account_protection_mode.lua`, `HSetMultiExpire` | Step-up hint: `required`, `reason`, `until_ts`, `updated`. Read by `dynamic_response.lua`, which then adds the account to `multilayer:global:captcha_accounts`. |

**Dynamic response and other actions** (`actions/dynamic_response.lua`,
`actions/haveibeenpwnd.lua`, `actions/clickhouse.lua`):

| Key pattern | Type | TTL / lifetime | Code | Purpose |
|---|---|---|---|---|
| `<prefix>alerts:last_sent:<subject>` | STRING | `ADMIN_ALERT_COOLDOWN_SECONDS` (900 s) | `dynamic_response.lua` | Admin-mail cooldown per alert subject (`SEVERE THREAT ALERT`, `HIGH THREAT ALERT`, `MODERATE THREAT ALERT`, spaces included). |
| `<prefix>multilayer:global:settings` | HASH | none | `dynamic_response.lua`, admin and test hooks | Global protection switches and threat level: `captcha_enabled`, `rate_limit_enabled`, `monitoring_mode`, `rate_limit_max`, `threat_level`, `system_started_at`, `warmup_window_seconds`. No server component reads them. |
| `<prefix>multilayer:global:blocked_regions` | SET | 1h, sliding | `dynamic_response.lua` | Country codes flagged under a severe threat. |
| `<prefix>multilayer:global:captcha_accounts` | SET | 1h (high measures) or 15 min (step-up hint); the last writer sets the TTL | `dynamic_response.lua` | Accounts that should get a CAPTCHA or step-up. |
| `<prefix>multilayer:global:rate_limited_ips` | SET | 1h, sliding | `dynamic_response.lua` | Client IPs flagged for rate limiting. |
| `<prefix>multilayer:global:country:<country_code>` | STRING | 24h, sliding | `dynamic_response.lua`, `IncrementAndExpire` | Attempts per country in 24h. |
| `<prefix>multilayer:global:countries` | SET | 24h, sliding | `dynamic_response.lua`, `AddToSetAndExpire` | Distinct countries seen in 24h. |
| `<prefix>multilayer:bootstrap:first_seen_ts` | STRING | none; written once | `dynamic_response.lua`, admin hook | Warm-up start timestamp. |
| `<prefix>multilayer:global:ok_streak` | STRING | 1h, sliding; deleted on reset or elevated threat | `dynamic_response.lua` | Consecutive low-threat evaluations before monitoring mode is cleared. |
| `<prefix>HAVEIBEENPWND:<md5_hex(account)>`, `<prefix>HAVEIBEENPWND:GATE:<md5_hex(account)>:<sha1_prefix5>` | HASH, STRING | hard-coded: hash 3600 s after a hit, 86400 s otherwise; gate 300 s (the native plugin's TTL options do not apply) | `haveibeenpwnd.lua`, `nauthilus_send_mail_hash` | Same layout as the native HaveIBeenPwned plugin (section 3.14). |
| `<prefix>clickhouse:authdedup:<username>:<client_ip>` | STRING | 300 s, `SET NX` | `clickhouse.lua` (retired) | Dedup gate of the retired Lua ClickHouse action. The raw username and IP appear in the key. |

**Dovecot session director** (`subject/monitoring.lua`,
`hooks/dovecot-session-cleaner.lua`):

| Key pattern | Type | TTL / lifetime | Code | Purpose |
|---|---|---|---|---|
| `<prefix>DS:<account>` | HASH | none | `monitoring.lua`, `dovecot-session-cleaner.lua` | Session-to-backend map per account (field = Dovecot proxy target, value = backend host). |
| `<prefix>DS_ACCOUNT` | HASH | none | same | Reverse index from proxy target to account. |

**Demo hook** (`hooks/dynamic-textmap-demo.lua`):

| Key pattern | Type | TTL / lifetime | Code | Purpose |
|---|---|---|---|---|
| `<prefix>demo:textmap:content` | STRING | `TEXTMAP_DEMO_TTL_SECONDS` (60 s) | `dynamic-textmap-demo.lua` | Demo map body (`text/plain`). |
| `<prefix>demo:textmap:version` | STRING | none (`INCR`) | same | Monotonic content version (ETag source). |
| `<prefix>demo:textmap:last_modified` | STRING | `TEXTMAP_DEMO_TTL_SECONDS` | same | Unix seconds for `Last-Modified`. |

The hooks `distributed-brute-force-admin.lua` and
`distributed-brute-force-test.lua` read, reset, and simulate the dynamic
response and monitoring keys above through the same key builder and pool. The
admin `reset_account` action removes one account from the per-protocol
attacked-accounts and protection sets and from
`multilayer:global:captcha_accounts`, and deletes its per-account keys of that
protocol (`nauthilus_keys.account_keys`). It leaves the server's brute-force
state alone; the user flush (section 3.1) removes password histories,
toleration sets, and affected-account members. Bundled Lua plugins not
mentioned here use no Redis.

### 3.16 Legacy and Retired Keys

No code path writes the retired keys below; the server and the bundled
plugins never read them. They are listed so that operators and reviewers can
recognize residual data in Redis and know whether it expires on its own.

| Key pattern | Status | Notes |
|---|---|---|
| `<prefix>oidc:denied_access_token:<raw_jwt>` | Dual-written and read | Raw-JWT denylist key next to the digest key; see section 3.7. |
| `<prefix>idp:flow:<flow_id>` | Retired | IdP flow state (JSON) outside the canonical session model. `flow.RedisStore` has no production caller. `contrib/session-keyspace-retirement` removes it. |
| `<prefix>oidc:dcr:{dynamic}:dynamic_user_epoch:*`, `<prefix>oidc:dcr:{registry}:active` | Retired | No TTL; manual operator cleanup as described in `IDP.md`. |
| `<prefix>PW_HIST_IPS:<username>` | Retired | Upper-case name; the current key is `pw_hist_ips:<account>`. |
| `PW_HIST:<username>:<ip>`, `PW_HIST:<ip>`, `PW_HIST_META:<ip>` | Retired, unprefixed | The current password histories are the `pw_hist:` keys of section 3.1. |
| `bf:TR:<ip>`, `bf:TR:<ip>:P`, `bf:TR:<ip>:N` | Retired, unprefixed | The current toleration sets are the `bf:tr:` keys of section 3.1. |
| `<prefix>account:<username>:ips:3600`, `<prefix>account:<username>:fails:3600` | Retired | Per-account monitoring layout without `multilayer:`; the current keys are in section 3.15. |
| `<prefix>global:auth_attempts:<window>`, `<prefix>global:unique_ips:<window>`, `<prefix>global:unique_users:<window>` | Retired | Global monitoring layout without `multilayer:`. Expires through its TTL. |
| `<prefix>multilayer:distributed_attack:accounts` | Retired | Layout without `:proto:`. Expires through its TTL. |
| `<prefix>acct:<acct_tag><username>:longwindow`, `<prefix>acct:<acct_tag><username>:stepup` | Retired | Layouts without `:proto:`. |
| `<prefix>multilayer:global:<name>` without `<global_tag>`, for `<name>` = `auth_attempts:<window>`, `unique_ips:<window>`, `unique_users:<window>`, `current_metrics`, `historical_metrics:<hour>`, `metrics:<unix_seconds>` | Retired while hash tags are enabled | With `USE_KEY_HASHTAGS=false` these are the current names. With hash tags enabled they are residual data; all expire through their TTL except `<prefix>multilayer:global:current_metrics`, which has none and must be deleted manually. |
| `{lua-nauthilus}:<prefix>multilayer:global:*`, `<prefix>multilayer:account:{lua-nauthilus}<username>:*`, `<prefix>hll:acct:{lua-nauthilus}<username>:*`, `<prefix>z:acct:{lua-nauthilus}<username>:*`, `<prefix>acct:{lua-nauthilus}<username>:*`, `{lua-nauthilus}:<prefix>multilayer:distributed_attack:*`, `{lua-nauthilus}:<prefix>z:spray:*` | Retired, Redis Cluster only | Names the Cluster rewrite of section 1.2 gives to monitoring keys with mixed hash tags. The bundled scripts pass keys with one shared tag, so they never produce these names, and nothing reads them. All expire through their TTL except `{lua-nauthilus}:<prefix>multilayer:global:current_metrics`, which has none and must be deleted manually. |
| browser-session and IdP-flow namespaces outside `<prefix>:browser-session` | Retired | The canonical session runtime never reads them; see `server/docs/development/browser_session_contract.md` and `contrib/session-keyspace-retirement`. |

## 4. Redis Lua Scripts

### 4.1 Server Script Registry (`rediscli.LuaScripts`)

Defined in `server/rediscli/lua_scripts.go`. All entries are uploaded to the
write handle and every distinct read handle at startup (`UploadAllScripts`,
started from `server/script_upload.go`) and lazily on demand. Callers use
three paths:

- `ExecuteScript`: re-uploads and retries once on `NOSCRIPT`, normalizes keys
  and retries once on `CROSSSLOT`.
- `ScriptPipeline`: normalizes keys up front on Cluster and reruns only the
  calls that failed with `NOSCRIPT`; there is no `CROSSSLOT` retry.
- The brute-force bucket check sends raw `EVALSHA` on a read-handle pipeline
  with its own `NOSCRIPT` re-upload and no key normalization; it relies on
  both window keys sharing the bucket tag.

| Script | KEYS / ARGV | Callers | Why atomic |
|---|---|---|---|
| `IncrementAndExpire` | KEYS[1] counter; ARGV[1] TTL s | `burstLeaderGate` (`bf:burst:*`) | `INCR` and `EXPIRE` together, so exactly one caller sees 1 and the key always has a TTL (sliding). |
| `AddToSetAndExpire` | KEYS[1] set; ARGV member, TTL s | none in Go (only uploaded) | `SADD` and `EXPIRE` together. Bundled Lua plugins upload their own script under the same name. |
| `RecordTolerationEvent` | KEYS `bf:tr:*:P`, `bf:tr:*:N`; ARGV now, window, `positive`/`negative`, member, negative cap | `recordTolerationEvent` | Adds the event, trims both sets to the window, caps the negative set, and refreshes both TTLs as one unit. |
| `AddToSetAndExpireLimit` | KEYS[1] `pw_hist:*`; ARGV hash, TTL s, max entries | `saveFailedPasswordHash` | Capacity check, `SADD`, and `EXPIRE` must not interleave, or the bound could be exceeded. |
| `UnlockIfTokenMatches` | KEYS[1] lock; ARGV expected token | `releaseRefreshLock` (`releaseRefreshLockScript`, run with `redis.NewScript`) | Compare-and-delete lock release. |
| `RWPSlidingWindowCheck` | KEYS[1] `bf:rwp:allow:*`; ARGV hash, now, TTL, max (unused) | `isRepeatingWrongPassword`, pre-auth prefetch | Purges expired members, then tests the hash. It writes (`ZREMRANGEBYSCORE`), so it runs on the write handle. |
| `RWPSlidingWindowCommit` | same keys; ARGV[4] max unique hashes | `CommitRWPSlidingWindow` | Classifies before mutating, then adds, evicts the oldest, and refreshes the TTL, so parallel failures cannot share a stale verdict. |
| `SlidingWindowCounter` | KEYS current and previous window; ARGV increment, weight, TTL, base limit, adaptive and static toleration parameters, positive reputation count, RWP floor | bucket check pipeline (read handle, increment 0), `SaveBruteForceBucketCountersToRedis` (write), `loadBruteForceBucketCounter` | Reads both windows, applies the reputation-scaled limit, optionally increments, and sets the TTL only on creation in one step. This is why scripts are also uploaded to read handles. |

### 4.2 Inline Go Scripts

These scripts are defined next to their callers with `redis.NewScript`
(`EVALSHA` with `EVAL` fallback) or run with `Eval`.

| Script | Defined in | Keys | Why atomic |
|---|---|---|---|
| `affectedAccountsExpireScript` | `server/bruteforce/affected_accounts_maintenance.go` | `affected_accounts`, `{…}:retention` | Removes a member from the set and the retention ZSET only while its deadline is still due, so a concurrent extension is never undone. |
| `affectedAccountsAdoptScript` | same | same | Writes deadlines (`nx` adopt or `gt` re-arm) only for members still in the set, so a concurrent flush is not resurrected. |
| `mfaAttemptScript` | `server/core/mfa_attempts.go` | `mfa:attempt:{…}` | Check and increment in one step; `EXPIRE` only on the first `INCR` keeps the window fixed. Returns 1 (reserved) or 0 (limit reached). |
| `compareAndDeleteTokenScript` | `server/grpcclient/authority/token_source.go` | token cache key | Deletes the cached bearer token only if its `token_digest` still matches the rejected token (`cjson.decode`), so a token another replica just refreshed survives. |
| `subjectEpochAdvanceScript` | `server/idp/redis_storage_keys.go` | subject epoch | `SET NX floor` then `INCR`, so the first revocation yields floor + 1. |
| `dynamicTrackedStoreScript` | `server/idp/redis_storage.go` | token record, index, epoch | Stores a token only while the epoch matches, adds it to the index, and raises the index TTL, so issuance cannot race a revocation. |
| `dynamicInitialRefreshStoreScript` | same | refresh record, index, family, epoch | As above, and publishes the family pointer. |
| `dynamicRefreshRotateScript` | same | old and new record, consumed marker, index, family, revoked marker, epoch | Rotation with reuse detection: returns rotated, unknown, consumed (revokes the family), revoked, or epoch changed. Builds the active-token key from an ARGV prefix inside the same slot. |
| `dynamicRefreshResolveScript` | same | record, consumed marker, epoch | Reads the record and epoch together; a consumed ancestor revokes the family. Builds family, token, and revoked keys from ARGV prefixes inside the same slot. |
| `staticRefreshConsumeScript` | same | static record, index, epoch | Single-use claim: succeeds only if the epoch is current and the ciphertext is unchanged since the read. |
| `trackedTokenDeleteScript` | same | record, index | Deletes a record and its index membership together. |
| `registrationScript` | `server/idp/dcr/repository.go` | `{registry}:clients` | Quota check and `ZADD NX` together. |
| `registrationAttemptScript` | same | the three rate keys | Checks all three budgets before incrementing any. |
| `touchIndexScript` | same | `{registry}:clients` | Extends the score only while the client is still active. |
| `touchRecordScript` | same | client record | Rewrites the record with `KEEPTTL` only if it still exists (no resurrection). |
| `redisCommitScript` | `server/sessionstate/redis_store.go` | one record | Compare-and-swap create or update plus `PEXPIRE`. |
| `redisDeleteScript` | same | one record | Revision-checked delete. |
| `redisConsumeScript` | same | one record | Revision-checked read and delete (single use). |
| `redisIndexedDeleteScript` | same | anchor, child | Rewrites the anchor index and deletes the child in one CAS step. |
| `redisIndexedConsumeScript` | same | anchor, child | Returns the child and removes it and its anchor index entry atomically. |
| `redisTouchScript` | same | anchor and its logout index (same tag) | Sliding idle refresh capped at the absolute expiry, applied to the anchor and the listed children together; rejects revoked or tombstoned anchors. Called by `CanonicalRuntime.Open`. |
| `redisTransactionScript` | same | anchor and N children (same tag) | Multi-record CAS commit (login completion, indexed commits). |
| `redisRevokeScript` | same | anchor | Tombstones the anchor before its children are deleted. |

### 4.3 Native Plugin Scripts

Native plugins register scripts through `Host.Redis().Scripts()`
(`redisScriptRegistry` in `server/pluginruntime/redis.go`). Names must match
`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`. `Upload` loads on the write handle and
best effort on all read handles; `Run` always executes `EVALSHA` on the write
handle and reloads once on `NOSCRIPT`. The registry is shared by all modules
of a process, so a later upload under the same name replaces the earlier
one.

The reputation plugin uploads six scripts at start
(`contrib/plugins/reputation/storage.go`). Each source is a shared preamble
plus `scripts/common.lua`, `scripts/state.lua`, `scripts/override_state.lua`,
and the operation script; ARGV[1] is always one JSON request.

| Script | Keys | Why atomic |
|---|---|---|
| `reputation.ingestion.v1` | `state`, `seen` | Validates, decays, and increments one subject and model, checks and records the seen tag, and sets both TTLs in one slot, so a partial fan-out can resume without double counting. |
| `reputation.assessment.v1` | `state`, `seen`, `override` (+ `operator-audit` with details) | Read-only snapshot with Redis `TIME`: decayed state, override band, optional audit. Never refreshes TTLs. |
| `reputation.override.v1` | `override` (+ `operator-audit`) | Compare-and-set put, delete, or get keyed on the previous audit ID, writing the audit receipt in the same step. |
| `reputation.metadata.v1` | `{manifest-meta}:allocation`, `{manifest-meta}:models` | Activate, status, begin and finish drain of the allocation identity and model registry; older writers cannot reopen the fence. |
| `reputation.control.v1` | one `{manifest-<shard>}:control` | Activate, drain, or report one shard fence. |
| `reputation.manifest.v1` | `manifest`, `control`, `subjects`, `events` (one shard) | Checks the shard fence, compares or creates the immutable manifest, and reserves per-source quotas in one step. |

### 4.4 Lua Plugin Scripts

Lua code registers scripts with `nauthilus_redis.redis_upload_script(conn, source, name)`
(`server/lualib/redislib/scripts.go`): `SCRIPT LOAD` on the selected handle
and best effort on every read handle, stored process-globally as
`name -> {sha1, source}`. `redis_run_script` uses `EVALSHA` by name and
re-uploads once on `NOSCRIPT`; with an empty name it runs `EVAL`. Names are
not namespaced and are independent of `rediscli.LuaScripts`, even where the
names match.

`init/init.lua` uploads these scripts for the bundled plugins:

| Script | Keys | Used by | Why atomic |
|---|---|---|---|
| `nauthilus_send_mail_hash` | `HAVEIBEENPWND:<md5>` | `haveibeenpwnd.lua` | Test-and-set of the `send_mail` field, so only one worker sends the leak notification. Returns `{'send_mail', key}` to the claiming worker, which then sends the mail, and `{'email_already_sent'}` otherwise. |
| `ZAddRemExpire` | one ZSET | `account_centric_monitoring.lua` (attacked-accounts flag), `account_longwindow_metrics.lua` (spray windows), `distributed-brute-force-test.lua` | `ZADD`, prune by score, and `EXPIRE` as one sliding-window update. |
| `HSetMultiExpire` | one HASH | protection mode, dynamic response, admin and test hooks | Multi-field `HSET` plus `EXPIRE` when the TTL is positive (TTL 0 keeps an existing TTL). |
| `SAddMultiExpire` | one SET | protection mode, dynamic response | Multi-member `SADD` plus `EXPIRE` when the TTL is positive. |
| `ExistsHSetMultiExpire` | one HASH | none | Writes only if the key does not exist yet. |
| `IncrementAndExpire` | one STRING | dynamic response, test hook | `INCR` plus `EXPIRE` (own copy, not the server registry entry). |
| `ACM_TrackAndAggregate` | 3 `ips`, 3 `fails`, 3 `metrics` keys, all with `<acct_tag>` (`nauthilus_keys.account_window_keys`) | `account_centric_monitoring.lua` | Updates three windows and recomputes counts and the suspicion verdict in one round trip. The caller flags a suspicious account in the attacked-accounts ZSET with a separate `ZAddRemExpire` call. |
| `GPM_TrackAndCurrent` | attempts, IPs, and users ZSET per window, current, historical, and per-second HASH, all with `<global_tag>` (`nauthilus_keys.global_pattern_keys`) | `global_pattern_monitoring.lua` | Updates all global windows, writes the current snapshot, and creates the hourly snapshot once. |
| `ALM_TrackAndSnapshot` | two HLLs, failure ZSET, long-window HASH, all with `<acct_tag>` (`nauthilus_keys.account_longwindow_keys`) | `account_longwindow_metrics.lua` | HLL and ZSET updates plus the long-window snapshot in one step. The caller writes password-spray tokens with separate `ZAddRemExpire` calls. |
| `AddToSetAndExpire` | one SET | dynamic response, test hook | `SADD` plus `EXPIRE` (own copy). |

## 5. Redis Usage Without Keys

- **Pub/Sub `bf:blocks`** (`definitions.RedisBFBlocksChannel`, unprefixed):
  `BroadcastBlock` publishes JSON `{"key", "rule", "block"}` when a ban is
  activated; `server/app/loopsfx/bruteforce_sync_service.go` subscribes on the
  read handle and updates the in-process L1 decision engine. L1 keys (`net:`,
  `bfdec:`, `wl:`, `swl:`, `rep:`) live in memory only.
- **CLIENT TRACKING**: with `storage.redis.client_tracking.enabled`, every
  connection sends `CLIENT TRACKING ON` with the configured options and
  prefixes (`server/rediscli/client.go`) and uses RESP3 unless
  `storage.redis.protocol` is set explicitly. No Go code
  consumes the invalidation messages; process-local caches keep their own
  TTLs.
- **Server configuration**: on client creation the server runs
  `CONFIG SET latency-monitor-threshold 100` on the write handle (failure only
  logs a warning).
- **Monitoring**: every 10 s `INFO` on the write handle and a distinct read
  handle, and `LATENCY LATEST` on the write handle
  (`server/rediscli/metrics.go`). `/healthz` sends `PING` to both handles.
  There are no heartbeat or readiness keys.
- **Batching** (`storage.redis.batching.*`, `server/rediscli/batching.go`):
  groups single commands into short pipelines; blocking commands, Pub/Sub,
  `hello`, `client`, `config`, and `script` are never batched. Keys are not
  changed.
- **Transactions and pipelines**: `WATCH`/`MULTI` for async jobs, device
  code transitions, and SLO fan-out responses (`commitSLOFanoutResponse`);
  `TxPipeline` for dynamic refresh revocation and DCR expiry; plain pipelines
  for the positive cache, the pre-auth prefetch, the flushes, the initial SLO
  fan-out store, and the SLO participant registry.
- **Look-alike names that are not Redis keys**: several components use
  Redis-style names for process-local memory. They never reach Redis:
  ClickHouse plugin buffers (`clickhouse:batch:*`), brute-force L1 entries
  (`net:`, `bfdec:`, `wl:`, `swl:`, `rep:`), singleflight keys (`tol:`), Lua
  VM pool names (`backend:`, `hook:`, `action:`, `cacheflush:`), and
  `nauthilus_cache` / module-cache entries of plugins (`hibp:`, `prot:`,
  `sdm:`, `geoip:`, `policy:`, `info:`, `env:`, `testing_csv:`).
- **Iteration**: `SSCAN` and `ZSCAN` over the affected-account set and index
  (cursors persisted in the maintenance hash), `HSCAN` over account-mapping
  shards. Go code never runs `SCAN` or `KEYS` over the keyspace; only the
  offline tool `contrib/session-keyspace-retirement` scans legacy namespaces.
  Lua code can, because `nauthilus_redis` exposes `redis_keys` and
  `redis_scan` (also on the read-only Policy-VM surface); no bundled plugin
  calls them.
