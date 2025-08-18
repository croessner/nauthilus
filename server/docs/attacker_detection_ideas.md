# Ideas for Detecting and Mitigating “Single‑Shot IP” Attackers (Low‑and‑Slow, No Fingerprinting)

This document outlines practical, fingerprint‑agnostic strategies to detect and mitigate attackers who use many unique IPs with exactly one login attempt each (password spraying/single‑shot pattern). The focus is on concepts and integration points with the existing Nauthilus architecture; implementation can follow later.

## What changed since the last draft
- Attacks are extremely slow and can span days.
- Device/browser fingerprinting is not a reliable signal:
  - IMAP: IMAP ID is often present for both legitimate users and attackers.
  - SMTP Submission: provides little to no useful client fingerprinting data.
  - OIDC: User‑Agent is easily spoofed.

Conclusion: we must assume no stable client fingerprint. Detection must be account‑centric and globally aggregated across long time windows (24h/7d) and work purely with robust signals like IP uniqueness, attempt timing, account‑level budgets, and password‑spray patterns. 

## Quick code map (current system)
- Core logic
  - server/core/bruteforce.go: AuthState.CheckBruteForce(...) orchestrates whitelists, protocol enablement, bucket rules, invokes BucketManager, and triggers Lua actions.
  - server/bruteforce/bruteforce.go: Redis‑backed BucketManager with counters, password history, pre‑result markers, network derivation, repeating‑wrong‑password detection.
  - server/core/auth.go: End‑to‑end auth flow incl. post‑Lua action, header/protocol handling, caching.
- Lua extensibility
  - server/lua-plugins.d/hooks/ and .../features/: HTTP‑exposed custom hooks and feature plugins; ideal for global patterning and dynamic responses.
- Documentation
  - server/docs/distributed_brute_force_detection.md: Detailed concept for distributed brute‑force detection via Lua/Redis (sliding windows, global and account‑centric metrics).

Takeaway: The rule‑based brute‑force system is strong. The gap is IP‑based limits when each IP only tries once. Solution: aggregate globally and think account‑first, with long windows and without ML or fingerprinting.

## Problem focus
- Attackers use many unrelated IPs (no clear ASN/provider clustering), exactly one attempt per IP.
- Per‑IP thresholds are ineffective; detection must use account, time, and spray patterns over long windows.

## Strategy (multi‑layered, fingerprint‑agnostic)

1) Account‑centric budgets and uniqueness over long windows
- Unique IPs per account (24h and 7d windows)
  - Data structure: HyperLogLog (HLL) per user and window (e.g., 1h/24h/7d).
  - Heuristic: if “unique IPs per account” is unusually high for 24h or 7d, place the account into a temporary protection mode.
- First‑seen IP greylisting per account (no fingerprinting required)
  - “New IP for this account” triggers delay/tarpit or Step‑Up (e.g., TOTP/WebAuthn) for a limited TTL.
  - IMAP/Submission: use protocol‑appropriate temporary failures or authentication delays rather than HTTP‑style challenges.
- Per‑account failure budgets (global across IPs)
  - Maintain failure budgets per account for 1h/24h/7d (e.g., allow small N per horizon). When budget is exceeded: 
    - enforce step‑up (OIDC),
    - add progressive backoff/temporary failures (IMAP/Submission),
    - slow down or deny further attempts for a cool‑down period.
- Temporal patterns without fingerprinting
  - Look for near‑uniform spacing or staircase patterns of single attempts over many days that deviate from the account’s usual behavior; use quantiles/hysteresis to avoid flapping.

2) Global low‑and‑slow detection
- Global unique‑IP velocity and accounts targeted
  - Track attempts, unique IPs, and unique users for 1h/24h/7d windows.
  - Derive metrics: attempts_per_ip, attempts_per_user, ips_per_user.
  - Compare to historical baselines (EWMA/quantiles). On anomaly: introduce small, system‑wide friction (e.g., +50–200 ms delay) or elevate account‑level protections for top‑targeted users.
- Password spraying without storing plaintext
  - Count prepared password tokens across many accounts/IPs using HMAC(secret, PreparePassword(pw)).
  - If a token spikes globally in 24h/7d windows, impose stricter controls for that token (e.g., immediate step‑up or stronger rate limits when that prepared password is attempted).

3) Protocol‑specific responses (without client fingerprinting)
- IMAP
  - Progressive backoff and temporary errors when an account is in protection mode or over budget.
  - Optional per‑account login‑delay after new IPs (e.g., small artificial latency).
- SMTP Submission
  - Respond with temporary failure codes and gradually increasing delays when account budgets are exhausted or spray patterns are detected. Avoid permanent blocks unless clearly malicious.
- OIDC (HTTP)
  - Risk‑based Step‑Up (TOTP/WebAuthn) for accounts in protection mode or when sprayed passwords are detected.
  - Optional Proof‑of‑Work (PoW) challenges for suspicious but not blocked flows; cache PoW completions by session to avoid repeated challenges for legitimate users.

4) Data structures and Redis key sketches (long windows)
- Sliding windows with ZSETs
  - Key: ntc:win:<scope>:<window>; member: request_id/ip/username; score: unix time.
  - Ops: ZADD, ZREMRANGEBYSCORE, ZCOUNT. Use windows like 3600, 86400, 604800. TTL ~2×window.
- Unique counts with HyperLogLog
  - Key: ntc:hll:acct:<username>:ips:<window>; PFADD ip; PFCOUNT returns cardinality.
- Password‑spray counters (privacy‑preserving)
  - Token: HMAC(secret, PreparePassword(pw)).
  - Per window ZSET/HLL to count token occurrences without storing plaintext passwords.
- Per‑account failures
  - ZSET key: ntc:z:acct:<username>:fails records failure timestamps.
  - Budgets for 1h/24h/7d are derived by ZCOUNT over respective windows; no separate counters required.

5) Integration points in Nauthilus
- Lua Feature plugin to collect metrics
  - Similar to global_pattern_monitoring.lua: update Redis ZSET/HLL on each auth attempt without blocking.
- Lua Action/Hook for dynamic responses
  - In AuthState.CheckBruteForce(...) post‑action read risk from Redis and apply: 
    - IMAP/Submission: temporary failures/backoffs,
    - OIDC: step‑up / PoW,
    - All: progressive delays.
- Reuse existing documentation
  - Complements server/docs/distributed_brute_force_detection.md with long‑window, account‑centric uniqueness and spray detection tailored to low‑and‑slow attacks.

6) Observability and metrics (Prometheus/Grafana)
- Suggested metrics
  - security_unique_ips_per_user{window="1h|24h|7d"}
  - security_accounts_in_protection_mode_total
  - security_account_fail_budget_used{window="1h|24h|7d"}
  - security_sprayed_password_tokens_total{window="24h|7d"}
  - security_stepup_challenges_issued_total
  - security_pow_challenges_issued_total
  - security_global_ips_per_user{window="24h|7d"}
  - security_slow_attack_suspicions_total (e.g., uniform spacing or long‑window anomalies)

7) Edge cases and false‑positive control
- NAT/CGNAT, mobile carriers, privacy IPv6 rotation, travel/remote work
  - Maintain soft whitelists/“known locations” per account and apply hysteresis.
  - Use graduated measures (delays, step‑up) before hard blocks.
- Dormant or typo‑prone usernames
  - Keep conservative default budgets and require admin review before permanent blocking.
- Transparency for admins
  - Admin hook to reset/status per account and to inspect long‑window metrics. Correlate logs with GUIDs.

## Example pseudocode (Lua/Redis) — long windows, no fingerprinting

Account HLL (unique IPs per user for 24h and 7d):

```lua
local function update_account_hll(redis, username, ip)
  local now = os.time()
  local windows = { 3600, 86400, 604800 } -- 1h, 24h, 7d
  for _, window in ipairs(windows) do
    local key = "ntc:hll:acct:" .. username .. ":ips:" .. window
    redis.call("PFADD", key, ip)
    redis.call("EXPIRE", key, window * 2)
  end
end

local function unique_ips_over(redis, username, window)
  local key = "ntc:hll:acct:" .. username .. ":ips:" .. window
  return tonumber(redis.call("PFCOUNT", key)) or 0
end
```

Per‑account failures and budgets (1h/24h/7d):

```lua
local function record_failure(redis, username)
  local now = os.time()
  local key = "ntc:z:acct:" .. username .. ":fails"
  redis.call("ZADD", key, now, tostring(now))
  -- Keep at most 7d in the set
  redis.call("ZREMRANGEBYSCORE", key, 0, now - 604800)
  redis.call("EXPIRE", key, 604800 * 2)
end

local function failures_in_window(redis, username, window)
  local now = os.time()
  local key = "ntc:z:acct:" .. username .. ":fails"
  return tonumber(redis.call("ZCOUNT", key, now - window, now)) or 0
end

local function is_under_protection(redis, username, thresholds)
  -- thresholds = { uniq_24h=U1, uniq_7d=U2, fail_24h=F1, fail_7d=F2 }
  local uniq24 = unique_ips_over(redis, username, 86400)
  local uniq7d = unique_ips_over(redis, username, 604800)
  local f24 = failures_in_window(redis, username, 86400)
  local f7d = failures_in_window(redis, username, 604800)
  return (uniq24 >= thresholds.uniq_24h) or
         (uniq7d >= thresholds.uniq_7d) or
         (f24 >= thresholds.fail_24h) or
         (f7d >= thresholds.fail_7d)
end
```

Password‑spray counters (privacy‑preserving):

```lua
-- pw_token is HMAC(secret, PreparePassword(pw)) provided by the caller
local function update_sprayed_pw(redis, pw_token)
  local now = os.time()
  local windows = { 86400, 604800 } -- 24h, 7d
  for _, window in ipairs(windows) do
    local key = "ntc:z:spray:pw:" .. window
    redis.call("ZADD", key, now, pw_token)
    redis.call("ZREMRANGEBYSCORE", key, 0, now - window)
    redis.call("EXPIRE", key, window * 2)
  end
end
```

## Rollout plan (incremental, low risk)
- Phase 1: Collect metrics only (Lua Feature plugin), build dashboards, validate thresholds over weeks.
- Phase 2: Enable soft measures (small delays, logging, admin hooks to reset). Prefer temporary failures for IMAP/Submission.
- Phase 3: Enable risk‑based Step‑Up/PoW/backoff; automate per‑account protection mode using long‑window signals.

## Closing remarks
Without ML and without fingerprinting, single‑shot IP password spraying can be mitigated by:
- detecting per‑account unique‑IP anomalies over 24h/7d,
- correlating global long‑window patterns and sprayed password tokens,
- responding adaptively with delays, temporary failures, and Step‑Up/PoW where applicable,
- all implemented with Redis/Lua via existing Nauthilus hooks and actions.
