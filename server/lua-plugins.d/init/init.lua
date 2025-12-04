-- Copyright (C) 2024 Christian Rößner
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program. If not, see <https://www.gnu.org/licenses/>.

local nauthilus_util = require("nauthilus_util")

local nauthilus_prometheus = require("nauthilus_prometheus")
local nauthilus_psnet = require("nauthilus_psnet")
local nauthilus_redis = require("nauthilus_redis")

local time = require("time")

local N = "init"

-- Wait until Redis is reachable before any Redis-dependent init work starts.
-- Uses ping loop with optional exponential backoff. Crashes the pod on timeout.
local function wait_for_redis(client, logging)
    local timeout_sec = tonumber(os.getenv("INIT_REDIS_WAIT_TIMEOUT_SEC") or "30") or 30
    local interval_ms = tonumber(os.getenv("INIT_REDIS_PING_INTERVAL_MS") or "200") or 200
    local backoff_enabled = (os.getenv("INIT_REDIS_BACKOFF_ENABLED") or "true"):lower()
    backoff_enabled = (backoff_enabled == "1" or backoff_enabled == "true" or backoff_enabled == "yes")
    local backoff_max_ms = tonumber(os.getenv("INIT_REDIS_BACKOFF_MAX_MS") or "2000") or 2000

    local deadline = os.time() + timeout_sec
    local attempts = 0
    local next_sleep = interval_ms

    while true do
        attempts = attempts + 1
        local ok, pong = pcall(nauthilus_redis.redis_ping, client)
        if ok and (pong == true or pong == "PONG" or pong == 1) then
            if logging and (logging.log_level == "debug" or logging.log_level == "info") then
                nauthilus_util.print_result(logging, {
                    caller = N .. ".lua",
                    level = "info",
                    message = "Redis ping successful",
                    attempts = attempts,
                })
            end
            return
        end

        if os.time() >= deadline then
            nauthilus_util.if_error_raise("init.lua: Redis not reachable within timeout (" .. tostring(timeout_sec) .. "s)")
            return -- unreachable
        end

        -- Sleep with optional exponential backoff
        if backoff_enabled then
            next_sleep = math.min(next_sleep * 2, backoff_max_ms)
        end
        -- Use time.sleep_ms when available; fallback to seconds sleep
        local slept = false
        if time and time.sleep_ms then
            local s_ok = pcall(time.sleep_ms, next_sleep)
            slept = s_ok == true or s_ok == nil -- pcall returns true plus returns; consider true as slept
        end
        if not slept and time and time.sleep then
            pcall(time.sleep, next_sleep / 1000.0)
        end
    end
end

function nauthilus_run_hook(logging)
    local result = {}

    result.level = "info"
    result.caller = N .. ".lua"

    local custom_pool = "default"
    local custom_pool_name =  os.getenv("CUSTOM_REDIS_POOL_NAME")
    if custom_pool_name ~= nil and  custom_pool_name ~= "" then
        local _, err_redis_reg = nauthilus_redis.register_redis_pool(custom_pool_name, "standalone", {
            address = "localhost:6379",
            password = "",
            db = 3,
            pool_size = 10,
            min_idle_conns = 1,
            tls_enabled = false
        })
        nauthilus_util.if_error_raise(err_redis_reg)

        local err_redis_client

        custom_pool, err_redis_client = nauthilus_redis.get_redis_connection(custom_pool_name)
        nauthilus_util.if_error_raise(err_redis_client)
    end

    -- Before any Redis script uploads or commands, ensure Redis is reachable.
    wait_for_redis(custom_pool, logging)

    local script = [[
        local redis_key = KEYS[1]
        local send_mail = redis.call('HGET', redis_key, 'send_mail')

        if send_mail == false then
            redis.call('HSET', redis_key, 'send_mail', '1')

            return {'send_email', redis_key}
        else
            return {'email_already_sent'}
        end
    ]]

    local upload_script_name = "nauthilus_send_mail_hash"
    local sha1, err_upload = nauthilus_redis.redis_upload_script(custom_pool, script, upload_script_name)
    nauthilus_util.if_error_raise(err_upload)
    result[upload_script_name] = sha1

    -- Upload required Redis Lua scripts used by security features
    -- 1) ZAddRemExpire: ZADD score member; ZREMRANGEBYSCORE -inf min_score; EXPIRE ttl
    local zadd_script = [[
        local key = KEYS[1]
        local score = tonumber(ARGV[1])
        local member = ARGV[2]
        -- ARGV[3] currently unused/reserved
        local min_score = tonumber(ARGV[4])
        local ttl = tonumber(ARGV[5]) or 0

        redis.call('ZADD', key, score, member)
        if min_score ~= nil then
            redis.call('ZREMRANGEBYSCORE', key, '-inf', min_score)
        end
        if ttl ~= nil and ttl > 0 then
            redis.call('EXPIRE', key, ttl)
        end
        return 1
    ]]
    local zadd_sha1, zadd_err = nauthilus_redis.redis_upload_script(custom_pool, zadd_script, "ZAddRemExpire")
    nauthilus_util.if_error_raise(zadd_err)
    result["ZAddRemExpire"] = zadd_sha1

    -- 2) HSetMultiExpire: HSET multiple fields then EXPIRE ttl
    local hset_multi_script = [[
        local key = KEYS[1]
        local ttl = tonumber(ARGV[1]) or 0
        local i = 2
        while i <= #ARGV do
            local field = ARGV[i]
            local value = ARGV[i + 1]
            redis.call('HSET', key, field, value)
            i = i + 2
        end
        if ttl ~= nil and ttl > 0 then
            redis.call('EXPIRE', key, ttl)
        end
        return 1
    ]]
    local hset_multi_sha1, hset_multi_err = nauthilus_redis.redis_upload_script(custom_pool, hset_multi_script, "HSetMultiExpire")
    nauthilus_util.if_error_raise(hset_multi_err)
    result["HSetMultiExpire"] = hset_multi_sha1

    -- 3) SAddMultiExpire: SADD multiple members then EXPIRE ttl
    local sadd_multi_script = [[
        local key = KEYS[1]
        local ttl = tonumber(ARGV[1]) or 0
        for i = 2, #ARGV do
            redis.call('SADD', key, ARGV[i])
        end
        if ttl ~= nil and ttl > 0 then
            redis.call('EXPIRE', key, ttl)
        end
        return 1
    ]]
    local sadd_multi_sha1, sadd_multi_err = nauthilus_redis.redis_upload_script(custom_pool, sadd_multi_script, "SAddMultiExpire")
    nauthilus_util.if_error_raise(sadd_multi_err)
    result["SAddMultiExpire"] = sadd_multi_sha1

    -- 4) ExistsHSetMultiExpire: if not EXISTS then HSET multiple then EXPIRE ttl
    local exists_hset_script = [[
        local key = KEYS[1]
        if redis.call('EXISTS', key) == 1 then
            return 0
        end
        local ttl = tonumber(ARGV[1]) or 0
        local i = 2
        while i <= #ARGV do
            local field = ARGV[i]
            local value = ARGV[i + 1]
            redis.call('HSET', key, field, value)
            i = i + 2
        end
        if ttl ~= nil and ttl > 0 then
            redis.call('EXPIRE', key, ttl)
        end
        return 1
    ]]
    local exists_hset_sha1, exists_hset_err = nauthilus_redis.redis_upload_script(custom_pool, exists_hset_script, "ExistsHSetMultiExpire")
    nauthilus_util.if_error_raise(exists_hset_err)
    result["ExistsHSetMultiExpire"] = exists_hset_sha1

    -- 5) IncrementAndExpire: INCR key then EXPIRE ttl
    local incr_script = [[
        local key = KEYS[1]
        local ttl = tonumber(ARGV[1]) or 0
        local val = redis.call('INCR', key)
        if ttl ~= nil and ttl > 0 then
            redis.call('EXPIRE', key, ttl)
        end
        return val
    ]]
    local incr_sha1, incr_err = nauthilus_redis.redis_upload_script(custom_pool, incr_script, "IncrementAndExpire")
    nauthilus_util.if_error_raise(incr_err)
    result["IncrementAndExpire"] = incr_sha1

    -- 6) ACM_TrackAndAggregate: single server-side processing for account_centric_monitoring
    --    Keys (order):
    --      1..3: ips:{w} for w in {W1,W2,W3}
    --      4..6: fails:{w} for w in {W1,W2,W3}
    --      7..9: metrics:{w} for w in {W1,W2,W3}
    --      10: attacked_accounts_key
    --    ARGV: now_ts, client_ip, fail_id, is_authenticated (0|1), attack_ttl,
    --          TH_UNIQ_1H, TH_UNIQ_24H, TH_UNIQ_7D, TH_FAIL_MIN_24H, TH_RATIO,
    --          W1, W2, W3, username
    local acm_script = [[
        local now_ts = tonumber(ARGV[1])
        local client_ip = ARGV[2]
        local fail_id = ARGV[3]
        local is_auth = tonumber(ARGV[4]) or 0
        local attack_ttl = tonumber(ARGV[5]) or 43200
        local TH_U1H = tonumber(ARGV[6]) or 12
        local TH_U24H = tonumber(ARGV[7]) or 25
        local TH_U7D = tonumber(ARGV[8]) or 60
        local TH_F24H = tonumber(ARGV[9]) or 8
        local TH_RATIO = tonumber(ARGV[10]) or 1.2
        local W1 = tonumber(ARGV[11]) or 3600
        local W2 = tonumber(ARGV[12]) or 86400
        local W3 = tonumber(ARGV[13]) or 604800
        local username = ARGV[14]

        local wins = {W1, W2, W3}

        local function process_window(i, z_ips, z_fails, h_metrics, win)
            -- write ip
            redis.call('ZADD', z_ips, now_ts, client_ip)
            redis.call('ZREMRANGEBYSCORE', z_ips, '-inf', now_ts - win)
            redis.call('EXPIRE', z_ips, win * 2)
            -- write fail when unauthenticated
            if is_auth == 0 and fail_id ~= nil and fail_id ~= '' then
                redis.call('ZADD', z_fails, now_ts, fail_id)
                redis.call('ZREMRANGEBYSCORE', z_fails, '-inf', now_ts - win)
                redis.call('EXPIRE', z_fails, win * 2)
            end
            -- read counts
            local ui = tonumber(redis.call('ZCOUNT', z_ips, now_ts - win, now_ts)) or 0
            local fa = tonumber(redis.call('ZCOUNT', z_fails, now_ts - win, now_ts)) or 0
            local ratio = 0
            if fa > 0 then ratio = ui / fa end
            -- persist metrics
            redis.call('HSET', h_metrics, 'unique_ips', ui, 'failed_attempts', fa, 'ip_to_fail_ratio', ratio, 'last_updated', now_ts)
            redis.call('EXPIRE', h_metrics, win * 2)
            return ui, fa, ratio
        end

        local ui1, fa1, r1 = process_window(1, KEYS[1], KEYS[4], KEYS[7], wins[1])
        local ui2, fa2, r2 = process_window(2, KEYS[2], KEYS[5], KEYS[8], wins[2])
        local ui3, fa3, r3 = process_window(3, KEYS[3], KEYS[6], KEYS[9], wins[3])

        -- suspicion logic
        local ratio_ok = ((fa2 > 0 and r2 >= TH_RATIO) or (fa1 > 0 and r1 >= TH_RATIO))
        local suspicious = 0
        if ((ui1 >= TH_U1H or ui2 >= TH_U24H) and ui3 >= TH_U7D and fa2 >= TH_F24H and ratio_ok) then
            suspicious = 1
            -- add to attacked accounts
            local attacked_key = KEYS[10]
            redis.call('ZADD', attacked_key, now_ts, username)
            redis.call('ZREMRANGEBYSCORE', attacked_key, '-inf', now_ts - attack_ttl)
            redis.call('EXPIRE', attacked_key, attack_ttl * 2)
        end

        return {ui1, fa1, r1, ui2, fa2, r2, ui3, fa3, suspicious}
    ]]

    local acm_sha1, acm_err = nauthilus_redis.redis_upload_script(custom_pool, acm_script, "ACM_TrackAndAggregate")
    nauthilus_util.if_error_raise(acm_err)
    result["ACM_TrackAndAggregate"] = acm_sha1

    -- 6) AddToSetAndExpire: SADD member then EXPIRE ttl
    local addset_script = [[
        local key = KEYS[1]
        local member = ARGV[1]
        local ttl = tonumber(ARGV[2]) or 0
        redis.call('SADD', key, member)
        if ttl ~= nil and ttl > 0 then
            redis.call('EXPIRE', key, ttl)
        end
        return 1
    ]]
    local addset_sha1, addset_err = nauthilus_redis.redis_upload_script(custom_pool, addset_script, "AddToSetAndExpire")
    nauthilus_util.if_error_raise(addset_err)
    result["AddToSetAndExpire"] = addset_sha1

    -- common
    nauthilus_prometheus.create_gauge_vec("http_client_concurrent_requests_total", "Measure the number of total concurrent HTTP client requests", { "service" })
    -- Pre-instantiate gauge series for clickhouse so it appears with value 0
    if nauthilus_prometheus.set_gauge then
        nauthilus_prometheus.set_gauge("http_client_concurrent_requests_total", 0, { service = "clickhouse" })
    end

    -- analytics.lua
    nauthilus_prometheus.create_counter_vec("analytics_count", "Count the criteria which caused rejection", {"feature"})

    -- haveibeenpwnd.lua
    nauthilus_prometheus.create_histogram_vec("haveibeenpwnd_duration_seconds", "HTTP request to the haveibeenpwnd network", { "http" })
    nauthilus_psnet.register_connection_target("api.pwnedpasswords.com:443", "remote", "haveibeenpwnd")

    -- telegram.lua
    nauthilus_prometheus.create_histogram_vec("telegram_duration_seconds", "HTTP request to the telegram network", { "bot" })

    -- clickhouse.lua
    nauthilus_prometheus.create_histogram_vec("clickhouse_duration_seconds", "HTTP request to the clickhouse service", { "op" })

    -- backend.lua
    nauthilus_psnet.register_connection_target("127.0.0.1:3306", "remote", "backend")

    -- blocklist.lua
    local blocklist_addr = os.getenv("BLOCKLIST_SERVICE_ENDPOINT")
    if blocklist_addr then
        nauthilus_prometheus.create_histogram_vec("blocklist_duration_seconds", "HTTP request to the blocklist service", { "http" })
        nauthilus_psnet.register_connection_target(blocklist_addr, "remote", "blocklist")
    end

    -- geoip.lua
    local geoip_policyd_addr = os.getenv("GEOIP_POLICY_SERVICE_ENDPOINT")
    if geoip_policyd_addr then
        nauthilus_prometheus.create_histogram_vec("geoippolicyd_duration_seconds", "HTTP request to the geoip-policyd service", { "http" })
        nauthilus_prometheus.create_counter_vec("geoippolicyd_count", "Count GeoIP countries", { "country", "status" })
        nauthilus_psnet.register_connection_target(geoip_policyd_addr, "remote", "geoippolicyd")
    end

    -- failed_login_hotspot.lua
    nauthilus_prometheus.create_gauge_vec("failed_login_hotspot_user_score", "Failed login ZSET score for username", { "username" })
    nauthilus_prometheus.create_gauge_vec("failed_login_hotspot_user_rank", "Rank within top failed-logins for username (lower is hotter)", { "username" })
    nauthilus_prometheus.create_gauge_vec("failed_login_hotspot_top_score", "Top-N failed login scores snapshot", { "rank", "username" })
    nauthilus_prometheus.create_gauge_vec("failed_login_hotspot_topn_size", "Size of Top-N snapshot for failed logins", { })
    nauthilus_prometheus.create_counter_vec("failed_login_hotspot_count", "Count of failed-login hotspot triggers", { "state" })

    -- security_* metrics from attacker_detection_ideas.md
    -- Note: For per-user metrics we include a 'username' label to avoid overwriting and to make values inspectable per account.
    nauthilus_prometheus.create_gauge_vec("security_unique_ips_per_user", "Unique IPs seen per user over time windows", { "username", "window" })
    nauthilus_prometheus.create_gauge_vec("security_account_fail_budget_used", "Number of failures for user over time windows", { "username", "window" })
    nauthilus_prometheus.create_gauge_vec("security_global_ips_per_user", "Global ratio of unique IPs to unique users over time windows", { "window" })
    nauthilus_prometheus.create_gauge_vec("security_accounts_in_protection_mode_total", "Current number of accounts in protection mode", { })
    nauthilus_prometheus.create_counter_vec("security_sprayed_password_tokens_total", "Count of observed privacy-preserving sprayed password tokens", { "window" })
    nauthilus_prometheus.create_counter_vec("security_stepup_challenges_issued_total", "Number of step-up challenges issued (hint flags set)", { })
    nauthilus_prometheus.create_counter_vec("security_pow_challenges_issued_total", "Number of proof-of-work challenges issued", { })
    nauthilus_prometheus.create_counter_vec("security_slow_attack_suspicions_total", "Heuristic slow-attack suspicions", { })

    -- Ensure zero-valued time series exist so dashboards don't show N/A
    -- We "touch" counters (instantiate with labels) without incrementing.
    if nauthilus_prometheus.touch_counter then
        -- Sprayed password tokens per window
        nauthilus_prometheus.touch_counter("security_sprayed_password_tokens_total", { window = "24h" })
        nauthilus_prometheus.touch_counter("security_sprayed_password_tokens_total", { window = "7d" })
        -- Step-Up, PoW, and slow-attack suspicion (no labels)
        nauthilus_prometheus.touch_counter("security_stepup_challenges_issued_total", { })
        nauthilus_prometheus.touch_counter("security_pow_challenges_issued_total", { })
        nauthilus_prometheus.touch_counter("security_slow_attack_suspicions_total", { })
    end

    result.status = "finished"

    if logging.log_level == "debug" or logging.log_level == "info" then
        nauthilus_util.print_result(logging, result)
    end
end
