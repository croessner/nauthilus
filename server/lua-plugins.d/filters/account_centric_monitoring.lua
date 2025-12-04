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

local N = "account_centric_monitoring"

local nauthilus_util = require("nauthilus_util")
local nauthilus_keys = require("nauthilus_keys")

local nauthilus_redis = require("nauthilus_redis")

-- Module-scope configuration (read once)
local windows = {3600, 86400, 604800} -- 1h, 24h, 7d

local function getenv_num(name, def)
    local v = tonumber(os.getenv(name) or "")
    if v == nil then return def end
    return v
end

local TH_UNIQ_1H = getenv_num("GPM_THRESH_UNIQ_1H", 12)
local TH_UNIQ_24H = getenv_num("GPM_THRESH_UNIQ_24H", 25)
local TH_UNIQ_7D = getenv_num("GPM_THRESH_UNIQ_7D", 60)
local TH_FAIL_MIN_24H = getenv_num("GPM_MIN_FAILS_24H", 8)
local TH_RATIO = getenv_num("GPM_THRESH_IP_TO_FAIL_RATIO", 1.2)
local ATTACK_TTL_SEC = getenv_num("GPM_ATTACK_TTL_SEC", 12 * 3600)

-- Gate the informational log to reduce overhead by default
local ACM_INFO_LOG = nauthilus_util.toboolean(os.getenv("ACM_INFO_LOG") or "")

-- Env thresholds (defaults conservative):
--  - GPM_THRESH_UNIQ_1H default 12
--  - GPM_THRESH_UNIQ_24H default 25
--  - GPM_THRESH_UNIQ_7D default 60
--  - GPM_MIN_FAILS_24H default 8
--  - GPM_THRESH_IP_TO_FAIL_RATIO default 1.2
--  - GPM_ATTACK_TTL_SEC default 43200 (12h)
--  - CUSTOM_REDIS_POOL_NAME optional pool

function nauthilus_call_filter(request)
    if request.no_auth then
        return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
    end

    -- Get Redis connection
    local custom_pool = "default"
    local custom_pool_name =  os.getenv("CUSTOM_REDIS_POOL_NAME")
    if custom_pool_name ~= nil and  custom_pool_name ~= "" then
        local err_redis_client

        custom_pool, err_redis_client = nauthilus_redis.get_redis_connection(custom_pool_name)
        nauthilus_util.if_error_raise(err_redis_client)
    end

    -- Track account-specific authentication attempts
    local timestamp = os.time()
    local username = request.username

    if not username or username == "" then
        return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
    end

    -- Hold per-window metrics explicitly
    local uniq_1h, uniq_24h, uniq_7d = 0, 0, 0
    local fails_1h, fails_24h, fails_7d = 0, 0, 0
    local ratio_1h, ratio_24h = 0, 0

    -- Fast path using server-side script (one RTT) when enabled
    local use_script = os.getenv("ACM_USE_SCRIPT")
    if use_script == nil or use_script == "" or nauthilus_util.toboolean(use_script) then
        local tag = nauthilus_keys.account_tag(username)
        local w1, w2, w3 = windows[1], windows[2], windows[3]

        -- Keys: ips[w1..3], fails[w1..3], metrics[w1..3], attacked_accounts
        local keys = {
            "ntc:multilayer:account:" .. tag .. username .. ":ips:" .. w1,
            "ntc:multilayer:account:" .. tag .. username .. ":ips:" .. w2,
            "ntc:multilayer:account:" .. tag .. username .. ":ips:" .. w3,
            "ntc:multilayer:account:" .. tag .. username .. ":fails:" .. w1,
            "ntc:multilayer:account:" .. tag .. username .. ":fails:" .. w2,
            "ntc:multilayer:account:" .. tag .. username .. ":fails:" .. w3,
            "ntc:multilayer:account:" .. tag .. username .. ":metrics:" .. w1,
            "ntc:multilayer:account:" .. tag .. username .. ":metrics:" .. w2,
            "ntc:multilayer:account:" .. tag .. username .. ":metrics:" .. w3,
            "ntc:multilayer:distributed_attack:accounts",
        }

        local fail_id
        if not request.authenticated then
            fail_id = request.request_id or tostring(timestamp)
        else
            fail_id = ""
        end

        local args = {
            timestamp,
            request.client_ip or "",
            fail_id,
            request.authenticated and 1 or 0,
            ATTACK_TTL_SEC,
            TH_UNIQ_1H, TH_UNIQ_24H, TH_UNIQ_7D, TH_FAIL_MIN_24H, TH_RATIO,
            w1, w2, w3,
            username,
        }

        local res, err_script = nauthilus_redis.redis_run_script(custom_pool, "", "ACM_TrackAndAggregate", keys, args)
        nauthilus_util.if_error_raise(err_script)

        -- Expect flat array: [ui1, fa1, r1, ui2, fa2, r2, ui3, fa3, suspicious]
        if nauthilus_util.is_table(res) then
            local ui1 = tonumber(res[1] or 0) or 0
            local fa1 = tonumber(res[2] or 0) or 0
            local r1 = tonumber(res[3] or 0) or 0
            local ui2 = tonumber(res[4] or 0) or 0
            local fa2 = tonumber(res[5] or 0) or 0
            local r2 = tonumber(res[6] or 0) or 0
            local ui3 = tonumber(res[7] or 0) or 0
            local fa3 = tonumber(res[8] or 0) or 0
            local suspicious = (tostring(res[9]) == "1" or res[9] == 1)

            uniq_1h, fails_1h, ratio_1h = ui1, fa1, r1
            uniq_24h, fails_24h, ratio_24h = ui2, fa2, r2
            uniq_7d, fails_7d = ui3, fa3

            if suspicious then
                -- Add to custom log for monitoring (parity with pipeline path)
                nauthilus_builtin.custom_log_add(N .. "_attack_detected", "true")
                nauthilus_builtin.custom_log_add(N .. "_username", username)
                nauthilus_builtin.custom_log_add(N .. "_uniq_ips_1h", uniq_1h)
                nauthilus_builtin.custom_log_add(N .. "_uniq_ips_24h", uniq_24h)
                nauthilus_builtin.custom_log_add(N .. "_uniq_ips_7d", uniq_7d)
                nauthilus_builtin.custom_log_add(N .. "_failed_24h", fails_24h)
                nauthilus_builtin.custom_log_add(N .. "_ratio_24h", ratio_24h)
            end

            -- Optional info log
            if ACM_INFO_LOG then
                local logs = {}
                logs.caller = N .. ".lua"
                logs.level = "info"
                logs.message = "Account metrics tracked"
                logs.username = username
                logs.uniq_ips_1h = uniq_1h
                logs.uniq_ips_24h = uniq_24h
                logs.uniq_ips_7d = uniq_7d
                logs.failed_1h = fails_1h
                logs.failed_24h = fails_24h
                logs.failed_7d = fails_7d
                logs.ratio_1h = ratio_1h
                logs.ratio_24h = ratio_24h
                logs.is_suspicious = suspicious

                nauthilus_util.print_result({ log_format = "json" }, logs)
            end

            return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
        end
        -- If script result unexpected, fall through to pipeline path
    end

    -- Stage 1: write events via master (ZAddRemExpire for IP and optionally FAIL)
    do
        local write_cmds = {}
        for _, window in ipairs(windows) do
            local ip_key = "ntc:multilayer:account:" .. nauthilus_keys.account_tag(username) .. username .. ":ips:" .. window
            table.insert(write_cmds, {"run_script", "ZAddRemExpire", {ip_key}, {timestamp, request.client_ip, 0, timestamp - window, window * 2}})

            if not request.authenticated then
                local fail_key_w = "ntc:multilayer:account:" .. nauthilus_keys.account_tag(username) .. username .. ":fails:" .. window
                local fail_id = request.request_id or (tostring(timestamp) .. "_" .. tostring(math.random(1000000)))
                table.insert(write_cmds, {"run_script", "ZAddRemExpire", {fail_key_w}, {timestamp, fail_id, 0, timestamp - window, window * 2}})
            end
        end

        if #write_cmds > 0 then
            local _, perr = nauthilus_redis.redis_pipeline(custom_pool, "write", write_cmds)
            nauthilus_util.if_error_raise(perr)
        end
    end

    -- Stage 2: read counts from replicas to offload master
    local read_cmds = {}
    for _, window in ipairs(windows) do
        local min_str = tostring(timestamp - window)
        local max_str = tostring(timestamp)
        local ip_key_r = "ntc:multilayer:account:" .. nauthilus_keys.account_tag(username) .. username .. ":ips:" .. window
        local fail_key_r = "ntc:multilayer:account:" .. nauthilus_keys.account_tag(username) .. username .. ":fails:" .. window
        table.insert(read_cmds, {"zcount", ip_key_r, min_str, max_str})
        table.insert(read_cmds, {"zcount", fail_key_r, min_str, max_str})
    end

    local rres, rerr = nauthilus_redis.redis_pipeline(custom_pool, "read", read_cmds)
    nauthilus_util.if_error_raise(rerr)

    -- Extract per-window values and compute ratios
    local vals = {}
    do
        local i = 1
        for _, window in ipairs(windows) do
            local ui = tonumber(rres[i] and rres[i].value or 0) or 0; i = i + 1
            local fa = tonumber(rres[i] and rres[i].value or 0) or 0; i = i + 1
            local ratio = 0
            if fa > 0 then ratio = ui / fa end
            vals[window] = {unique_ips = ui, failed_attempts = fa, ratio = ratio}

            if window == 3600 then
                uniq_1h, fails_1h, ratio_1h = ui, fa, ratio
            elseif window == 86400 then
                uniq_24h, fails_24h, ratio_24h = ui, fa, ratio
            elseif window == 604800 then
                uniq_7d, fails_7d = ui, fa
            end
        end
    end

    -- Batch: store per-window account metrics via HSetMultiExpire in a single write pipeline
    do
        local wcmds = {}
        for _, window in ipairs(windows) do
            local v = vals[window]
            local account_metrics_key = "ntc:multilayer:account:" .. nauthilus_keys.account_tag(username) .. username .. ":metrics:" .. window
            table.insert(wcmds, {"run_script", "HSetMultiExpire", {account_metrics_key}, {
                window * 2,
                "unique_ips", v.unique_ips,
                "failed_attempts", v.failed_attempts,
                "ip_to_fail_ratio", v.ratio,
                "last_updated", timestamp
            }})
        end
        if #wcmds > 0 then
            local _, perr2 = nauthilus_redis.redis_pipeline(custom_pool, "write", wcmds)
            nauthilus_util.if_error_raise(perr2)
        end
    end

    -- Suspicion logic (aims to reduce false positives due to carrier NAT/TOR)
    -- Require short-term AND long-term signals, minimum fails, and a healthy ratio
    local ratio_ok = false
    if (fails_24h > 0 and ratio_24h >= TH_RATIO) or (fails_1h > 0 and ratio_1h >= TH_RATIO) then
        ratio_ok = true
    end

    local is_suspicious = false
    if (
        (uniq_1h >= TH_UNIQ_1H or uniq_24h >= TH_UNIQ_24H) and
        uniq_7d >= TH_UNIQ_7D and
        fails_24h >= TH_FAIL_MIN_24H and
        ratio_ok
    ) then
        is_suspicious = true

        -- Add this account to the list of accounts under distributed attack using atomic Redis Lua script
        local attacked_accounts_key = "ntc:multilayer:distributed_attack:accounts"
        local _, err_script3 = nauthilus_redis.redis_run_script(
                custom_pool,
            "", 
            "ZAddRemExpire", 
            {attacked_accounts_key}, 
            {timestamp, username, 0, timestamp - ATTACK_TTL_SEC, ATTACK_TTL_SEC * 2}
        )
        nauthilus_util.if_error_raise(err_script3)

        -- Log the suspicious activity
        local attack_logs = {}
        attack_logs.caller = N .. ".lua"
        attack_logs.level = "warning"
        attack_logs.message = "Potential distributed brute force attack detected"
        attack_logs.username = username
        attack_logs.uniq_ips_1h = uniq_1h
        attack_logs.uniq_ips_24h = uniq_24h
        attack_logs.uniq_ips_7d = uniq_7d
        attack_logs.failed_1h = fails_1h
        attack_logs.failed_24h = fails_24h
        attack_logs.failed_7d = fails_7d
        attack_logs.ratio_1h = ratio_1h
        attack_logs.ratio_24h = ratio_24h
        attack_logs.thresholds = {
            TH_UNIQ_1H = TH_UNIQ_1H,
            TH_UNIQ_24H = TH_UNIQ_24H,
            TH_UNIQ_7D = TH_UNIQ_7D,
            TH_FAIL_MIN_24H = TH_FAIL_MIN_24H,
            TH_RATIO = TH_RATIO,
            ATTACK_TTL_SEC = ATTACK_TTL_SEC,
        }

        nauthilus_util.print_result({ log_format = "json" }, attack_logs)

        -- Add to custom log for monitoring
        nauthilus_builtin.custom_log_add(N .. "_attack_detected", "true")
        nauthilus_builtin.custom_log_add(N .. "_username", username)
        nauthilus_builtin.custom_log_add(N .. "_uniq_ips_1h", uniq_1h)
        nauthilus_builtin.custom_log_add(N .. "_uniq_ips_24h", uniq_24h)
        nauthilus_builtin.custom_log_add(N .. "_uniq_ips_7d", uniq_7d)
        nauthilus_builtin.custom_log_add(N .. "_failed_24h", fails_24h)
        nauthilus_builtin.custom_log_add(N .. "_ratio_24h", ratio_24h)
    end

    -- Add log with per-window metrics (optional)
    if ACM_INFO_LOG then
        local logs = {}
        logs.caller = N .. ".lua"
        logs.level = "info"
        logs.message = "Account metrics tracked"
        logs.username = username
        logs.uniq_ips_1h = uniq_1h
        logs.uniq_ips_24h = uniq_24h
        logs.uniq_ips_7d = uniq_7d
        logs.failed_1h = fails_1h
        logs.failed_24h = fails_24h
        logs.failed_7d = fails_7d
        logs.ratio_1h = ratio_1h
        logs.ratio_24h = ratio_24h
        logs.is_suspicious = is_suspicious

        nauthilus_util.print_result({ log_format = "json" }, logs)
    end

    return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
end
