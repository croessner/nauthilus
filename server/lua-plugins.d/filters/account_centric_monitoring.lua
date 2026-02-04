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
local nauthilus_otel = require("nauthilus_opentelemetry")

-- Module-scope configuration (read once)
local windows = {3600, 86400, 604800} -- 1h, 24h, 7d

local function getenv_num(name, def)
    local v = tonumber(nauthilus_util.getenv(name, "") or "")
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
local ACM_INFO_LOG = nauthilus_util.toboolean(nauthilus_util.getenv("ACM_INFO_LOG", "false"))

-- Env thresholds (defaults conservative):
--  - GPM_THRESH_UNIQ_1H default 12
--  - GPM_THRESH_UNIQ_24H default 25
--  - GPM_THRESH_UNIQ_7D default 60
--  - GPM_MIN_FAILS_24H default 8
--  - GPM_THRESH_IP_TO_FAIL_RATIO default 1.2
--  - GPM_ATTACK_TTL_SEC default 43200 (12h)
--  - CUSTOM_REDIS_POOL_NAME optional pool

local time = require("time")

local CUSTOM_REDIS_POOL = nauthilus_util.getenv("CUSTOM_REDIS_POOL_NAME", "default")

local function protocol_segment(request)
    local protocol = request.protocol
    if protocol == nil or protocol == "" then
        return "unknown"
    end
    return protocol
end

function nauthilus_call_filter(request)
    if request.no_auth then
        return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
    end

    -- Track account-specific authentication attempts
    local timestamp = time.unix()
    local username = request.username

    if not username or username == "" then
        return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
    end

    local protocol = protocol_segment(request)

    -- Hold per-window metrics explicitly
    local uniq_1h, uniq_24h, uniq_7d = 0, 0, 0
    local fails_1h, fails_24h, fails_7d = 0, 0, 0
    local ratio_1h, ratio_24h = 0, 0

    local tag = nauthilus_keys.account_tag(username)
    local w1, w2, w3 = windows[1], windows[2], windows[3]

    local keys = {
        nauthilus_util.get_redis_key(request, "multilayer:account:" .. tag .. username .. ":proto:" .. protocol .. ":ips:" .. w1),
        nauthilus_util.get_redis_key(request, "multilayer:account:" .. tag .. username .. ":proto:" .. protocol .. ":ips:" .. w2),
        nauthilus_util.get_redis_key(request, "multilayer:account:" .. tag .. username .. ":proto:" .. protocol .. ":ips:" .. w3),
        nauthilus_util.get_redis_key(request, "multilayer:account:" .. tag .. username .. ":proto:" .. protocol .. ":fails:" .. w1),
        nauthilus_util.get_redis_key(request, "multilayer:account:" .. tag .. username .. ":proto:" .. protocol .. ":fails:" .. w2),
        nauthilus_util.get_redis_key(request, "multilayer:account:" .. tag .. username .. ":proto:" .. protocol .. ":fails:" .. w3),
        nauthilus_util.get_redis_key(request, "multilayer:account:" .. tag .. username .. ":proto:" .. protocol .. ":metrics:" .. w1),
        nauthilus_util.get_redis_key(request, "multilayer:account:" .. tag .. username .. ":proto:" .. protocol .. ":metrics:" .. w2),
        nauthilus_util.get_redis_key(request, "multilayer:account:" .. tag .. username .. ":proto:" .. protocol .. ":metrics:" .. w3),
        nauthilus_util.get_redis_key(request, "multilayer:distributed_attack:accounts:proto:" .. protocol),
    }

    local fail_id = ""
    if not request.authenticated then
        -- Use request.session directly as stable identifier
        fail_id = tostring(request.session or "")
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

    local res, err_script = nauthilus_redis.redis_run_script(CUSTOM_REDIS_POOL, "", "ACM_TrackAndAggregate", keys, args)
    nauthilus_util.if_error_raise(err_script)

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
            nauthilus_builtin.custom_log_add(N .. "_attack_detected", "true")
            nauthilus_builtin.custom_log_add(N .. "_username", username)
            nauthilus_builtin.custom_log_add(N .. "_uniq_ips_1h", uniq_1h)
            nauthilus_builtin.custom_log_add(N .. "_uniq_ips_24h", uniq_24h)
            nauthilus_builtin.custom_log_add(N .. "_uniq_ips_7d", uniq_7d)
            nauthilus_builtin.custom_log_add(N .. "_failed_24h", fails_24h)
            nauthilus_builtin.custom_log_add(N .. "_ratio_24h", ratio_24h)
        end

        -- Telemetry: evaluation span with metrics
        if nauthilus_otel and nauthilus_otel.is_enabled() then
            local tr = nauthilus_otel.tracer("nauthilus/lua/acm")
            tr:with_span("acm.evaluate", function(span)
                span:set_attributes({
                    ["peer.service"] = "acm",
                    username = username or "",
                    uniq_ips_1h = uniq_1h,
                    uniq_ips_24h = uniq_24h,
                    uniq_ips_7d = uniq_7d,
                    fails_1h = fails_1h,
                    fails_24h = fails_24h,
                    fails_7d = fails_7d,
                    ratio_1h = ratio_1h,
                    ratio_24h = ratio_24h,
                    suspicious = suspicious,
                })

                if suspicious then
                    span:add_event("flagged", { reason = "thresholds" })
                end
            end)
        end

        if ACM_INFO_LOG then
            local logs = {}
            logs.caller = N .. ".lua"
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

            nauthilus_util.log_info(request, logs)
        end

        return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
    end

    -- In unexpected cases, still return OK to avoid blocking auth
    return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
end
