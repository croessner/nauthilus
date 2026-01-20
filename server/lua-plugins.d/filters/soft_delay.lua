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

-- Phase 2 (soft measures) per docs/attacker_detection_ideas.md:
--  - Introduce small, risk-based delays (50–200 ms) without blocking
--  - Rely on long-window account metrics and flags
--  - Log decisions; remain conservative to avoid harming legit users

-- Env thresholds (defaults conservative):
--  - SOFT_DELAY_MIN_MS default 50
--  - SOFT_DELAY_MAX_MS default 200
--  - SOFT_DELAY_THRESH_UNIQ24 default 8
--  - SOFT_DELAY_THRESH_UNIQ7D default 20
--  - SOFT_DELAY_THRESH_FAIL24 default 5
--  - SOFT_DELAY_THRESH_FAIL7D default 10
--  - CUSTOM_REDIS_POOL_NAME optional pool

local N = "soft_delay"

local nauthilus_util = require("nauthilus_util")
local nauthilus_keys = require("nauthilus_keys")

local nauthilus_redis = require("nauthilus_redis")
local nauthilus_otel = require("nauthilus_opentelemetry")

local time = require("time")

local nauthilus_cache = require("nauthilus_cache")

-- Read env with default fallback
local default_delay_min_ms = tonumber(nauthilus_util.getenv("SOFT_DELAY_MIN_MS", "50"))
local default_delay_max_ms = tonumber(nauthilus_util.getenv("SOFT_DELAY_MAX_MS", "200"))
-- Thresholds for enabling delay
local threshold_uniq24 = tonumber(nauthilus_util.getenv("SOFT_DELAY_THRESH_UNIQ24", "8"))
local threshold_uniq7d = tonumber(nauthilus_util.getenv("SOFT_DELAY_THRESH_UNIQ24", "20"))
local threshold_fail24 = tonumber(nauthilus_util.getenv("SOFT_DELAY_THRESH_FAIL24", "5"))
local threshold_fail7d = tonumber(nauthilus_util.getenv("SOFT_DELAY_THRESH_FAIL7D", "10"))
local CUSTOM_REDIS_POOL = nauthilus_util.getenv("CUSTOM_REDIS_POOL_NAME", "default")

local function clamp(v, lo, hi)
    if v < lo then return lo end
    if v > hi then return hi end
    return v
end

local function get_metrics(pool, username, request)
    local ckey = "sdm:" .. (username or "")
    local cached = nauthilus_cache.cache_get(ckey)
    if cached and type(cached) == "table" then
        return cached, true
    end

    local tag = nauthilus_keys.account_tag(username)
    local snap_key = nauthilus_util.get_redis_key(request, "acct:" .. tag .. username .. ":longwindow")

    -- Pipeline the related user-specific reads
    local cmds = {
        { "hget", snap_key, "uniq_ips_24h" },
        { "hget", snap_key, "uniq_ips_7d" },
        { "hget", snap_key, "fails_24h" },
        { "hget", snap_key, "fails_7d" },
    }
    local res, err = nauthilus_redis.redis_pipeline(pool, "read", cmds)
    nauthilus_util.if_error_raise(err)

    if type(res) ~= "table" then
        res = {}
    end
    local function val(i)
        local e = res[i]
        if type(e) ~= "table" then
            return nil
        end
        if e.ok == false then
            return nil
        end
        return e.value
    end

    local uniq24 = tonumber(val(1) or "0") or 0
    local uniq7d = tonumber(val(2) or "0") or 0
    local fail24 = tonumber(val(3) or "0") or 0
    local fail7d = tonumber(val(4) or "0") or 0

    -- Separate call for the global attack set
    local attack_score, err_a = nauthilus_redis.redis_zscore(pool, nauthilus_util.get_redis_key(request, "multilayer:distributed_attack:accounts"), username)
    nauthilus_util.if_error_raise(err_a)

    local metrics = {
        uniq24 = uniq24,
        uniq7d = uniq7d,
        fail24 = fail24,
        fail7d = fail7d,
        attacked = (attack_score ~= nil)
    }

    nauthilus_cache.cache_set(ckey, metrics, 5)

    return metrics, false
end

function nauthilus_call_filter(request)
    if request.no_auth then
        return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
    end

    local username = request.username or request.account
    local client_ip = request.client_ip
    if not username or username == "" then
        return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
    end

    local m, _ = get_metrics(CUSTOM_REDIS_POOL, username, request)
    local applied_delay_ms = 0

    local risky = false
    if m.uniq24 >= threshold_uniq24 or m.uniq7d >= threshold_uniq7d or m.fail24 >= threshold_fail24 or m.fail7d >= threshold_fail7d or m.attacked then
        risky = true
    end

    if risky then
        -- Scale delay by how much we exceed thresholds, but clamp to sane bounds
        local factor = 1.0
        if m.uniq24 > threshold_uniq24 then
            factor = factor + (m.uniq24 - threshold_uniq24) * 0.05
        end
        if m.uniq7d > threshold_uniq7d then
            factor = factor + (m.uniq7d - threshold_uniq7d) * 0.02
        end
        if m.fail24 > threshold_fail24 then
            factor = factor + (m.fail24 - threshold_fail24) * 0.03
        end
        if m.fail7d > threshold_fail7d then
            factor = factor + (m.fail7d - threshold_fail7d) * 0.01
        end
        if m.attacked then
            factor = factor + 0.5
        end

        local base_ms = default_delay_min_ms + math.random(0, math.max(0, default_delay_max_ms - default_delay_min_ms))
        applied_delay_ms = math.floor(clamp(base_ms * factor, default_delay_min_ms, default_delay_max_ms))

        -- Apply delay; time.sleep uses seconds (float)
        time.sleep(applied_delay_ms / 1000.0)
    end

    -- Telemetry: record evaluation and any applied delay
    if nauthilus_otel and nauthilus_otel.is_enabled() then
        local tr = nauthilus_otel.tracer("nauthilus/lua/soft_delay")
        tr:with_span("soft_delay.evaluate", function(span)
            span:set_attributes({
                ["peer.service"] = "soft_delay",
                username = username or "",
                client_ip = client_ip or "",
                uniq_ips_24h = m.uniq24,
                uniq_ips_7d = m.uniq7d,
                fails_24h = m.fail24,
                fails_7d = m.fail7d,
                attacked = m.attacked,
                applied_delay_ms = applied_delay_ms,
                threshold_uniq24 = threshold_uniq24,
                threshold_uniq7d = threshold_uniq7d,
                threshold_fail24 = threshold_fail24,
                threshold_fail7d = threshold_fail7d,
            })
            if applied_delay_ms > 0 then
                span:add_event("sleep", { duration_ms = applied_delay_ms })
            end
        end)
    end

    -- Log decision
    local logs = {
        caller = N .. ".lua",
        message = risky and "Applied soft delay" or "No soft delay",
        username = username,
        client_ip = client_ip,
        uniq_ips_24h = m.uniq24,
        uniq_ips_7d = m.uniq7d,
        fails_24h = m.fail24,
        fails_7d = m.fail7d,
        attacked = m.attacked,
        applied_delay_ms = applied_delay_ms,
    }

    if risky then
        nauthilus_util.log_warn(request, logs)
    else
        nauthilus_util.log_info(request, logs)
    end

    -- Add to custom logs for correlation
    nauthilus_builtin.custom_log_add(N .. "_delay_ms", applied_delay_ms)

    return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
end
