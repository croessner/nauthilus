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
local nauthilus_redis = require("nauthilus_redis")

local time = require("time")

-- Read env with default fallback
local default_delay_min_ms = tonumber(os.getenv("SOFT_DELAY_MIN_MS") or "50")
local default_delay_max_ms = tonumber(os.getenv("SOFT_DELAY_MAX_MS") or "200")
-- Thresholds for enabling delay
local threshold_uniq24 = tonumber(os.getenv("SOFT_DELAY_THRESH_UNIQ24") or "8")
local threshold_uniq7d = tonumber(os.getenv("SOFT_DELAY_THRESH_UNIQ7D") or "20")
local threshold_fail24 = tonumber(os.getenv("SOFT_DELAY_THRESH_FAIL24") or "5")
local threshold_fail7d = tonumber(os.getenv("SOFT_DELAY_THRESH_FAIL7D") or "10")

local function clamp(v, lo, hi)
    if v < lo then return lo end
    if v > hi then return hi end
    return v
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

    -- Redis client
    local client = "default"
    local pool_name = os.getenv("CUSTOM_REDIS_POOL_NAME")
    if pool_name and pool_name ~= "" then
        local err
        client, err = nauthilus_redis.get_redis_connection(pool_name)
        nauthilus_util.if_error_raise(err)
    end

    local now = os.time()
    local applied_delay_ms = 0

    -- Fast read snapshot produced by Phase 1 feature
    local snap_key = "ntc:acct:" .. username .. ":longwindow"
    local uniq24 = tonumber(nauthilus_redis.redis_hget(client, snap_key, "uniq_ips_24h") or "0") or 0
    local uniq7d = tonumber(nauthilus_redis.redis_hget(client, snap_key, "uniq_ips_7d") or "0") or 0
    local fail24 = tonumber(nauthilus_redis.redis_hget(client, snap_key, "fails_24h") or "0") or 0
    local fail7d = tonumber(nauthilus_redis.redis_hget(client, snap_key, "fails_7d") or "0") or 0

    -- Additional indicator: account flagged as under attack
    local attacked_accounts_key = "ntc:multilayer:distributed_attack:accounts"
    local attack_score = nauthilus_redis.redis_zscore(client, attacked_accounts_key, username)

    local risky = false
    if uniq24 >= threshold_uniq24 or uniq7d >= threshold_uniq7d or fail24 >= threshold_fail24 or fail7d >= threshold_fail7d then
        risky = true
    end
    if attack_score ~= nil then
        risky = true
    end

    if risky then
        -- Scale delay by how much we exceed thresholds, but clamp to sane bounds
        local factor = 1.0
        if uniq24 > threshold_uniq24 then factor = factor + (uniq24 - threshold_uniq24) * 0.05 end
        if uniq7d > threshold_uniq7d then factor = factor + (uniq7d - threshold_uniq7d) * 0.02 end
        if fail24 > threshold_fail24 then factor = factor + (fail24 - threshold_fail24) * 0.03 end
        if fail7d > threshold_fail7d then factor = factor + (fail7d - threshold_fail7d) * 0.01 end
        if attack_score ~= nil then factor = factor + 0.5 end

        local base_ms = default_delay_min_ms + math.random(0, math.max(0, default_delay_max_ms - default_delay_min_ms))
        applied_delay_ms = math.floor(clamp(base_ms * factor, default_delay_min_ms, default_delay_max_ms))

        -- Apply delay; time.sleep uses seconds (float)
        time.sleep(applied_delay_ms / 1000.0)
    end

    -- Log decision
    local logs = {
        caller = N .. ".lua",
        level = risky and "warning" or "info",
        message = risky and "Applied soft delay" or "No soft delay",
        username = username,
        client_ip = client_ip,
        uniq_ips_24h = uniq24,
        uniq_ips_7d = uniq7d,
        fails_24h = fail24,
        fails_7d = fail7d,
        attacked = (attack_score ~= nil),
        applied_delay_ms = applied_delay_ms,
        ts = now,
    }
    nauthilus_util.print_result({ log_format = "json" }, logs)

    -- Add to custom logs for correlation
    nauthilus_builtin.custom_log_add(N .. "_delay_ms", applied_delay_ms)

    return nauthilus_builtin.ACTION_RESULT_OK
end
