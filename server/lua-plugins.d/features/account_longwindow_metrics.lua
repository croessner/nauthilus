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


-- Phase 1 implementation from docs/attacker_detection_ideas.md:
--  - Per-account unique IPs via HyperLogLog over 24h and 7d windows
--  - Per-account failure timestamps over up to 7d
--  - Optional privacy-preserving password-spray token counters (if provided)
-- This feature only collects metrics and never blocks; it is safe to enable in learning mode.

local N = "account_longwindow_metrics"

local nauthilus_util = require("nauthilus_util")
local nauthilus_keys = require("nauthilus_keys")

local nauthilus_redis = require("nauthilus_redis")
local nauthilus_misc = require("nauthilus_misc")
local nauthilus_prometheus = require("nauthilus_prometheus")
local nauthilus_password = require("nauthilus_password")

function nauthilus_call_feature(request)
    -- This feature should run regardless of success/failure, but respect no_auth
    if request.no_auth then
        return nauthilus_builtin.FEATURE_TRIGGER_NO, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_YES
    end

    -- Derive context
    local username = request.username or request.account -- some protocols fill account
    local client_ip = request.client_ip
    local authenticated = (request.authenticated == true)
    local now = os.time()
    -- Use request.session directly for per-request identifier
    local req_id = tostring(request.session or "")

    -- Get Redis connection
    local client = "default"
    local pool_name = os.getenv("CUSTOM_REDIS_POOL_NAME")
    if pool_name ~= nil and pool_name ~= "" then
        local err
        client, err = nauthilus_redis.get_redis_connection(pool_name)
        nauthilus_util.if_error_raise(err)
    end

    -- Server-side tracking and snapshot via ALM_TrackAndSnapshot (single RTT)
    local pw_token
    if request.password and request.password ~= "" then
        local ok, token = pcall(nauthilus_password.generate_password_hash, request.password)
        if ok and token and token ~= "" then
            pw_token = token
        end
    end

    local uniq24, uniq7d, fails_24h, fails_7d = 0, 0, 0, 0
    if username and username ~= "" then
        local tag = nauthilus_keys.account_tag(username)
        local scoped = client_ip
        if client_ip and client_ip ~= "" then
            local s = nauthilus_misc.scoped_ip("lua_generic", client_ip)
            if s and s ~= "" then scoped = s end
        end

        local keys = {
            "ntc:hll:acct:" .. tag .. username .. ":ips:86400",
            "ntc:hll:acct:" .. tag .. username .. ":ips:604800",
            "ntc:z:acct:" .. tag .. username .. ":fails",
            "ntc:acct:" .. tag .. username .. ":longwindow",
            "ntc:z:spray:pw:86400",
            "ntc:z:spray:pw:604800",
        }
        local args = {
            now,
            scoped or "",
            authenticated and 1 or 0,
            req_id,
            pw_token or "",
        }

        local sres, serr = nauthilus_redis.redis_run_script(client, "", "ALM_TrackAndSnapshot", keys, args)
        nauthilus_util.if_error_raise(serr)
        if type(sres) == "table" then
            uniq24 = tonumber(sres[1] or 0) or 0
            uniq7d = tonumber(sres[2] or 0) or 0
            fails_24h = tonumber(sres[3] or 0) or 0
            fails_7d = tonumber(sres[4] or 0) or 0
        end
    end

    -- Prometheus counters for spray tokens, unchanged
    if pw_token and pw_token ~= "" then
        nauthilus_prometheus.increment_counter("security_sprayed_password_tokens_total", { window = "24h" })
        nauthilus_prometheus.increment_counter("security_sprayed_password_tokens_total", { window = "7d" })
    end

    -- Logging: keep it lightweight
    local logs = {
        caller = N .. ".lua",
        level = "info",
        message = "Mmetrics updated",
        username = username,
        client_ip = client_ip,
        authenticated = authenticated,
        has_pw_token = (pw_token ~= nil),
        ts = now,
    }
    nauthilus_util.print_result({ log_format = "json" }, logs)

    return nauthilus_builtin.FEATURE_TRIGGER_NO, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_OK
end
