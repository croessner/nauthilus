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

-- Per-account long-window metrics used by policy and post-action processing.
-- This environment source only collects metrics and never blocks; it is safe to enable in learning mode.
--
-- Emitted policy attributes:
--  - lua.plugin.account_longwindow.username
--  - lua.plugin.account_longwindow.authenticated
--  - lua.plugin.account_longwindow.uniq_ips_24h
--  - lua.plugin.account_longwindow.uniq_ips_7d
--  - lua.plugin.account_longwindow.fails_24h
--  - lua.plugin.account_longwindow.fails_7d
--  - lua.plugin.account_longwindow.has_pw_token

local N = "account_longwindow_metrics"

local nauthilus_util = require("nauthilus_util")
local nauthilus_keys = require("nauthilus_keys")
local nauthilus_redis_pool = require("nauthilus_redis_pool")
local policy_facts = require("nauthilus_policy_facts")

local nauthilus_redis = require("nauthilus_redis")
local nauthilus_misc = require("nauthilus_misc")
local nauthilus_prometheus = require("nauthilus_prometheus")
local nauthilus_password = require("nauthilus_password")
local time = require("time")

-- record_spray_token adds a password token to every global spray window. The windows are global, so each one is
-- written in its own single-key call: ALM_TrackAndSnapshot only receives keys with the account hash tag.
local function record_spray_token(client, request, pw_token, now)
    for _, window in ipairs(nauthilus_keys.LONG_WINDOWS) do
        local _, err = nauthilus_redis.redis_run_script(
            client,
            "",
            "ZAddRemExpire",
            { nauthilus_keys.spray_key(request, window) },
            { now, pw_token, 0, now - window, window * 2 }
        )
        nauthilus_util.if_error_raise(err)
    end
end

function nauthilus_call_environment(request)
    -- This environment source should run regardless of success/failure, but respect no_auth
    if request.no_auth then
        return nauthilus_builtin.ENVIRONMENT_TRIGGER_NO, nauthilus_builtin.ENVIRONMENT_ABORT_NO, nauthilus_builtin.ENVIRONMENT_RESULT_OK
    end

    -- Derive context
    local username = request.username or request.account -- some protocols fill account
    local client_ip = request.client_ip
    local authenticated = (request.authenticated == true)
    local now = time.unix()
    -- Use request.session directly for per-request identifier
    local req_id = tostring(request.session or "")
    local protocol = nauthilus_keys.protocol(request.protocol)

    local client = nauthilus_redis_pool.connection()

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
        local scoped = client_ip
        if client_ip and client_ip ~= "" then
            local s = nauthilus_misc.scoped_ip("lua_generic", client_ip)
            if s and s ~= "" then scoped = s end
        end

        local keys = nauthilus_keys.account_longwindow_keys(request, username, protocol)
        local args = {
            now,
            scoped or "",
            authenticated and 1 or 0,
            req_id,
        }

        local sres, serr = nauthilus_redis.redis_run_script(client, "", "ALM_TrackAndSnapshot", keys, args)
        nauthilus_util.if_error_raise(serr)
        if type(sres) == "table" then
            uniq24 = tonumber(sres[1] or 0) or 0
            uniq7d = tonumber(sres[2] or 0) or 0
            fails_24h = tonumber(sres[3] or 0) or 0
            fails_7d = tonumber(sres[4] or 0) or 0
        end

        if pw_token and pw_token ~= "" then
            record_spray_token(client, request, pw_token, now)
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
        message = "Metrics updated",
        username = username,
        client_ip = client_ip,
        authenticated = authenticated,
        has_pw_token = (pw_token ~= nil),
    }
    nauthilus_util.log_info(request, logs)
    policy_facts.emit_many("account_longwindow", {
        username = username or "",
        authenticated = authenticated,
        uniq_ips_24h = uniq24,
        uniq_ips_7d = uniq7d,
        fails_24h = fails_24h,
        fails_7d = fails_7d,
        has_pw_token = (pw_token ~= nil),
    })

    return nauthilus_builtin.ENVIRONMENT_TRIGGER_NO, nauthilus_builtin.ENVIRONMENT_ABORT_NO, nauthilus_builtin.ENVIRONMENT_RESULT_OK
end
