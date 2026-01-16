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

local N = "failed_login_tracker"

local nauthilus_util = require("nauthilus_util")

local nauthilus_redis = require("nauthilus_redis")
local nauthilus_context = require("nauthilus_context")

local CUSTOM_REDIS_POOL = nauthilus_util.getenv("CUSTOM_REDIS_POOL_NAME", "default")

function nauthilus_call_action(request)
    -- Skip if no authentication was attempted or if authentication was successful
    if request.no_auth or request.authenticated then
        return nauthilus_builtin.ACTION_RESULT_OK
    end

    -- Get Redis connection
    local custom_pool = "default"
    if CUSTOM_REDIS_POOL ~= "default" then
        local err_redis_client

        custom_pool, err_redis_client = nauthilus_redis.get_redis_connection(CUSTOM_REDIS_POOL)
        nauthilus_util.if_error_raise(err_redis_client)
    end

    -- Define the key for the top-100 failed logins
    local top_failed_logins_key = "ntc:top_failed_logins"

    -- Get the username from the request
    local username = request.username

    if username and username ~= "" then
        -- Only track failed logins for usernames that don't have a recognized account
        -- This prevents legitimate users who mistype their password from being added to the list
        if not request.account or request.account == "" then
            -- Increment the score and trim the set in a single Redis pipeline round-trip
            local pipeline_cmds = {
                {"zincrby", top_failed_logins_key, 1, username},
                {"zremrangebyrank", top_failed_logins_key, 0, -101},
            }
            local _, pipe_err = nauthilus_redis.redis_pipeline(custom_pool, "write", pipeline_cmds)
            nauthilus_util.if_error_raise(pipe_err)
        end

        -- Get result table
        local rt = nauthilus_context.context_get("rt")
        if rt == nil then
            rt = {}
        end

        if nauthilus_util.is_table(rt) then
            if not request.account or request.account == "" then
                rt.failed_login_tracked = true
            else
                rt.failed_login_skipped = true
                rt.failed_login_skipped_reason = "recognized_account"
            end
            nauthilus_context.context_set("rt", rt)
        end

        -- Add log
        local logs = {}
        logs.caller = N .. ".lua"
        logs.level = "info"

        if not request.account or request.account == "" then
            logs.message = "Failed login tracked for username: " .. username
        else
            logs.message = "Failed login NOT tracked for recognized account: " .. username
            logs.reason = "Account is recognized"
        end

        nauthilus_util.print_result({ log_format = "json" }, logs)
    end

    return nauthilus_builtin.ACTION_RESULT_OK
end
