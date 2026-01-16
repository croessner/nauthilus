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

local nauthilus_redis = require("nauthilus_redis")
local nauthilus_http_request = require("nauthilus_http_request")

local json = require("json")

local N = "callback"

local CUSTOM_REDIS_POOL = nauthilus_util.getenv("CUSTOM_REDIS_POOL_NAME", "default")

local CATEGORIES = {
    ["service:imap-login"] = true,
    ["service:pop3-login"] = true,
    ["service:lmtp"] = true,
    ["service:managesieve-login"] = true,
}

function nauthilus_run_hook(logging, session)
    local result = {}

    result.level = "info"
    result.caller = N .. ".lua"
    result.session = session

    local custom_pool = "default"
    if CUSTOM_REDIS_POOL ~= "default" then
        local err_redis_client

        custom_pool, err_redis_client = nauthilus_redis.get_redis_connection(CUSTOM_REDIS_POOL)
        nauthilus_util.if_error_raise(err_redis_client)
    end

    local header = nauthilus_http_request.get_http_request_header("Content-Type")
    local body = nauthilus_http_request.get_http_request_body()

    if nauthilus_util.table_length(header) == 0 or header[1] ~= "application/json" then
        nauthilus_util.print_result(logging, result, "HTTP request header: Wrong 'Content-Type'")

        return
    end

    local body_table, err_jdec = json.decode(body)
    nauthilus_util.if_error_raise(err_jdec)

    if not nauthilus_util.is_table(body_table) then
        nauthilus_util.print_result(logging, result, "HTTP request body: Result is not a table")

        return
    end

    local function update_target_user_table(target)
        -- Pipeline HGET + HDEL to minimize roundtrips
        local cmds = {
            {"hget", "ntc:DS_ACCOUNT", target},
            {"hdel", "ntc:DS_ACCOUNT", target},
        }
        local pres, perr = nauthilus_redis.redis_pipeline(custom_pool, "write", cmds)
        if perr then
            result.update_target_user_table_error = perr
            return
        end

        local account
        if type(pres) == "table" and type(pres[1]) == "table" and pres[1].ok ~= false then
            account = pres[1].value
        end

        return account
    end

    result.state = "client disconnected"

    for k, v in pairs(body_table) do
        if k == "categories" then
            if nauthilus_util.is_table(v) then
                for _, category in ipairs(v) do
                    if CATEGORIES[category] then
                        result.category = category
                    end
                end
            end
        elseif k == "start_time" then
            if nauthilus_util.is_string(v) then
                result.start_time = v
            end
        elseif k == "end_time" then
            if nauthilus_util.is_string(v) then
                result.end_time = v
            end
        elseif k == "event" then
            if nauthilus_util.is_string(v) then
                result.event = v
            end
        elseif k == "fields" then
            if nauthilus_util.is_table(v) then
                for field_name, field_value in pairs(v) do
                    if field_name == "user" then
                        result.user = field_value
                    elseif field_name == "local_ip" then
                        result.local_ip = field_value
                    elseif field_name == "local_port" then
                        result.local_port = field_value
                    elseif field_name == "remote_ip" then
                        result.remote_ip = field_value
                    elseif field_name == "remote_port" then
                        result.remote_port = field_value
                    elseif field_name == "session" then
                        result.session = field_value
                    end
                end
            end
        end
    end

    if CATEGORIES[result.category] then
        local target = result.remote_ip .. ":" .. result.remote_port
        local account = update_target_user_table(target)
        local redis_key = "ntc:DS:" .. account

        if account then
            -- Cleanup dovecot session
            local _, err_redis_hdel = nauthilus_redis.redis_hdel(custom_pool, redis_key, target)
            if err_redis_hdel then
                result.remove_dovecot_target_error = err_redis_hdel
            end
        end

        if logging.log_level == "debug" or logging.log_level == "info" then
           nauthilus_util.print_result(logging, result)
        end
    end

    return result
end
