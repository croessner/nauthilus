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

dynamic_loader("nauthilus_redis")
local nauthilus_redis = require("nauthilus_redis")

dynamic_loader("nauthilus_http_request")
local nauthilus_http_request = require("nauthilus_http_request")

dynamic_loader("nauthilus_gluacrypto")
local crypto = require("crypto")

dynamic_loader("nauthilus_gll_json")
local json = require("json")

local N = "callback"

function nauthilus_run_hook(logging)
    local result = {}

    result.level = "info"
    result.caller = N .. ".lua"

    local function print_result(err_string)
        result.ts = nauthilus_util.get_current_timestamp()

        if err_string ~= nil and err_string ~= "" then
            result.level = "error"

            result.error = err_string
        end

        if logging.log_format == "json" then
            local result_json, err_jenc = json.encode(result)
            nauthilus_util.if_error_raise(err_jenc)

            print(result_json)
        else
            local output_str = {}

            for k, v in pairs(result) do
                if string.match(v, "%s") then
                    v = '"' .. v .. '"'
                end

                table.insert(output_str, k .. '=' .. v)
            end

            print(table.concat(output_str, " "))
        end
    end

    local header = nauthilus_http_request.get_http_request_header("Content-Type")
    local body = nauthilus_http_request.get_http_request_body()

    if nauthilus_util.table_length(header) == 0 or header[1] ~= "application/json" then
        print_result("HTTP request header: Wrong 'Content-Type'")

        return
    end

    local body_table, err_jdec = json.decode(body)
    nauthilus_util.if_error_raise(err_jdec)

    if not nauthilus_util.is_table(body_table) then
        print_result("HTTP request body: Result is not a table")

        return
    end

    result.state = "client disconnected"
    result.dovecot_session = "unknown"

    local is_cmd_noop = false

    for k, v in pairs(body_table) do
        if k == "categories" then
            if nauthilus_util.is_table(v) then
                for _, category in ipairs(v) do
                    if category == "service:imap" or category == "service:lmtp" then
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
        elseif k == "fields" then
            if nauthilus_util.is_table(v) then
                for field_name, field_value in pairs(v) do
                    if field_name == "user" then
                        result.user = field_value
                    elseif field_name == "session" then
                        result.dovecot_session = field_value
                    elseif field_name == "remote_ip" then
                        result.remote_ip = field_value
                    elseif field_name == "remote_port" then
                        result.remote_port = field_value
                    elseif field_name == "cmd_name" then
                        if field_value == "NOOP" then
                            is_cmd_noop = true
                        end
                    end
                end
            end
        end
    end

    if result.category == "service:imap" or result.category == "service:pop3" or result.category == "service:lmtp" or result.category == "service:sieve" then
        if result.dovecot_session ~= "unknown" then
            local redis_key = "ntc:DS:" .. crypto.md5(result.user)

            if is_cmd_noop then
                result.cmd = "NOOP"
                result.state = "client session refreshed"

                local _, err_redis_expire = nauthilus_redis.redis_expire(redis_key, 3600)
                nauthilus_util.if_error_raise(err_redis_expire)
            else
                -- Cleanup dovecot session
                local deleted, err_redis_hdel = nauthilus_redis.redis_hdel(redis_key, result.dovecot_session)
                if err_redis_hdel then
                    result.remove_dovecot_session_status = err_redis_hdel
                else
                    result.remove_dovecot_session_status = deleted
                end
            end
        end

        if logging.log_level == "debug" or logging.log_level == "info" then
            print_result()
        end
    end
end
