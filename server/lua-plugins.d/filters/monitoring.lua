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

dynamic_loader("nauthilus_http_request")
local nauthilus_http_request = require("nauthilus_http_request")

dynamic_loader("nauthilus_backend")
local nauthilus_backend = require("nauthilus_backend")

local N = "director"

local function get_service()
    local header = nauthilus_http_request.get_http_request_header("X-Nauthilus-Service")
    if nauthilus_util.table_length(header) == 1 then
        return header[1]
    end

    return nil
end

local function get_dovecot_target()
    local header = nauthilus_http_request.get_http_request_header("X-Dovecot-Proxy-Target")
    if nauthilus_util.table_length(header) == 1 then
        return header[1]
    end

    return nil
end

function nauthilus_call_filter(request)
    if not request.authenticated then
        return nauthilus_builtin.FILTER_REJECT, nauthilus_builtin.FILTER_RESULT_OK
    end

    local service = get_service()
    if service ~= "Dovecot" then
        return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
    end

    dynamic_loader("nauthilus_redis")
    local nauthilus_redis = require("nauthilus_redis")
    local redis_key = "ntc:DS:" .. request.account

    local custom_pool = "default"
    local custom_pool_name =  os.getenv("CUSTOM_REDIS_POOL_NAME")
    if custom_pool_name ~= nil and  custom_pool_name ~= "" then
        local err_redis_client

        custom_pool, err_redis_client = nauthilus_redis.get_redis_connection(custom_pool_name)
        nauthilus_util.if_error_raise(err_redis_client)
    end

    --[[
    local function set_initial_expiry()
        local length, err_redis_hlen = nauthilus_redis.redis_hlen(custom_pool, redis_key)
        if err_redis_hlen then
            if err_redis_hlen ~= "redis: nil" then
                nauthilus_builtin.custom_log_add(N .. "_redis_hlen_error", err_redis_hlen)
            end
        else
            if length == 1 then
                local _, err_redis_expire = nauthilus_redis.redis_expire(custom_pool, redis_key, 604800)
                nauthilus_util.if_error_raise(err_redis_expire)
            end
        end
    end
    ]]--

    local function invalidate_stale_sessions()
        local _, err_redis_hdel = nauthilus_redis.redis_del(custom_pool, redis_key)

        nauthilus_util.if_error_raise(err_redis_hdel)
    end

    local function update_target_user_table(session)
        local _, err_redis_hset = nauthilus_redis.redis_hset(custom_pool, "ntc:DS_ACCOUNT", session, request.account)
        if err_redis_hset then
            nauthilus_builtin.custom_log_add(N .. "_redis_hset_error", err_redis_hset)

            return
        end
    end

    local function add_session(session, server)
        local _, err_redis_hset = nauthilus_redis.redis_hset(custom_pool, redis_key, session, server)
        if err_redis_hset then
            nauthilus_builtin.custom_log_add(N .. "_redis_hset_error", err_redis_hset)

            return
        end

        -- set_initial_expiry()
        nauthilus_builtin.custom_log_add(N .. "_dovecot_target", session)

        update_target_user_table(session)
    end

    local function get_server_from_sessions(session)
        local server_from_session, err_redis_hget = nauthilus_redis.redis_hget(custom_pool, redis_key, session)
        if err_redis_hget then
            if err_redis_hget ~= "redis: nil" then
                nauthilus_builtin.custom_log_add(N .. "_redis_hget_error", err_redis_hget)

                return nil
            end
        end

        if server_from_session and server_from_session ~= "" then
            return server_from_session
        end

        local all_sessions, err_redis_hgetall = nauthilus_redis.redis_hgetall(custom_pool, redis_key)
        if err_redis_hgetall then
            if err_redis_hgetall ~= "redis: nil" then
                nauthilus_builtin.custom_log_add(N .. "_redis_hgetall_error", err_redis_hget)
            end

            return nil
        end

        for _, first_server in pairs(all_sessions) do
            return first_server
        end

        return nil
    end

    local function preprocess_backend_servers(backend_servers)
        local valid_servers = {}

        for _, server in ipairs(backend_servers) do
            if server.protocol == request.protocol then
                table.insert(valid_servers, server)
            end
        end

        return valid_servers
    end

    local server_host
    local session = get_dovecot_target()
    local result = {}
    local valid_servers = preprocess_backend_servers(nauthilus_backend.get_backend_servers())
    local num_of_bs = nauthilus_util.table_length(valid_servers)

    result.caller = N .. ".lua"
    result.level = "info"
    result.ts = nauthilus_util.get_current_timestamp()

    if request.debug then
        result.level = "debug"
        result.session = request.session
        result.dovecot_target = session
        result.protocol = request.protocol
        result.account = request.account
        result.backend_servers_alive = tostring(num_of_bs)

        local backend_servers_hosts = {}
        for _, server in ipairs(valid_servers) do
            table.insert(backend_servers_hosts, server.host)
        end

        result.backend_servers = table.concat(backend_servers_hosts, ", ")
    end

    if num_of_bs > 0 then
        local maybe_server = get_server_from_sessions(session)

        if maybe_server then
            for _, server in ipairs(valid_servers) do
                if server.host == maybe_server then
                    server_host = maybe_server
                    result.backend_server_selected = server_host

                    break
                end
            end

            if not server_host then
                invalidate_stale_sessions()

                server_host = valid_servers[math.random(1, num_of_bs)].host
                result.backend_server_selected = server_host
            end
        else
            server_host = valid_servers[math.random(1, num_of_bs)].host
            result.backend_server_selected = server_host
        end
    end

    if server_host then
        local backend_result = nauthilus_backend_result.new()
        local attributes = {}

        add_session(session, server_host)

        local expected_server = get_server_from_sessions(session)

        -- Another client might have been faster at the same point in time...
        if expected_server and  server_host ~= expected_server then
            server_host = expected_server
            result.backend_server_selected = server_host
        end

        attributes["Proxy-Host"] = server_host

        nauthilus_builtin.custom_log_add(N .. "_backend_server", server_host)

        backend_result:attributes(attributes)
        nauthilus_backend.apply_backend_result(backend_result)
    end

    nauthilus_util.print_result({ log_format = request.log_format }, result, nil)

    if server_host == nil then
        return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_FAIL
    end

    return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
end
