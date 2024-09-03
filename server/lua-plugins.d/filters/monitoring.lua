dynamic_loader("nauthilus_redis")
dynamic_loader("nauthilus_backend")
dynamic_loader("nauthilus_http_request")
dynamic_loader("nauthilus_gluacrypto")

local nauthilus_redis = require("nauthilus_redis")
local nauthilus_backend = require("nauthilus_backend")
local nauthilus_http_request = require("nauthilus_http_request")

local nauthilus_util = require("nauthilus_util")

local crypto = require("crypto")

local N = "monitoring"

local wanted_protocols = {
    "imap", "imapa", "pop3", "pop3s", "lmtp", "lmtps",
    "sieve", -- Not sure about this
}

function nauthilus_call_filter(request)
    local skip_and_accept_filter = false

    -- Dovecot userdb request
    if request.authenticated and request.no_auth then
        skip_and_accept_filter = true
    end

    -- Dovecot passdb request
    if request.authenticated and not request.no_auth then
        skip_and_accept_filter = true

        for _, proto in ipairs(wanted_protocols) do
            if proto == request.protocol then
                skip_and_accept_filter = false

                break
            end
        end
    end

    if skip_and_accept_filter then
        nauthilus_backend.remove_from_backend_result({ "Proxy-Host" })

        return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
    end

    local function get_dovecot_session()
        local header = nauthilus_http_request.get_http_request_header("X-Dovecot-Session")
        if nauthilus_util.table_length(header) == 1 then
            return header[1]
        end

        return nil
    end

    local function set_initial_expiry(redis_key)
        local length, err_redis_hlen = nauthilus_redis.redis_hlen(redis_key)
        if err_redis_hlen then
            if err_redis_hlen ~= "redis: nil" then
                nauthilus_builtin.custom_log_add(N .. "_redis_hlen_error", err_redis_hlen)
            end
        else
            if length == 1 then
                local _, err_redis_expire = nauthilus_redis.redis_expire(redis_key, 3600)
                nauthilus_util.if_error_raise(err_redis_expire)
            end
        end
    end

    local function add_session(session, server)
        if session == nil then
            return
        end

        local redis_key = "ntc:DS:" .. crypto.md5(request.account)

        local _, err_redis_hset = nauthilus_redis.redis_hset(redis_key, session, server)
        if err_redis_hset then
            nauthilus_builtin.custom_log_add(N .. "_redis_hset_error", err_redis_hset)

            return
        end

        set_initial_expiry(redis_key)
        nauthilus_builtin.custom_log_add(N .. "_dovecot_session", session)
    end

    local function get_server_from_sessions(session)
        local redis_key = "ntc:DS:" .. crypto.md5(request.account)

        local server_from_session, err_redis_hget = nauthilus_redis.redis_hget(redis_key, session)
        if err_redis_hget then
            if err_redis_hget ~= "redis: nil" then
                nauthilus_builtin.custom_log_add(N .. "_redis_hget_error", err_redis_hget)
            end

            return nil
        end

        if server_from_session ~= "" then
            return server_from_session
        end

        local all_sessions, err_redis_hgetall = nauthilus_redis.redis_hgetall(redis_key)
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

    -- Only look for backend servers, if a user was authenticated (passdb requests)
    if request.authenticated and not request.no_auth then
        local num_of_bs = 0

        local backend_servers = nauthilus_backend.get_backend_servers()
        if nauthilus_util.is_table(backend_servers) then
            num_of_bs = nauthilus_util.table_length(backend_servers)

            local server_ip = ""
            local new_server_ip = ""

            local session = get_dovecot_session()
            if session then
                local maybe_server = get_server_from_sessions(session)
                if maybe_server then
                    server_ip = maybe_server
                end
            end

            if num_of_bs > 0 then
                local attributes = {}

                local b = nauthilus_backend_result.new()

                for _, server in ipairs(backend_servers) do
                    new_server_ip = server.ip

                    if server_ip == new_server_ip then
                        attributes["Proxy-Host"] = server_ip

                        add_session(session, server_ip)
                        nauthilus_builtin.custom_log_add(N .. "_backend_server_current", server_ip)

                        b:attributes(attributes)
                        nauthilus_backend.apply_backend_result(b)

                        break
                    end
                end

                if server_ip ~= new_server_ip then
                    -- Put your own logic here to select a proper server for the user. In this demo, the last server
                    -- available is always used.
                    attributes["Proxy-Host"] = new_server_ip

                    add_session(session, new_server_ip)
                    nauthilus_builtin.custom_log_add(N .. "_backend_server_new", new_server_ip)

                    b:attributes(attributes)
                    nauthilus_backend.apply_backend_result(b)
                end
            end
        end

        if num_of_bs == 0 then
            nauthilus_builtin.custom_log_add(N .. "_backend_server", "failed")
            nauthilus_builtin.status_message_set("No backend servers are available")

            return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_FAIL
        else
            nauthilus_builtin.custom_log_add(N .. "_backend_server", "success")
        end

        return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
    end

    -- Anything else must be a rejected request
    return nauthilus_builtin.FILTER_REJECT, nauthilus_builtin.FILTER_RESULT_OK
end
