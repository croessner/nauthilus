local crypto = require("crypto")

local N = "monitoring"

---@type table wanted_protocols
local wanted_protocols = {
    "imap", "imapa", "pop3", "pop3s", "lmtp", "lmtps",
    "sieve", -- Not sure about this
}

---@param request table
---@return number, number
function nauthilus_call_filter(request)
    ---@type boolean skip_and_accept_filter
    local skip_and_accept_filter = false

    -- Dovecot userdb request
    if request.authenticated and request.no_auth then
        skip_and_accept_filter = true
    end

    -- Dovecot passdb request
    if request.authenticated and not request.no_auth then
        skip_and_accept_filter = true

        ---@param proto string
        for _, proto in ipairs(wanted_protocols) do
            if proto == request.protocol then
                skip_and_accept_filter = false

                break
            end
        end
    end

    if skip_and_accept_filter then
        nauthilus.remove_from_backend_result({ "Proxy-Host" })

        return nauthilus.FILTER_ACCEPT, nauthilus.FILTER_RESULT_OK
    end

    --- This function retrieves the Dovecot session from the http request header.
    ---@return string
    local function get_dovecot_session()
        ---@type table header
        local header = nauthilus.get_http_request_header("X-Dovecot-Session")
        if #header == 1 then
            return header[1]
        end

        return nil
    end

    --- This function sets an initial expiry for a given Redis key if the length of the key is 1.
    ---@param redis_key string
    ---@return void
    local function set_initial_expiry(redis_key)
        ---@type number length
        ---@type string err_redis_hlen
        local length, err_redis_hlen = nauthilus.redis_hlen(redis_key)
        if err_redis_hlen ~= nil then
            nauthilus.custom_log_add(N .. "_redis_hlen_error", err_redis_hlen)
        else
            if length == 1 then
                nauthilus.redis_expire(redis_key, 3600)
            end
        end
    end

    --- This function adds a Redis hash map for a user with the key "session" and the value "server".
    ---@param session string
    ---@param server string
    ---@return void
    local function add_session(session, server)
        if session == nil then
            return
        end

        local redis_key = "ntc:DS:" .. crypto.md5(request.account)

        ---@type string err_redis_hset
        local _, err_redis_hset = nauthilus.redis_hset(redis_key, session, server)
        if err_redis_hset ~= nil then
            nauthilus.custom_log_add(N .. "_redis_hset_error", err_redis_hset)
        end

        set_initial_expiry(redis_key)
        nauthilus.custom_log_add(N .. "_dovecot_session", session)
    end

    --- This function retrieves a server from a Redis hash map of a user if any was found.
    ---@param session string
    ---@return string
    local function get_server_from_sessions(session)
        ---@type string redis_key
        local redis_key = "ntc:DS:" .. crypto.md5(request.account)

        ---@type string server_from_session
        ---@type string err_redis_hget
        local server_from_session, err_redis_hget = nauthilus.redis_hget(redis_key, session)
        if err_redis_hget ~= nil then
            nauthilus.custom_log_add(N .. "_redis_hget_error", err_redis_hget)

            return nil
        end

        if server_from_session ~= "" then
            return server_from_session
        end

        ---@type table all_sessions
        ---@type string err_redis_hgetall
        local all_sessions, err_redis_hgetall = nauthilus.redis_hgetall(redis_key)
        if err_redis_hgetall ~= nil then
            nauthilus.custom_log_add(N .. "_redis_hgetall_error", err_redis_hget)

            return nil
        end

        ---@param first_server string
        for _, first_server in pairs(all_sessions) do
            return first_server
        end

        return nil
    end

    -- Only look for backend servers, if a user was authenticated (passdb requests)
    if request.authenticated and not request.no_auth then
        ---@type number num_of_bs
        local num_of_bs = 0

        local backend_servers = nauthilus.get_backend_servers()
        if backend_servers ~= nil and type(backend_servers) == "table" then
            num_of_bs = #backend_servers

            ---@type string server_ip
            local server_ip = ""

            ---@type string new_server_ip
            local new_server_ip = ""

            local session = get_dovecot_session()
            if session ~= nil then
                local maybe_server = get_server_from_sessions(session)
                if maybe_server ~= nil then
                    server_ip = maybe_server
                end
            end

            if num_of_bs > 0 then
                ---@type table attributes
                local attributes = {}

                ---@type userdata b
                local b = backend_result.new()

                ---@param server table
                for _, server in ipairs(backend_servers) do
                    new_server_ip = server.ip

                    if server_ip == new_server_ip then
                        attributes["Proxy-Host"] = server_ip

                        add_session(session, server_ip)
                        nauthilus.custom_log_add(N .. "_backend_server_current", server_ip)

                        b:attributes(attributes)
                        nauthilus.apply_backend_result(b)

                        break
                    end
                end

                if server_ip ~= new_server_ip then
                    -- Put your own logic here to select a proper server for the user. In this demo, the last server
                    -- available is always used.
                    attributes["Proxy-Host"] = new_server_ip

                    add_session(session, new_server_ip)
                    nauthilus.custom_log_add(N .. "_backend_server_new", new_server_ip)

                    b:attributes(attributes)
                    nauthilus.apply_backend_result(b)
                end
            end
        end

        if num_of_bs == 0 then
            nauthilus.custom_log_add(N .. "_backend_server", "failed")
            nauthilus.status_message_set("No backend servers are available")

            return nauthilus.FILTER_ACCEPT, nauthilus.FILTER_RESULT_FAIL
        else
            nauthilus.custom_log_add(N .. "_backend_server", "success")
        end

        return nauthilus.FILTER_ACCEPT, nauthilus.FILTER_RESULT_OK
    end

    -- Anything else must be a rejected request
    return nauthilus.FILTER_REJECT, nauthilus.FILTER_RESULT_OK
end
