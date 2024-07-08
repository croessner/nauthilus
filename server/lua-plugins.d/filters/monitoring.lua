local crypto = require("crypto")

function nauthilus_call_filter(request)
    ---@return string
    local function get_dovecot_session()
        ---@type table headers
        local headers = nauthilus:get_all_http_request_headers()
        ---@param header_name string
        ---@param header_values table
        for header_name, header_values in pairs(headers) do
            if header_name == "x-dovecot-session" then
                return header_values[1]
            end
        end

        return nil
    end

    ---@param redis_key string
    ---@return void
    local function set_initial_expiry(redis_key)
        ---@type number length
        ---@type string err_redis_hlen
        local length, err_redis_hlen = nauthilus.redis_hlen(redis_key)
        if err_redis_hlen ~= nil then
            nauthilus.custom_log_add("reids_hlen_failure", err_redis_hlen)
        else
            if length == 1 then
                nauthilus.redis_expire(redis_key, 3600)
            end
        end
    end

    ---@param session string
    ---@param server string
    ---@return void
    local function add_session(session, server)
        local redis_key = "ntc:DS:" .. crypto.md5(request.account)

        ---@type string err_redis_hset
        local _, err_redis_hset = nauthilus.redis_hset(redis_key, session, server)
        if err_redis_hset ~= nil then
            nauthilus.custom_log_add("reids_hset_failure", err_redis_hset)
        end

        set_initial_expiry(redis_key)
    end

    local function get_server_from_sessions(session)
        local redis_key = "ntc:DS:" .. crypto.md5(request.account)

        ---@type string server_from_session
        ---@type string err_redis_hget
        local server_from_session, err_redis_hget = nauthilus.redis_hget(redis_key, session)
        if err_redis_hget ~= nil then
            nauthilus.custom_log_add("reids_hget_failure", err_redis_hget)

            return nil
        end

        if server_from_session ~= "" then
            return server_from_session
        end

        ---@type table all_sessions
        ---@type string err_redis_hgetall
        local all_sessions, err_redis_hgetall = nauthilus.redis_hgetall(redis_key)
        if err_redis_hgetall ~= nil then
            nauthilus.custom_log_add("reids_hgetall_failure", err_redis_hget)

            return nil
        end

        ---@param first_server string
        for _, first_server in pairs(all_sessions) do
            return first_server
        end

        return nil
    end

    -- Only look for backend servers, if a user was authenticated
    if request.authenticated then
        local result = {}
        local num_of_bs = 0

        result.caller = "monitoring.lua"
        result.level = "info"
        result.session = request.session

        local backend_servers = nauthilus.get_backend_servers()
        if backend_servers ~= nil and type(backend_servers) == "table" then
            num_of_bs = #backend_servers

            local server_ip = ""
            local new_server_ip = ""
            local server_port = 0

            local session = get_dovecot_session()
            if session ~= nil then
                local maybe_server = get_server_from_sessions(session)
                if maybe_server ~= nil then
                    server_ip = maybe_server
                end
            end

            for _, server in ipairs(backend_servers) do
                new_server_ip = server.ip
                server_port = server.port

                if server_ip == new_server_ip then
                    if session ~= nil then
                        add_session(session, server_ip)
                    end

                    nauthilus.select_backend_server(server_ip, server_port)
                    nauthilus.custom_log_add("backend_server_session", server_ip .. ":" .. tostring(server_port))

                    break
                end
            end

            if server_ip ~= new_server_ip then
                if session ~= nil then
                    add_session(session, new_server_ip)
                end

                nauthilus.select_backend_server(new_server_ip, server_port)
                nauthilus.custom_log_add("backend_server_new", server_ip .. ":" .. tostring(server_port))
            end
        end

        if num_of_bs == 0 then
            nauthilus.custom_log_add("backend_server_monitoring", "failed")
            nauthilus.context_set("backend_server_monitoring", "fail")
            nauthilus.status_message_set("No backend servers are available")

            return nauthilus.FILTER_ACCEPT, nauthilus.FILTER_RESULT_FAIL
        else
            nauthilus.custom_log_add("backend_server_monitoring", "success")
            nauthilus.context_set("backend_server_monitoring", "ok")
        end

        return nauthilus.FILTER_ACCEPT, nauthilus.FILTER_RESULT_OK
    end

    return nauthilus.FILTER_REJECT, nauthilus.FILTER_RESULT_OK
end
