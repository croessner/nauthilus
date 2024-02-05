local json = require("json")

function nauthilus_call_filter(request)
    -- Only look for backend servers, if a user was authenticated
    if request.authenticated then
        local result = {}
        local num_of_bs = 0

        result.caller = "nginx.lua"
        result.level = "info"
        result.session = request.session

        local backend_servers = nauthilus.get_nginx_backend_servers()
        if backend_servers ~= nil and type(backend_servers) == "table" then
            num_of_bs = #backend_servers

            for i, bs in pairs(backend_servers) do
                if bs ~= nil and type(bs) == "table" then
                    for server, port in pairs(bs) do
                        result["server_" .. i] = server .. ":" .. tostring(port)

                        -- Just an example
                        if i == 1 then
                            nauthilus.select_nginx_backend_server(server, port)

                            nauthilus.custom_log_add("nginx_backend_server", server .. ":" .. tostring(port))
                        end

                        break
                    end
                end
            end
        end

        print(json.encode(result))

        if num_of_bs == 0 then
            nauthilus.custom_log_add("nginx_backend", "failed")
            nauthilus.context_set("nginx_backend", "fail")
        else
            nauthilus.custom_log_add("nginx_backend", "success")
            nauthilus.context_set("nginx_backend", "ok")
        end


        return nauthilus.FILTER_ACCEPT, nauthilus.FILTER_RESULT_OK
    end

    return nauthilus.FILTER_REJECT, nauthilus.FILTER_RESULT_OK
end