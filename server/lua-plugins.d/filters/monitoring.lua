local json = require("json")

function nauthilus_call_filter(request)
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

            for i, bs in pairs(backend_servers) do
                if bs ~= nil and type(bs) == "table" then
                    for _, server in pairs(bs) do
                        local server_ip = ""
                        local server_port = 0

                        for key, value in pairs(server) do
                            if key == "ip" then
                                server_ip = value
                            end

                            if key == "port" then
                                server_port = value
                            end
                        end

                        -- Just an example
                        if i == 1 then
                            nauthilus.select_backend_server(server_ip, server_port)

                            nauthilus.custom_log_add("backend_server", server_ip .. ":" .. tostring(server_port))
                        end

                        break
                    end
                end
            end
        end

        print(json.encode(result))

        if num_of_bs == 0 then
            nauthilus.custom_log_add("backend_server_monitoring", "failed")
            nauthilus.context_set("backend_server_monitoring", "fail")
        else
            nauthilus.custom_log_add("backend_server_monitoring", "success")
            nauthilus.context_set("backend_server_monitoring", "ok")
        end


        return nauthilus.FILTER_ACCEPT, nauthilus.FILTER_RESULT_OK
    end

    return nauthilus.FILTER_REJECT, nauthilus.FILTER_RESULT_OK
end