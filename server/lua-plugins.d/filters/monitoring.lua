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

            local server_ip = ""
            local server_port = 0

            for i, server in pairs(backend_servers) do
                --[[
                print("Protocol: " .. server.protocol)
                print("IP: " .. server.ip)
                print("Port: " .. server.port)
                if server.haproxy_v2 then
                    print("HAProxyV2 is enabled.")
                else
                    print("HAProxyV2 is not enabled.")
                end
                ]]--

                server_ip = server.ip
                server_port = server.port

                -- Just an example
                if i == 1 then
                    nauthilus.select_backend_server(server_ip, server_port)

                    nauthilus.custom_log_add("backend_server", server_ip .. ":" .. tostring(server_port))
                end

                break
            end
        end

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
