local tcp = require("tcp")

function nauthilus_call_action(request)
    if not request.repeating then
        -- Send IP/Mask
        local conn, err = tcp.open(os.getenv('HAPROXY_STATS'))

        if request.protocol == "smtps" or request.protocol == "submission" then
            -- Use smtp-sink
            err = conn:write("add map " .. os.getenv('HAPROXY_SMTP_MAP') .. " " .. request.client_net .. " block_smtp\n")
        else
            -- Block connection
            err = conn:write("add map " .. os.getenv('HAPROXY_GENERIC_MAP') .. " " .. request.client_net .. " block_" .. request.protocol .. "\n")
        end

        if err then
            error(err)
        end
    end

    -- Required by telegram.lua
    nauthilus.context_set("haproxy", "ok")

    nauthilus.custom_log_add("haproxy", "success")

    return nauthilus.ACTION_RESULT_OK
end
