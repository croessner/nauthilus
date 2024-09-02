local nauthilus_util = require("nauthilus_util")
local nauthilus_context = require("nauthilus_context")

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

        nauthilus_util.if_error_raise(err)

        -- Get result table
        local rt = nauthilus_context.context_get("rt")
        if rt == nil then
            rt = {}
        end
        if nauthilus_util.is_table(rt) then
            rt.brute_force_haproxy = true

            nauthilus_context.context_set("rt", rt)
        end
    end

    -- Required by telegram.lua
    nauthilus_context.context_set("haproxy", "ok")

    nauthilus_builtin.custom_log_add("haproxy", "success")

    return nauthilus_builtin.ACTION_RESULT_OK
end
