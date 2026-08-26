local nauthilus_http_response = require("nauthilus_http_response")

nauthilus_http_response.set_http_response_header = function(name, value)
    nauthilus_builtin.custom_log_add("header", tostring(name) .. "=" .. tostring(value))
end

dofile("server/lua-plugins.d/actions/bruteforce_header.lua")

local original = nauthilus_call_action

function nauthilus_call_action(request)
    request.brute_force_bucket = "smtp"

    return original(request)
end
