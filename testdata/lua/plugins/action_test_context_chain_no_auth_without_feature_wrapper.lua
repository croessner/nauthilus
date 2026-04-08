local nauthilus_context = require("nauthilus_context")

dofile("server/lua-plugins.d/actions/test_context_chain.lua")

local original = nauthilus_call_action

function nauthilus_call_action(request)
    request.no_auth = true
    request.feature = ""
    request.status_message = "OK"

    nauthilus_context.context_set("test_stage_filter", "filter")
    nauthilus_context.context_set("test_marker_filter", tostring(request.session or ""))

    return original(request)
end
