local nauthilus_context = require("nauthilus_context")

dofile("server/lua-plugins.d/subject/test_context_chain.lua")

local original = nauthilus_call_subject

function nauthilus_call_subject(request)
    nauthilus_context.context_set("test_stage_environment", "environment")
    nauthilus_context.context_set("test_marker_environment", tostring(request.session or ""))

    local action, result = original(request)

    return action, result
end
