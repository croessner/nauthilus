local nauthilus_context = require("nauthilus_context")

dofile("server/lua-plugins.d/filters/test_context_chain.lua")

local original = nauthilus_call_filter

function nauthilus_call_filter(request)
    nauthilus_context.context_set("test_stage_feature", "feature")
    nauthilus_context.context_set("test_marker_feature", tostring(request.session or ""))

    local action, result = original(request)

    return action, result
end
