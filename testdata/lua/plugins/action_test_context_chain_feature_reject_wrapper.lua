local nauthilus_context = require("nauthilus_context")

dofile("server/lua-plugins.d/actions/test_context_chain.lua")

local original = nauthilus_call_action

function nauthilus_call_action(request)
    nauthilus_context.context_set("test_stage_feature", "feature")
    nauthilus_context.context_set("test_marker_feature", tostring(request.session or ""))

    request.feature_rejected = true
    request.status_message = "Feature rejected the request"

    return original(request)
end
