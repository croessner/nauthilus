local nauthilus_context = require("nauthilus_context")

dofile("server/lua-plugins.d/actions/test_context_chain.lua")

local original = nauthilus_call_action

function nauthilus_call_action(request)
    nauthilus_context.context_set("test_stage_environment", "environment")
    nauthilus_context.context_set("test_marker_environment", tostring(request.session or ""))

    request.environment_rejected = true
    request.environment_stage_expected = true
    request.subject_stage_expected = false
    request.status_message = "Environment source rejected the request"

    return original(request)
end
