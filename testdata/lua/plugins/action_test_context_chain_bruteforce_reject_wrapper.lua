local nauthilus_context = require("nauthilus_context")

dofile("server/lua-plugins.d/actions/test_context_chain.lua")

local original = nauthilus_call_action

function nauthilus_call_action(request)
    request.feature = "brute_force"
    request.feature_rejected = true
    request.feature_stage_expected = false
    request.filter_stage_expected = false
    request.status_message = "Invalid login or password"

    return original(request)
end
