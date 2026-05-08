local nauthilus_context = require("nauthilus_context")

dofile("server/lua-plugins.d/subject/test_context_chain.lua")

local original = nauthilus_call_subject

function nauthilus_call_subject(request)
    request.no_auth = true

    local action, result = original(request)
    local stage = nauthilus_context.context_get("test_stage_subject")
    local marker = nauthilus_context.context_get("test_marker_subject")

    if stage ~= "subject" then
        error("expected test_stage_subject to be 'subject', got '" .. tostring(stage) .. "'")
    end

    if marker ~= tostring(request.session or "") then
        error("expected test_marker_subject to match session, got '" .. tostring(marker) .. "'")
    end

    return action, result
end
