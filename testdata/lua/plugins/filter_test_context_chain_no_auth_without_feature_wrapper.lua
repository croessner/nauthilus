local nauthilus_context = require("nauthilus_context")

dofile("server/lua-plugins.d/filters/test_context_chain.lua")

local original = nauthilus_call_filter

function nauthilus_call_filter(request)
    request.no_auth = true

    local accepted = original(request)
    if accepted then
        local stage = nauthilus_context.context_get("test_stage_filter")
        local marker = nauthilus_context.context_get("test_marker_filter")

        if stage ~= "filter" then
            error("expected test_stage_filter to be 'filter', got '" .. tostring(stage) .. "'")
        end

        if marker ~= tostring(request.session or "") then
            error("expected test_marker_filter to match session, got '" .. tostring(marker) .. "'")
        end

        return 1
    end

    return 0
end
