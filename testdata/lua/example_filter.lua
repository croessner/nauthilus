-- Example Lua filter for testing
-- This is a simple test filter that checks the username
--
-- Usage:
--   ./nauthilus/bin/nauthilus --test-lua testdata/lua/example_filter.lua \
--                             --test-callback filter \
--                             --test-mock testdata/lua/filter_test.json

local nauthilus_context = require("nauthilus_context")
local nauthilus_redis = require("nauthilus_redis")

function nauthilus_call_filter(request)
    -- Get username from context
    local username = nauthilus_context.context_get("username")

    if username == nil or username == "" then
        return -1  -- Reject if no username
    end

    -- Check Redis for blocklist
    local blocked = nauthilus_redis.exists("blocklist:" .. username)
    if blocked == 1 then
        return -1  -- Reject if user is blocked
    end

    -- All checks passed
    return 0  -- Accept
end
