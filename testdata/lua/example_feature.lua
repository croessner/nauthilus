-- Example Lua feature for testing
-- This feature checks for suspicious login patterns
--
-- Usage:
--   ./nauthilus/bin/nauthilus --test-lua testdata/lua/example_feature.lua \
--                             --test-callback feature \
--                             --test-mock testdata/lua/feature_test.json

local nauthilus_context = require("nauthilus_context")
local nauthilus_redis = require("nauthilus_redis")

function nauthilus_call_feature(request)
    -- Get brute force count from context
    local bf_count = nauthilus_context.context_get("brute_force_count")

    if bf_count and bf_count > 3 then
        -- Log suspicious activity
        return true  -- Feature triggered
    end

    -- Check if IP is on blocklist
    local client_ip = nauthilus_context.context_get("client_ip")
    if client_ip then
        local blocked = nauthilus_redis.exists("blocklist:" .. client_ip)
        if blocked == 1 then
            return true  -- Feature triggered
        end
    end

    return false  -- Feature not triggered
end
