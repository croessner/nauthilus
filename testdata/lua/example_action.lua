-- Example Lua action for testing
-- This action records login events
--
-- Usage:
--   ./nauthilus/bin/nauthilus --test-lua testdata/lua/example_action.lua \
--                             --test-callback action \
--                             --test-mock testdata/lua/action_test.json

local nauthilus_context = require("nauthilus_context")
local nauthilus_redis = require("nauthilus_redis")

function nauthilus_call_action(request)
    -- Get user information
    local username = nauthilus_context.context_get("username")
    local client_ip = nauthilus_context.context_get("client_ip")
    local service = nauthilus_context.context_get("service")

    if not username then
        return false
    end

    -- Increment login counter
    local key = "login:count:" .. username
    nauthilus_redis.incr(key)
    nauthilus_redis.expire(key, 86400)  -- 24 hours

    -- Store last login IP
    local ip_key = "login:last_ip:" .. username
    nauthilus_redis.set(ip_key, client_ip)

    return true  -- Action succeeded
end
