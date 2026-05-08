-- Example Lua environment source for testing
-- This environment source checks for suspicious login patterns
--
-- Usage:
--   ./nauthilus/bin/nauthilus --test-lua testdata/lua/example_environment.lua \
--                             --test-callback environment \
--                             --test-mock testdata/lua/environment_test.json

local nauthilus_context = require("nauthilus_context")
local nauthilus_redis = require("nauthilus_redis")

function nauthilus_call_environment(request)
    -- Get brute force count from context
    local bf_count = nauthilus_context.context_get("brute_force_count")

    if bf_count and bf_count > 3 then
        -- Log suspicious activity
        return nauthilus_builtin.ENVIRONMENT_TRIGGER_YES,
            nauthilus_builtin.ENVIRONMENT_ABORT_NO,
            nauthilus_builtin.ENVIRONMENT_RESULT_OK
    end

    -- Check if IP is on blocklist
    local client_ip = nauthilus_context.context_get("client_ip")
    if client_ip then
        local blocked = nauthilus_redis.exists("blocklist:" .. client_ip)
        if blocked == 1 then
            return nauthilus_builtin.ENVIRONMENT_TRIGGER_YES,
                nauthilus_builtin.ENVIRONMENT_ABORT_NO,
                nauthilus_builtin.ENVIRONMENT_RESULT_OK
        end
    end

    return nauthilus_builtin.ENVIRONMENT_TRIGGER_NO,
        nauthilus_builtin.ENVIRONMENT_ABORT_NO,
        nauthilus_builtin.ENVIRONMENT_RESULT_OK
end
