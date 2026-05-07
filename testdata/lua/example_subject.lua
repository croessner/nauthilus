-- Example Lua subject source for testing
-- This is a simple test subject source that checks the username
--
-- Usage:
--   ./nauthilus/bin/nauthilus --test-lua testdata/lua/example_subject.lua \
--                             --test-callback subject \
--                             --test-mock testdata/lua/subject_test.json

local nauthilus_context = require("nauthilus_context")
local nauthilus_redis = require("nauthilus_redis")

function nauthilus_call_subject(request)
    -- Get username from context
    local username = nauthilus_context.context_get("username")

    if username == nil or username == "" then
        return nauthilus_builtin.SUBJECT_REJECT, nauthilus_builtin.SUBJECT_RESULT_OK
    end

    -- Check Redis for blocklist
    local blocked = nauthilus_redis.exists("blocklist:" .. username)
    if blocked == 1 then
        return nauthilus_builtin.SUBJECT_REJECT, nauthilus_builtin.SUBJECT_RESULT_OK
    end

    -- All checks passed
    return nauthilus_builtin.SUBJECT_ACCEPT, nauthilus_builtin.SUBJECT_RESULT_OK
end
