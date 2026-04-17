-- Example Lua backend for testing
-- This backend validates against cached user data
--
-- Usage:
--   ./nauthilus/bin/nauthilus --test-lua testdata/lua/example_backend.lua \
--                             --test-callback backend \
--                             --test-mock testdata/lua/backend_test.json

local nauthilus_context = require("nauthilus_context")
local nauthilus_redis = require("nauthilus_redis")
local nauthilus_backend_result = require("nauthilus_backend_result")

local function new_backend_result(authenticated, user_found)
    local result = nauthilus_backend_result.new()
    result.authenticated = authenticated
    result.user_found = user_found

    return result
end

function nauthilus_backend_verify_password(request)
    -- Get credentials from context
    local username = nauthilus_context.context_get("username")
    local password = nauthilus_context.context_get("password")

    if not username or not password then
        return nauthilus_builtin.BACKEND_RESULT_OK, new_backend_result(false, false)
    end

    -- Check Redis cache for user
    local cache_key = "backend:cache:" .. username
    local cached_user = nauthilus_redis.get(cache_key)

    if cached_user then
        -- User found in cache, create backend result
        local result = new_backend_result(true, true)
        result.account_field = username
        result.unique_user_id = "uid-" .. username
        result.display_name = "Cached User"

        return nauthilus_builtin.BACKEND_RESULT_OK, result
    end

    -- User not found
    return nauthilus_builtin.BACKEND_RESULT_OK, new_backend_result(false, false)
end
