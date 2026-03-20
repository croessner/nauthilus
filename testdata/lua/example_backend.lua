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

function nauthilus_backend_verify_password(request)
    -- Get credentials from context
    local username = nauthilus_context.context_get("username")
    local password = nauthilus_context.context_get("password")

    if not username or not password then
        return nil  -- Authentication failed
    end

    -- Check Redis cache for user
    local cache_key = "backend:cache:" .. username
    local cached_user = nauthilus_redis.get(cache_key)

    if cached_user then
        -- User found in cache, create backend result
        local result = nauthilus_backend_result.new()
        result.authenticated = true
        result.user_found = true
        result.account_field = username
        result.unique_user_id = "uid-" .. username
        result.display_name = "Cached User"

        return result
    end

    -- User not found
    return nil
end
