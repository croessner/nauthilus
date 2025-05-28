-- Copyright (C) 2024 Christian Rößner
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program. If not, see <https://www.gnu.org/licenses/>.

local nauthilus_util = require("nauthilus_util")

dynamic_loader("nauthilus_redis")
local nauthilus_redis = require("nauthilus_redis")

local N = "init_neural"

function nauthilus_run_hook(logging)
    local result = {}

    result.level = "info"
    result.caller = N .. ".lua"

    -- Get Redis connection
    local redis_pool = "default"
    local redis_handle, err_redis_client = nauthilus_redis.get_redis_connection(redis_pool)
    nauthilus_util.if_error_raise(err_redis_client)

    -- Define Redis Lua scripts for atomic operations

    -- ZAddRemExpire: Combines ZADD, ZREMRANGEBYSCORE, and EXPIRE operations
    local zadd_rem_expire_script = [[
        local key = KEYS[1]
        local score = tonumber(ARGV[1])
        local member = ARGV[2]
        local min_score = tonumber(ARGV[3])
        local max_score = tonumber(ARGV[4])
        local expire_seconds = tonumber(ARGV[5])

        redis.call("ZADD", key, score, member)
        redis.call("ZREMRANGEBYSCORE", key, min_score, max_score)
        redis.call("EXPIRE", key, expire_seconds)

        return redis.call("ZCARD", key)
    ]]

    -- HSetMultiExpire: Combines multiple HSET operations and an EXPIRE operation
    local hset_multi_expire_script = [[
        local key = KEYS[1]
        local expire_seconds = tonumber(ARGV[1])

        -- Process field-value pairs (starting from ARGV[2])
        for i = 2, #ARGV, 2 do
            local field = ARGV[i]
            local value = ARGV[i+1]
            redis.call("HSET", key, field, value)
        end

        redis.call("EXPIRE", key, expire_seconds)

        return "OK"
    ]]

    -- SAddMultiExpire: Combines multiple SADD operations and an EXPIRE operation
    local sadd_multi_expire_script = [[
        local key = KEYS[1]
        local expire_seconds = tonumber(ARGV[1])

        -- Process members (starting from ARGV[2])
        for i = 2, #ARGV do
            redis.call("SADD", key, ARGV[i])
        end

        redis.call("EXPIRE", key, expire_seconds)

        return redis.call("SCARD", key)
    ]]

    -- ExistsHSetMultiExpire: Checks if a key exists, and if not, performs multiple HSET operations and an EXPIRE operation
    local exists_hset_multi_expire_script = [[
        local key = KEYS[1]
        local expire_seconds = tonumber(ARGV[1])

        -- Check if the key exists
        local exists = redis.call("EXISTS", key)
        if exists == 0 then
            -- Process field-value pairs (starting from ARGV[2])
            for i = 2, #ARGV, 2 do
                local field = ARGV[i]
                local value = ARGV[i+1]
                redis.call("HSET", key, field, value)
            end

            redis.call("EXPIRE", key, expire_seconds)
            return 1
        end

        return 0
    ]]

    -- Upload scripts to Redis
    local scripts = {
        ["ZAddRemExpire"] = zadd_rem_expire_script,
        ["HSetMultiExpire"] = hset_multi_expire_script,
        ["SAddMultiExpire"] = sadd_multi_expire_script,
        ["ExistsHSetMultiExpire"] = exists_hset_multi_expire_script
    }

    for name, script in pairs(scripts) do
        local sha1, err_upload = nauthilus_redis.redis_upload_script(redis_handle, script, name)
        if err_upload then
            result.level = "error"
            result.error = "Failed to upload script " .. name .. ": " .. err_upload
            nauthilus_util.print_result(logging, result)
            return
        end
        result[name] = sha1
    end

    result.status = "finished"
    result.message = "Neural Redis scripts uploaded successfully"

    if logging.log_level == "debug" or logging.log_level == "info" then
        nauthilus_util.print_result(logging, result)
    end
end
