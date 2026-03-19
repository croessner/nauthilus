local nauthilus_util = require("nauthilus_util")
local nauthilus_redis = require("nauthilus_redis")

nauthilus_util.if_error_raise = function(err)
    if err ~= nil and tostring(err) ~= "" then
        error(tostring(err))
    end
end

nauthilus_util.get_redis_key = function(_, key)
    return "ntc:" .. tostring(key)
end

nauthilus_util.log_info = function(_, logs)
    if type(logs) == "table" and logs.message ~= nil then
        nauthilus_builtin.custom_log_add("info", tostring(logs.message))
    end
end

nauthilus_redis.get_redis_connection = function(pool_name)
    return pool_name, nil
end

nauthilus_redis.redis_pipeline = function(_, mode, commands)
    local count = 0
    if type(commands) == "table" then
        count = #commands
    end

    nauthilus_builtin.custom_log_add("pipeline", tostring(mode) .. ":" .. tostring(count))

    return true, nil
end

dofile("server/lua-plugins.d/actions/failed_login_tracker.lua")
