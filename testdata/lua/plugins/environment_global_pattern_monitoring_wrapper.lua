-- Runs global_pattern_monitoring.lua and then its reader security_metrics.lua under the Redis layout probe, and checks
-- that the current one-hour snapshot lands under the name dynamic_response.lua and the admin hook read.
local nauthilus_redis = require("nauthilus_redis")
local probe = require("redis_layout_probe")

probe.install()
probe.upload_init_scripts()

dofile("server/lua-plugins.d/environment/security_metrics.lua")

local call_security_metrics = nauthilus_call_environment

dofile("server/lua-plugins.d/environment/global_pattern_monitoring.lua")

local call_global_pattern = nauthilus_call_environment

function nauthilus_call_environment(request)
    local triggered, abort, result = call_global_pattern(request)

    probe.require_value("current global metrics", nauthilus_redis.redis_hget(
        probe.connection(), probe.global_key("current_metrics"), "attempts"
    ))

    call_security_metrics(request)

    return triggered, abort, result
end
