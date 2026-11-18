-- Runs account_centric_monitoring.lua under the Redis layout probe and checks that the flagged account and the
-- per-account windows land under the names the protection, soft-delay, and dynamic-response readers use.
local nauthilus_redis = require("nauthilus_redis")
local probe = require("redis_layout_probe")

probe.install()
probe.upload_init_scripts()

dofile("server/lua-plugins.d/subject/account_centric_monitoring.lua")

local call_subject = nauthilus_call_subject

function nauthilus_call_subject(request)
    local action, result = call_subject(request)
    local conn = probe.connection()

    probe.require_value("attacked-account flag", nauthilus_redis.redis_zscore(
        conn, probe.protocol_key("multilayer:distributed_attack:accounts"), request.username
    ))
    probe.require_value("1h unique-IP window", nauthilus_redis.redis_zscore(
        conn, probe.account_key("multilayer:account", "ips:3600"), request.client_ip
    ))

    return action, result
end
