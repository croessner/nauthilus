-- Runs account_protection_mode.lua under the Redis layout probe against long-window data seeded under the name
-- account_longwindow_metrics.lua writes, and checks the protection state it records.
local nauthilus_redis = require("nauthilus_redis")
local probe = require("redis_layout_probe")

probe.install()
probe.upload_init_scripts()

dofile("server/lua-plugins.d/subject/account_protection_mode.lua")

local call_subject = nauthilus_call_subject

function nauthilus_call_subject(request)
    local action, result = call_subject(request)
    local conn = probe.connection()

    probe.require_value("protection state", nauthilus_redis.redis_hget(
        conn, probe.account_key("acct", "protection"), "active"
    ))
    probe.require_value("step-up hint", nauthilus_redis.redis_hget(
        conn, probe.account_key("acct", "stepup"), "required"
    ))
    probe.require_value("protection set membership", nauthilus_redis.redis_sismember(
        conn, probe.protocol_key("acct:protection_active"), request.username
    ))

    return action, result
end
