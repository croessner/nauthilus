-- Runs account_longwindow_metrics.lua under the Redis layout probe and checks that the long-window snapshot and the
-- password-spray token land under the names their readers use.
local nauthilus_redis = require("nauthilus_redis")
local probe = require("redis_layout_probe")

probe.install()
probe.upload_init_scripts()

dofile("server/lua-plugins.d/environment/account_longwindow_metrics.lua")

local call_environment = nauthilus_call_environment

function nauthilus_call_environment(request)
    local triggered, abort, result = call_environment(request)
    local conn = probe.connection()

    probe.require_value("long-window snapshot", nauthilus_redis.redis_hget(
        conn, probe.account_key("acct", "longwindow"), "fails_24h"
    ))
    probe.require_value("24h spray token", nauthilus_redis.redis_zscore(
        conn, probe.PREFIX .. "z:spray:pw:86400", "deadbeef"
    ))

    return triggered, abort, result
end
