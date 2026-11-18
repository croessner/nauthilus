-- Runs the reset_account action of distributed-brute-force-admin.lua under the Redis layout probe and checks that the
-- account's monitoring and protection state is gone while server-owned brute-force keys are left alone.
local nauthilus_redis = require("nauthilus_redis")
local probe = require("redis_layout_probe")

probe.install()
probe.upload_init_scripts()

dofile("server/lua-plugins.d/hooks/distributed-brute-force-admin.lua")

local run_hook = nauthilus_run_hook

function nauthilus_run_hook(request)
    local result = run_hook(request)
    local conn = probe.connection()

    if type(result) ~= "table" or result.status ~= "success" then
        error("reset_account failed: " .. tostring(type(result) == "table" and result.message or result))
    end

    probe.require_absent("attacked-account flag", nauthilus_redis.redis_zscore(
        conn, probe.protocol_key("multilayer:distributed_attack:accounts"), probe.USERNAME
    ))
    probe.require_absent("protection set membership", nauthilus_redis.redis_sismember(
        conn, probe.protocol_key("acct:protection_active"), probe.USERNAME
    ))
    probe.require_absent("captcha set membership", nauthilus_redis.redis_sismember(
        conn, probe.PREFIX .. "multilayer:global:captcha_accounts", probe.USERNAME
    ))
    probe.require_absent("protection state", nauthilus_redis.redis_hget(
        conn, probe.account_key("acct", "protection"), "active"
    ))
    probe.require_absent("long-window snapshot", nauthilus_redis.redis_hget(
        conn, probe.account_key("acct", "longwindow"), "fails_24h"
    ))
    probe.require_absent("1h failure window", nauthilus_redis.redis_zscore(
        conn, probe.account_key("multilayer:account", "fails:3600"), "seeded-failure"
    ))
    probe.require_value("other account in the attacked set", nauthilus_redis.redis_zscore(
        conn, probe.protocol_key("multilayer:distributed_attack:accounts"), "bob@example.test"
    ))

    return result
end
