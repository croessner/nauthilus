-- Runs the simulate_attack action of distributed-brute-force-test.lua under the Redis layout probe and checks that the
-- simulated attack lands under the names the monitoring readers use.
local nauthilus_redis = require("nauthilus_redis")
local probe = require("redis_layout_probe")

probe.install()
probe.upload_init_scripts()

dofile("server/lua-plugins.d/hooks/distributed-brute-force-test.lua")

local run_hook = nauthilus_run_hook

function nauthilus_run_hook(request)
    local result = run_hook(request)
    local conn = probe.connection()

    if type(result) ~= "table" or result.status ~= "success" then
        error("simulate_attack failed: " .. tostring(type(result) == "table" and result.message or result))
    end

    probe.require_value("attacked-account flag", nauthilus_redis.redis_zscore(
        conn, probe.protocol_key("multilayer:distributed_attack:accounts"), probe.USERNAME
    ))
    probe.require_value("current global metrics", nauthilus_redis.redis_hget(
        conn, probe.global_key("current_metrics"), "attempts"
    ))
    probe.require_value("simulated account failures", nauthilus_redis.redis_zcount(
        conn, probe.account_key("multilayer:account", "fails:3600"), "-inf", "+inf"
    ) ~= 0 or nil)

    return result
end
