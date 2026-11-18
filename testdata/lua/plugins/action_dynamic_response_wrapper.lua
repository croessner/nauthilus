-- Runs dynamic_response.lua under the Redis layout probe. Fixtures seed attack and step-up data under the names
-- account_centric_monitoring.lua and account_protection_mode.lua write.
local nauthilus_redis = require("nauthilus_redis")
local probe = require("redis_layout_probe")

probe.install()
probe.upload_init_scripts()

dofile("server/lua-plugins.d/actions/dynamic_response.lua")

local call_action = nauthilus_call_action

function nauthilus_call_action(request)
    local result = call_action(request)

    -- A seeded step-up hint must move the account into the CAPTCHA/step-up set.
    if request.username ~= nil and request.username ~= "" then
        probe.require_value("step-up account in captcha set", nauthilus_redis.redis_sismember(
            probe.connection(), probe.PREFIX .. "multilayer:global:captcha_accounts", request.username
        ))
    end

    return result
end
