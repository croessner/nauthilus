local nauthilus_context = require("nauthilus_context")
local nauthilus_util = require("nauthilus_util")

nauthilus_util.get_redis_key = function(_, key)
    return "ntc:" .. tostring(key)
end

package.loaded["nauthilus_geoip_bridge"] = {
    attach = function()
        return {}
    end,
}

dofile("server/lua-plugins.d/subject/geoip_reputation.lua")

local original = nauthilus_call_subject

function nauthilus_call_subject(request)
    local action, result = original(request)
    local facts = nauthilus_context.context_get("policy_facts") or {}
    local reputation = facts.geoip_reputation or {}

    if reputation.preexisting_decision ~= "suspicious" then
        error("pre-existing reputation decision was not emitted before learning")
    end

    if reputation.preexisting_samples ~= 40 then
        error("pre-existing reputation samples did not preserve the stored count")
    end

    if reputation.samples ~= 41 then
        error("legacy reputation samples did not retain post-update semantics")
    end

    return action, result
end
