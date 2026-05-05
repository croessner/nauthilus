local nauthilus_context = require("nauthilus_context")
local nauthilus_prometheus = require("nauthilus_prometheus")

nauthilus_prometheus.increment_counter = function(metric, labels)
    local feature = ""
    if type(labels) == "table" and labels.feature ~= nil then
        feature = tostring(labels.feature)
    end

    nauthilus_builtin.custom_log_add("metric", metric .. ":" .. feature)
end

nauthilus_context.context_set("policy_facts", {
    blocklist = { matched = true },
    geoip = { rejected = true },
    failed_login_hotspot = { triggered = true },
    account_protection = { active = true },
})

dofile("server/lua-plugins.d/actions/analytics.lua")
