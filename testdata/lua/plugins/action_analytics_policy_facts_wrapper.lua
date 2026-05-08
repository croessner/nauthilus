local nauthilus_context = require("nauthilus_context")
local nauthilus_prometheus = require("nauthilus_prometheus")

nauthilus_prometheus.increment_counter = function(metric, labels)
    local environment = ""
    if type(labels) == "table" and labels.environment ~= nil then
        environment = tostring(labels.environment)
    end

    nauthilus_builtin.custom_log_add("metric", metric .. ":" .. environment)
end

nauthilus_context.context_set("policy_facts", {
    blocklist = { matched = true },
    geoip = { rejected = true },
    failed_login_hotspot = { triggered = true },
    account_protection = { active = true },
})

dofile("server/lua-plugins.d/actions/analytics.lua")
