local nauthilus_context = require("nauthilus_context")
local nauthilus_prometheus = require("nauthilus_prometheus")

nauthilus_prometheus.increment_counter = function(metric, labels)
    local environment = ""
    if type(labels) == "table" and labels.environment ~= nil then
        environment = tostring(labels.environment)
    end

    nauthilus_builtin.custom_log_add("metric", metric .. ":" .. environment)
end

nauthilus_context.context_set("rt", {
    environment_blocklist = true,
    subject_geoippolicyd = true,
    environment_failed_login_hotspot = true,
})

dofile("server/lua-plugins.d/actions/analytics.lua")
