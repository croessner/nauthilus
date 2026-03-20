local nauthilus_context = require("nauthilus_context")
local nauthilus_prometheus = require("nauthilus_prometheus")

nauthilus_prometheus.increment_counter = function(metric, labels)
    local feature = ""
    if type(labels) == "table" and labels.feature ~= nil then
        feature = tostring(labels.feature)
    end

    nauthilus_builtin.custom_log_add("metric", metric .. ":" .. feature)
end

nauthilus_context.context_set("rt", {
    feature_blocklist = true,
    filter_geoippolicyd = true,
    feature_failed_login_hotspot = true,
})

dofile("server/lua-plugins.d/actions/analytics.lua")
