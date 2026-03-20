local nauthilus_util = require("nauthilus_util")
local nauthilus_otel = require("nauthilus_opentelemetry")

nauthilus_util.if_error_raise = function(err)
    if err ~= nil and tostring(err) ~= "" then
        error(tostring(err))
    end
end

nauthilus_otel.is_enabled = function()
    return false
end

nauthilus_builtin.status_message_set = function(message)
    nauthilus_builtin.custom_log_add("status", tostring(message))
end

package.preload["glua_http"] = function()
    return {
        post = function()
            return {
                status_code = 200,
                body = '{"found":true}',
            }, nil
        end,
    }
end

dofile("server/lua-plugins.d/features/blocklist.lua")
