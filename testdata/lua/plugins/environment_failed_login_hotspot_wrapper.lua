local nauthilus_util = require("nauthilus_util")

nauthilus_util.get_redis_key = function(_, key)
    return "ntc:" .. tostring(key)
end

package.loaded["time"] = {
    unix = function()
        return 1000
    end,
}

dofile("server/lua-plugins.d/environment/failed_login_hotspot.lua")
