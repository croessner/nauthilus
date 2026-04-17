local nauthilus_util = require("nauthilus_util")

nauthilus_util.if_error_raise = function(err)
    if err ~= nil and tostring(err) ~= "" then
        error(tostring(err))
    end
end

package.preload["nauthilus_password"] = function()
    return {
        compare_passwords = function(stored, provided)
            return tostring(stored) == tostring(provided), nil
        end,
    }
end

package.preload["nauthilus_backend_result"] = function()
    local M = {}

    function M.new()
        local obj = {}

        function obj:authenticated(value)
            self.authenticated = value and true or false
        end

        function obj:user_found(value)
            self.user_found = value and true or false
        end

        function obj:account_field(value)
            self.account_field = value
        end

        function obj:totp_secret_field(value)
            self.totp_secret_field = value
        end

        function obj:unique_user_id_field(value)
            self.unique_user_id_field = value
        end

        function obj:display_name_field(value)
            self.display_name_field = value
        end

        function obj:attributes(value)
            self.attributes = value
        end

        return obj
    end

    return M
end

nauthilus_backend_result = require("nauthilus_backend_result")

dofile("server/lua-plugins.d/backend/backend.lua")

local original = nauthilus_backend_verify_password

function nauthilus_backend_verify_password(request)
    local status, backend_result = original(request)

    return status, backend_result
end
