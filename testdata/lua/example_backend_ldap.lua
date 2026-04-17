-- Example Lua backend for LDAP testing
-- This backend validates mocked LDAP integration.
--
-- Usage:
--   ./nauthilus/bin/nauthilus --test-lua testdata/lua/example_backend_ldap.lua \
--                             --test-callback backend \
--                             --test-mock testdata/lua/backend_ldap_test.json

local nauthilus_context = require("nauthilus_context")
local nauthilus_ldap = require("nauthilus_ldap")
local nauthilus_backend_result = require("nauthilus_backend_result")

local function new_backend_result(authenticated, user_found)
    local result = nauthilus_backend_result.new()
    result.authenticated = authenticated
    result.user_found = user_found

    return result
end

function nauthilus_backend_verify_password(request)
    local username = nauthilus_context.context_get("username")

    if not username or username == "" then
        return nauthilus_builtin.BACKEND_RESULT_OK, new_backend_result(false, false)
    end

    local host, port, endpoint_err = nauthilus_ldap.ldap_endpoint("default")
    if endpoint_err ~= nil or host == nil or port == nil then
        return nauthilus_builtin.BACKEND_RESULT_OK, new_backend_result(false, false)
    end

    local attrs, search_err = nauthilus_ldap.ldap_search({
        pool_name = "default",
        session = request.session or "ldap-test-session",
        basedn = "ou=people,dc=example,dc=com",
        filter = "(mail=" .. username .. ")",
        scope = "sub",
        attributes = { "uid", "mail", "displayName" }
    })

    if search_err ~= nil or attrs == nil then
        return nauthilus_builtin.BACKEND_RESULT_OK, new_backend_result(false, false)
    end

    local dn_uid = username
    if attrs.uid and attrs.uid[1] then
        dn_uid = attrs.uid[1]
    end

    local modify_res, modify_err = nauthilus_ldap.ldap_modify({
        pool_name = "default",
        session = request.session or "ldap-test-session",
        operation = "replace",
        dn = "uid=" .. dn_uid .. ",ou=people,dc=example,dc=com",
        attributes = {
            lastAuthMethod = "lua-test"
        }
    })

    if modify_err ~= nil or modify_res == nil then
        return nauthilus_builtin.BACKEND_RESULT_OK, new_backend_result(false, false)
    end

    local result = new_backend_result(true, true)
    result.account_field = username

    if attrs.uid and attrs.uid[1] then
        result.unique_user_id = attrs.uid[1]
    end

    if attrs.displayName and attrs.displayName[1] then
        result.display_name = attrs.displayName[1]
    end

    return nauthilus_builtin.BACKEND_RESULT_OK, result
end
