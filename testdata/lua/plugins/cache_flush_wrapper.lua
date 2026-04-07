local nauthilus_cache = require("nauthilus_cache")
local nauthilus_context = require("nauthilus_context")

local function build_keys(username)
    return {
        "ucp:__default__:" .. username,
        "user_name:__default__:" .. username
    }
end

function nauthilus_cache_flush(request)
    local username = tostring(request.username or "")
    local account_name = nauthilus_context.context_get("account")

    if account_name == nil or tostring(account_name) == "" then
        account_name = "fallback-account:" .. username
    else
        account_name = tostring(account_name)
    end

    local marker_key = "cache_flush:marker:" .. username
    nauthilus_cache.cache_set(marker_key, true, 0)

    local marker = nauthilus_cache.cache_get(marker_key)
    if marker ~= true then
        error("cache marker write/read failed")
    end

    local additional_keys = build_keys(username)
    nauthilus_builtin.custom_log_add("cache_flush_keys", table.concat(additional_keys, ","))
    nauthilus_builtin.custom_log_add("cache_flush_account", account_name)

    return additional_keys, account_name
end
