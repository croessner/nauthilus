-- Copyright (C) 2025 Christian Rößner
--
-- Builds the Redis keys of the bundled monitoring, protection, and response plugins.
--
-- Layout:
--   * per-account keys:  <prefix><namespace>:<account_tag><username>:proto:<protocol>:<suffix>
--   * per-protocol sets: <prefix><name>:proto:<protocol>
--   * global pattern:    <prefix>multilayer:global:<global_tag><name>
--
-- Every multi-key Redis script receives keys that share one hash tag: the account tag for ACM_TrackAndAggregate and
-- ALM_TrackAndSnapshot, the global tag for GPM_TrackAndCurrent. A Redis Cluster client therefore sends the names
-- unchanged, and every reader finds them. Global sets that a per-account script would otherwise mix in (attacked
-- accounts, password-spray windows) are written in their own single-key calls.
--
-- USE_KEY_HASHTAGS=false empties both tags. That is safe on standalone and Sentinel Redis only: on Redis Cluster the
-- server rewrites untagged script keys to one shared tag, and the readers no longer find them.

local nauthilus_util = require("nauthilus_util")
local crypto = require('glua_crypto')

local M = {}

-- Window sizes in seconds. ACM_TrackAndAggregate and GPM_TrackAndCurrent receive their windows in this order.
M.ACCOUNT_WINDOWS = { 3600, 86400, 604800 }
M.GLOBAL_WINDOWS = { 60, 300, 900, 3600, 86400, 604800 }
M.LONG_WINDOWS = { 86400, 604800 }

M.UNKNOWN_PROTOCOL = "unknown"

local ACCOUNT_WINDOW_KINDS = { "ips", "fails", "metrics" }

local function toboolean(v)
    if v == nil or v == "" then
        return true
    end
    return nauthilus_util.toboolean(v)
end

local USE_HASHTAGS = toboolean(nauthilus_util.getenv("USE_KEY_HASHTAGS", "true"))
local HASHTAG_PREFIX = nauthilus_util.getenv("KEY_HASHTAG_PREFIX", "acm-")

--- account_tag returns a hash-tag for the given username or an empty string when disabled.
--- Example: "{acm-<md5>}" when enabled; "" when disabled.
--- The tag should be concatenated directly before the username segment, like:
---   "ntc:acct:" .. account_tag(username) .. username .. ":stepup"
---@param username string
---@return string
function M.account_tag(username)
    if not username or username == "" then
        return ""
    end

    if not USE_HASHTAGS then
        return ""
    end

    local id = crypto.md5(username)

    return "{" .. HASHTAG_PREFIX .. id .. "}"
end

--- global_tag returns the hash tag shared by all GPM_TrackAndCurrent keys, or "" when hash tags are disabled.
--- The md5-based account tags never collide with it.
---@return string
function M.global_tag()
    if not USE_HASHTAGS then
        return ""
    end

    return "{" .. HASHTAG_PREFIX .. "global}"
end

--- protocol returns the protocol key segment; an empty protocol maps to "unknown".
---@param protocol string|nil
---@return string
function M.protocol(protocol)
    if protocol == nil or protocol == "" then
        return M.UNKNOWN_PROTOCOL
    end

    return tostring(protocol)
end

--- account_key returns <prefix><namespace>:<account_tag><username>:proto:<protocol>:<suffix>.
---@param request table
---@param namespace string
---@param username string
---@param protocol string|nil
---@param suffix string
---@return string
function M.account_key(request, namespace, username, protocol, suffix)
    return nauthilus_util.get_redis_key(
        request,
        namespace .. ":" .. M.account_tag(username) .. username .. ":proto:" .. M.protocol(protocol) .. ":" .. suffix
    )
end

--- account_state_key returns the per-account HASH acct:<...>:<kind> (longwindow, protection, or stepup).
---@param request table
---@param username string
---@param protocol string|nil
---@param kind string
---@return string
function M.account_state_key(request, username, protocol, kind)
    return M.account_key(request, "acct", username, protocol, kind)
end

--- protocol_key returns <prefix><name>:proto:<protocol> for per-protocol sets of usernames.
---@param request table
---@param name string
---@param protocol string|nil
---@return string
function M.protocol_key(request, name, protocol)
    return nauthilus_util.get_redis_key(request, name .. ":proto:" .. M.protocol(protocol))
end

--- attacked_accounts_key returns the ZSET of accounts flagged by account_centric_monitoring.lua.
---@param request table
---@param protocol string|nil
---@return string
function M.attacked_accounts_key(request, protocol)
    return M.protocol_key(request, "multilayer:distributed_attack:accounts", protocol)
end

--- protection_active_key returns the SET of accounts currently in protection mode.
---@param request table
---@param protocol string|nil
---@return string
function M.protection_active_key(request, protocol)
    return M.protocol_key(request, "acct:protection_active", protocol)
end

--- spray_key returns the global password-spray ZSET of one long window.
---@param request table
---@param window number
---@return string
function M.spray_key(request, window)
    return nauthilus_util.get_redis_key(request, "z:spray:pw:" .. window)
end

--- global_key returns <prefix>multilayer:global:<global_tag><name>.
---@param request table
---@param name string
---@return string
function M.global_key(request, name)
    return nauthilus_util.get_redis_key(request, "multilayer:global:" .. M.global_tag() .. name)
end

--- global_window_key returns a global sliding-window ZSET (auth_attempts, unique_ips, or unique_users).
---@param request table
---@param metric string
---@param window number
---@return string
function M.global_window_key(request, metric, window)
    return M.global_key(request, metric .. ":" .. window)
end

--- current_metrics_key returns the HASH with the current one-hour global metrics.
---@param request table
---@return string
function M.current_metrics_key(request)
    return M.global_key(request, "current_metrics")
end

--- historical_metrics_key returns the HASH with the first snapshot of one UTC hour (YYYY-MM-DD-HH).
---@param request table
---@param hour_key string
---@return string
function M.historical_metrics_key(request, hour_key)
    return M.global_key(request, "historical_metrics:" .. hour_key)
end

--- account_window_keys returns the ACM_TrackAndAggregate KEYS: ips, fails, and metrics for each account window.
---@param request table
---@param username string
---@param protocol string|nil
---@return table
function M.account_window_keys(request, username, protocol)
    local keys = {}

    for _, kind in ipairs(ACCOUNT_WINDOW_KINDS) do
        for _, window in ipairs(M.ACCOUNT_WINDOWS) do
            table.insert(keys, M.account_key(request, "multilayer:account", username, protocol, kind .. ":" .. window))
        end
    end

    return keys
end

--- account_longwindow_keys returns the ALM_TrackAndSnapshot KEYS: one HLL per long window, the failure ZSET, and the
--- long-window snapshot.
---@param request table
---@param username string
---@param protocol string|nil
---@return table
function M.account_longwindow_keys(request, username, protocol)
    local keys = {}

    for _, window in ipairs(M.LONG_WINDOWS) do
        table.insert(keys, M.account_key(request, "hll:acct", username, protocol, "ips:" .. window))
    end

    table.insert(keys, M.account_key(request, "z:acct", username, protocol, "fails"))
    table.insert(keys, M.account_state_key(request, username, protocol, "longwindow"))

    return keys
end

--- account_keys returns every per-account key of the bundled plugins for one protocol.
---@param request table
---@param username string
---@param protocol string|nil
---@return table
function M.account_keys(request, username, protocol)
    local keys = M.account_window_keys(request, username, protocol)

    for _, key in ipairs(M.account_longwindow_keys(request, username, protocol)) do
        table.insert(keys, key)
    end

    table.insert(keys, M.account_state_key(request, username, protocol, "protection"))
    table.insert(keys, M.account_state_key(request, username, protocol, "stepup"))

    return keys
end

--- global_pattern_keys returns the GPM_TrackAndCurrent KEYS: attempts, IPs, and users per global window, then the
--- current, historical (hour_key), and per-second (now) metrics hashes.
---@param request table
---@param now number
---@param hour_key string
---@return table
function M.global_pattern_keys(request, now, hour_key)
    local keys = {}

    for _, window in ipairs(M.GLOBAL_WINDOWS) do
        table.insert(keys, M.global_window_key(request, "auth_attempts", window))
        table.insert(keys, M.global_window_key(request, "unique_ips", window))
        table.insert(keys, M.global_window_key(request, "unique_users", window))
    end

    table.insert(keys, M.current_metrics_key(request))
    table.insert(keys, M.historical_metrics_key(request, hour_key))
    table.insert(keys, M.global_key(request, "metrics:" .. now))

    return keys
end

return M
