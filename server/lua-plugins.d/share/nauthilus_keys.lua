-- Copyright (C) 2025 Christian Rößner
--
-- Helper for building Redis keys with optional Cluster hash-tags.
-- On Sentinel/standalone this is harmless; on Cluster it keeps related keys in the same slot.

local nauthilus_util = require("nauthilus_util")

local M = {}

local function use_hashtags()
    local v = os.getenv("USE_KEY_HASHTAGS")
    if v == nil or v == "" then
        return true
    end
    return nauthilus_util.toboolean(v)
end

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

    if not use_hashtags() then
        return ""
    end

    local prefix = os.getenv("KEY_HASHTAG_PREFIX") or "acm-"
    local crypto = require('glua_crypto')
    local id = crypto.md5(username)

    return "{" .. prefix .. id .. "}"
end

return M
