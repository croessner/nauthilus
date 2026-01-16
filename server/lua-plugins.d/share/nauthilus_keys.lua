-- Copyright (C) 2025 Christian Rößner
--
-- Helper for building Redis keys with optional Cluster hash-tags.
-- On Sentinel/standalone this is harmless; on Cluster it keeps related keys in the same slot.

local nauthilus_util = require("nauthilus_util")
local crypto = require('glua_crypto')

local M = {}

local function toboolean(v)
    if v == nil or v == "" then
        return true
    end
    return nauthilus_util.toboolean(v)
end

local USE_HASHTAGS = toboolean(os.getenv("USE_KEY_HASHTAGS"))
local HASHTAG_PREFIX = os.getenv("KEY_HASHTAG_PREFIX") or "acm-"

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

return M
