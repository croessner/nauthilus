-- Copyright (C) 2026 Christian Rößner
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program. If not, see <https://www.gnu.org/licenses/>.

-- Test probe for the Redis key layout of the bundled Lua plugins.
--
-- The luatest Redis runtime is a single miniredis instance, so it cannot show what Redis Cluster or a custom Redis
-- pool would do. The probe makes those failure modes visible on every Redis call of the plugin under test:
--
--   * cluster slot: a script whose keys do not share one hash tag is rewritten by the server on a Cluster client
--     (rediscli.EnsureKeysInSameSlot), so readers that use the original names miss the data;
--   * custom pool: the plugin must pass the connection of CUSTOM_REDIS_POOL_NAME, never the pool name string,
--     which the server silently replaces with the default handle;
--   * retired keys: the plugin must not touch key layouts the server no longer writes.
--
-- Fixtures that use the probe set CUSTOM_REDIS_POOL_NAME to M.POOL. The probe hands out a marker connection for that
-- pool and forwards marker calls to the default miniredis handle.

local nauthilus_util = require("nauthilus_util")
local nauthilus_redis = require("nauthilus_redis")

local M = {}

M.PREFIX = "ntc:"
M.POOL = "lua-custom"

-- Fixture identity shared by every layout fixture; ACCOUNT_TAG is "{acm-" .. md5(USERNAME) .. "}".
M.USERNAME = "alice@example.test"
M.PROTOCOL = "imap"
M.ACCOUNT_TAG = "{acm-2960a687c8031d3d105b67802b5e130e}"
M.GLOBAL_TAG = "{acm-global}"

--- account_key pins the documented per-account layout: <prefix><namespace>:<acct_tag><username>:proto:<protocol>:<suffix>.
function M.account_key(namespace, suffix)
    return M.PREFIX .. namespace .. ":" .. M.ACCOUNT_TAG .. M.USERNAME .. ":proto:" .. M.PROTOCOL .. ":" .. suffix
end

--- protocol_key pins the documented per-protocol layout: <prefix><name>:proto:<protocol>.
function M.protocol_key(name)
    return M.PREFIX .. name .. ":proto:" .. M.PROTOCOL
end

--- global_key pins the documented global-pattern layout: <prefix>multilayer:global:<global_tag><name>.
function M.global_key(name)
    return M.PREFIX .. "multilayer:global:" .. M.GLOBAL_TAG .. name
end

local INIT_SCRIPT = "server/lua-plugins.d/init/init.lua"
-- Functions that take no connection argument and therefore stay unwrapped.
local UNWRAPPED_FUNCTIONS = {
    register_redis_pool = true,
    get_redis_connection = true,
    redis_encrypt = true,
    redis_decrypt = true,
    redis_is_encryption_enabled = true,
}

local marker = setmetatable({}, {
    __tostring = function()
        return "probe-connection:" .. M.POOL
    end,
})

-- hash_tag mirrors rediscli.redisKeyHashTag: the span from the first "{" to the first "}".
local function hash_tag(key)
    local first_open = string.find(key, "{", 1, true)
    local first_close = string.find(key, "}", 1, true)

    if first_open == nil or first_close == nil or first_close < first_open then
        return nil
    end

    return string.sub(key, first_open, first_close)
end

-- assert_same_slot fails when a multi-key script call would be rewritten on a Cluster client.
local function assert_same_slot(label, keys)
    if type(keys) ~= "table" or #keys < 2 then
        return
    end

    local first = hash_tag(tostring(keys[1]))

    for i = 1, #keys do
        local tag = hash_tag(tostring(keys[i]))
        if tag == nil then
            error(string.format("cluster slot probe: key %q of %s has no hash tag", tostring(keys[i]), label))
        end

        if tag ~= first then
            error(string.format(
                "cluster slot probe: keys of %s do not share one hash tag: %q vs %q",
                label, tostring(keys[1]), tostring(keys[i])
            ))
        end
    end
end

-- is_retired reports whether a key uses a layout the server or the bundled plugins no longer write.
local function is_retired(key)
    if type(key) ~= "string" then
        return false
    end

    if string.find(key, "PW_HIST", 1, true) or string.find(key, "bf:TR:", 1, true) then
        return true
    end

    if string.find(key, "affected_accounts", 1, true) then
        return true
    end

    local unprefixed = key
    if string.sub(key, 1, #M.PREFIX) == M.PREFIX then
        unprefixed = string.sub(key, #M.PREFIX + 1)
    end

    if string.find(unprefixed, "^account:") or string.find(unprefixed, "^global:") then
        return true
    end

    if unprefixed == "multilayer:distributed_attack:accounts" then
        return true
    end

    if string.find(unprefixed, "^acct:") and not string.find(unprefixed, ":proto:", 1, true) then
        return string.find(unprefixed, ":longwindow$") ~= nil or string.find(unprefixed, ":stepup$") ~= nil
    end

    return false
end

-- assert_not_retired fails when any string argument of a Redis call names a retired key.
local function assert_not_retired(label, values)
    for _, value in ipairs(values) do
        if type(value) == "table" then
            assert_not_retired(label, value)
        elseif is_retired(value) then
            error(string.format("retired key probe: %s touches retired key %q", label, value))
        end
    end
end

-- check_pipeline_rows validates every row of a Lua Redis pipeline.
local function check_pipeline_rows(rows)
    for idx, row in ipairs(rows or {}) do
        local label = "pipeline row " .. idx .. " (" .. tostring(row[1]) .. ")"

        if row[1] == "run_script" then
            if type(row[3]) ~= "string" or type(row[4]) ~= "table" then
                error("pipeline probe: " .. label .. " must be {\"run_script\", \"\", \"<name>\", {keys}, {args}}")
            end

            assert_same_slot(label .. " " .. row[3], row[4])
        end
    end
end

-- resolve_connection maps the marker to the default handle and rejects pool name strings.
local function resolve_connection(name, conn)
    if conn == marker then
        return "default"
    end

    error(string.format(
        "custom pool probe: %s received %s %q instead of the connection of pool %q",
        name, type(conn), tostring(conn), M.POOL
    ))
end

-- wrap_function installs the probe around one nauthilus_redis function.
local function wrap_function(name, original)
    return function(conn, ...)
        local args = { ... }

        assert_not_retired(name, args)

        if name == "redis_run_script" then
            assert_same_slot("redis_run_script " .. tostring(args[2]), args[3])
        elseif name == "redis_pipeline" then
            check_pipeline_rows(args[2])
        end

        return original(resolve_connection(name, conn), ...)
    end
end

--- install patches nauthilus_redis and nauthilus_util for the plugin under test.
function M.install()
    nauthilus_util.get_redis_key = function(_, key)
        return M.PREFIX .. tostring(key)
    end

    for name, original in pairs(nauthilus_redis) do
        if type(original) == "function" and not UNWRAPPED_FUNCTIONS[name] then
            nauthilus_redis[name] = wrap_function(name, original)
        end
    end

    nauthilus_redis.register_redis_pool = function()
        return true, nil
    end

    nauthilus_redis.get_redis_connection = function(name)
        if name ~= M.POOL then
            return nil, "custom pool probe: unexpected pool " .. tostring(name)
        end

        return marker, nil
    end
end

--- connection returns the probe connection of the custom pool for wrapper assertions.
function M.connection()
    return marker
end

--- upload_init_scripts runs init/init.lua so that named Redis scripts exist in miniredis.
function M.upload_init_scripts()
    local previous_hook = nauthilus_run_hook

    dofile(INIT_SCRIPT)

    local init_hook = nauthilus_run_hook
    nauthilus_run_hook = previous_hook

    init_hook({ logging = { log_level = "info", log_format = "json" } })
end

--- require_value fails unless the value is present.
function M.require_value(label, value)
    if value == nil or value == false or value == "" then
        error("layout probe: missing " .. label)
    end
end

--- require_absent fails when the value is present.
function M.require_absent(label, value)
    if value ~= nil and value ~= false and value ~= "" then
        error("layout probe: " .. label .. " still present: " .. tostring(value))
    end
end

return M
