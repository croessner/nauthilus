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

-- Shared helper for policy-aware Lua plugins.
--
-- Emitted policy attributes:
--  - lua.plugin.<namespace>.<key> for emit*, set_public*, and status_message calls.

local nauthilus_context = require("nauthilus_context")

local M = {}

local CONTEXT_KEY = "policy_facts"
local LOG_PREFIX = "policy_fact_"
local ATTRIBUTE_PREFIX = "lua.plugin."
local policy_module = nil

local function normalize_segment(value)
    local segment = tostring(value or ""):lower()
    segment = segment:gsub("[^%w_]+", "_")
    segment = segment:gsub("^_+", "")
    segment = segment:gsub("_+$", "")

    if segment == "" then
        return "unknown"
    end

    return segment
end

local function stringify(value)
    if type(value) ~= "table" then
        return tostring(value)
    end

    local parts = {}
    for _, item in ipairs(value) do
        table.insert(parts, tostring(item))
    end

    return table.concat(parts, ",")
end

local function facts_table()
    local facts = nauthilus_context.context_get(CONTEXT_KEY)
    if type(facts) ~= "table" then
        facts = {}
    end

    return facts
end

local function add_public_log(namespace, key, value)
    if nauthilus_builtin == nil or nauthilus_builtin.custom_log_add == nil then
        return
    end

    nauthilus_builtin.custom_log_add(LOG_PREFIX .. namespace .. "_" .. key, stringify(value))
end

local function load_policy_module()
    if policy_module ~= nil then
        return policy_module
    end

    local ok, mod = pcall(require, "nauthilus_policy")
    if not ok then
        error("nauthilus_policy emitter is not available: " .. tostring(mod))
    end

    policy_module = mod
    return policy_module
end

local function attribute_id(namespace, key)
    return ATTRIBUTE_PREFIX .. namespace .. "." .. key
end

local function emit_attribute(namespace, key, value, details)
    load_policy_module().emit_attribute({
        id = attribute_id(namespace, key),
        value = value,
        details = details,
    })
end

local function collect_entries(namespace, values)
    if type(values) ~= "table" then
        return nil
    end

    local normalized_namespace = normalize_segment(namespace)
    local entries = {}

    for key, value in pairs(values) do
        table.insert(entries, {
            namespace = normalized_namespace,
            key = normalize_segment(key),
            value = value,
        })
    end

    return entries
end

local function store_entries(entries, public)
    if type(entries) ~= "table" then
        return
    end

    local facts = facts_table()

    for _, entry in ipairs(entries) do
        if type(facts[entry.namespace]) ~= "table" then
            facts[entry.namespace] = {}
        end

        facts[entry.namespace][entry.key] = entry.value

        if public then
            add_public_log(entry.namespace, entry.key, entry.value)
        end
    end

    nauthilus_context.context_set(CONTEXT_KEY, facts)
end

local function store_many(namespace, values, public, emit)
    local entries = collect_entries(namespace, values)
    if entries == nil then
        return
    end

    if emit then
        for _, entry in ipairs(entries) do
            emit_attribute(entry.namespace, entry.key, entry.value)
        end
    end

    store_entries(entries, public)
end

function M.set(namespace, key, value)
    store_many(namespace, { [key] = value }, false, false)

    return value
end

function M.set_public(namespace, key, value)
    return M.emit_public(namespace, key, value)
end

function M.emit(namespace, key, value, details)
    local normalized_namespace = normalize_segment(namespace)
    local normalized_key = normalize_segment(key)

    emit_attribute(normalized_namespace, normalized_key, value, details)
    store_entries({
        {
            namespace = normalized_namespace,
            key = normalized_key,
            value = value,
        }
    }, false)

    return value
end

function M.emit_public(namespace, key, value, details)
    local normalized_namespace = normalize_segment(namespace)
    local normalized_key = normalize_segment(key)

    emit_attribute(normalized_namespace, normalized_key, value, details)
    store_entries({
        {
            namespace = normalized_namespace,
            key = normalized_key,
            value = value,
        }
    }, true)

    return value
end

function M.set_public_log(namespace, key, value)
    add_public_log(normalize_segment(namespace), normalize_segment(key), value)

    return value
end

function M.set_many(namespace, values)
    store_many(namespace, values, false, false)
end

function M.set_many_public(namespace, values)
    return M.emit_many_public(namespace, values)
end

function M.emit_many(namespace, values)
    store_many(namespace, values, false, true)
end

function M.emit_many_public(namespace, values)
    store_many(namespace, values, true, true)
end

function M.status_message(namespace, message)
    if nauthilus_builtin ~= nil and nauthilus_builtin.status_message_set ~= nil then
        nauthilus_builtin.status_message_set(message)
    end

    return M.emit_public(namespace, "status_message", message)
end

return M
