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

-- Bridges native Go GeoIP runtime data into the legacy Lua rt.geoip_info shape.

local nauthilus_context = require("nauthilus_context")

local M = {}

local NATIVE_KEY = "plugin.environment.geoip"
local RT_KEY = "rt"
local LEGACY_ISO_CODES_KEY = "geoippolicyd_iso_codes_seen"
local SOURCE_NATIVE = "native_geoip"

local function is_table(value)
    return type(value) == "table"
end

local function trim(value)
    if type(value) ~= "string" then
        return ""
    end

    return value:match("^%s*(.-)%s*$") or ""
end

local function iso_code(value)
    local code = trim(value):upper()
    if code:match("^[A-Z][A-Z]$") then
        return code
    end

    return ""
end

local function non_empty_string(value)
    local text = trim(value)
    if text == "" then
        return ""
    end

    return text
end

local function number_or_nil(value)
    local number = tonumber(value)
    if number == nil or number < 0 then
        return nil
    end

    return math.floor(number)
end

local function first_iso(list)
    if not is_table(list) then
        return ""
    end

    for _, value in ipairs(list) do
        local code = iso_code(value)
        if code ~= "" then
            return code
        end
    end

    return ""
end

local function iso_list(country_code, existing)
    local result = {}
    local seen = {}

    local function add(value)
        local code = iso_code(value)
        if code ~= "" and not seen[code] then
            table.insert(result, code)
            seen[code] = true
        end
    end

    if is_table(existing) then
        for _, value in ipairs(existing) do
            add(value)
        end
    end

    add(country_code)

    return result
end

local function normalize_native(native)
    if not is_table(native) then
        return nil
    end

    local country_code = iso_code(native.country_iso)
    local asn_country_code = iso_code(native.asn_country_iso)
    local matched = native.matched == true
    local info = {
        source = SOURCE_NATIVE,
        matched = matched,
        native_matched = matched,
        native_country_iso = country_code,
        current_country_code = country_code,
        country_name = non_empty_string(native.country_name),
        city_name = non_empty_string(native.city_name),
        asn = number_or_nil(native.asn),
        asn_org = non_empty_string(native.asn_org),
        asn_prefix = non_empty_string(native.asn_prefix),
        asn_registry = non_empty_string(native.asn_registry),
        asn_country_iso = asn_country_code,
        asn_allocated = non_empty_string(native.asn_allocated),
        asn_status = non_empty_string(native.asn_status),
    }

    if matched then
        info.status = "matched"
    else
        info.status = "miss"
    end

    info.iso_codes_seen = iso_list(country_code, nil)

    return info
end

local function copy_native_fields(target, native)
    target.native_matched = native.native_matched
    target.native_country_iso = native.native_country_iso

    local field_names = {
        "country_name",
        "city_name",
        "asn",
        "asn_org",
        "asn_prefix",
        "asn_registry",
        "asn_country_iso",
        "asn_allocated",
        "asn_status",
    }

    for _, field in ipairs(field_names) do
        if native[field] ~= nil and native[field] ~= "" then
            target[field] = native[field]
        end
    end
end

local function merge_info(existing, native)
    local info = existing
    if not is_table(info) then
        info = {}
    end

    if info.source == nil or info.source == "" then
        info.source = native.source
    end

    if info.matched == nil then
        info.matched = native.matched
    end

    if info.current_country_code == nil or info.current_country_code == "" then
        info.current_country_code = native.current_country_code
    end

    if info.status == nil or info.status == "" then
        info.status = native.status
    end

    copy_native_fields(info, native)
    info.iso_codes_seen = iso_list(info.current_country_code, info.iso_codes_seen)

    return info
end

function M.native()
    return nauthilus_context.context_get(NATIVE_KEY)
end

function M.attach()
    local native = normalize_native(M.native())
    if native == nil then
        local rt_existing = nauthilus_context.context_get(RT_KEY)
        if is_table(rt_existing) and is_table(rt_existing.geoip_info) then
            return rt_existing.geoip_info
        end

        return {}
    end

    local rt = nauthilus_context.context_get(RT_KEY)
    if not is_table(rt) then
        rt = {}
    end

    rt.geoip_info = merge_info(rt.geoip_info, native)
    nauthilus_context.context_set(RT_KEY, rt)

    local existing_codes = nauthilus_context.context_get(LEGACY_ISO_CODES_KEY)
    local country_code = first_iso(existing_codes)
    if country_code == "" then
        nauthilus_context.context_set(LEGACY_ISO_CODES_KEY, rt.geoip_info.iso_codes_seen)
    end

    return rt.geoip_info
end

return M
