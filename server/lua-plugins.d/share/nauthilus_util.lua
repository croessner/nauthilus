-- Copyright (C) 2024 Christian Rößner
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

local time = require("time")
local json = require("json")
local nauthilus_cache = require("nauthilus_cache")

local nauthilus_util = {}

--- nauthilus_util.getenv returns the value of an environment variable, cached via nauthilus_cache.
---@param name string
---@param default string
---@return string
function nauthilus_util.getenv(name, default)
    local key = "env:" .. name
    local val = nauthilus_cache.cache_get(key)
    if val ~= nil then
        return val
    end

    val = os.getenv(name)
    if val == nil then
        val = default
    end

    nauthilus_cache.cache_set(key, val, 0)

    return val
end

--- nauthilus_util.exists_in_table iterates over a flat Lua table (list) and checks, if a string was found in the values.
---@param tbl table
---@param element string
---@return boolean
function nauthilus_util.exists_in_table(tbl, element)
    ---@param value string
    for _, value in pairs(tbl) do
        if value == element then
            return true
        end
    end

    return false
end

--- nauthilus_util.get_current_timestamp creates a timestamp string valid for logging purposes.
---@return string
function nauthilus_util.get_current_timestamp()
    ---@type string tz
    local tz = nauthilus_util.getenv("TZ", "UTC")

    ---@type string currentTime
    ---@type string err
    local currentTime, err = time.format(time.unix(), "2006-01-02T15:04:05 -07:00", tz)

    -- Fallback: if the configured time zone is unknown (e.g., tzdata missing), format in UTC instead of raising.
    if err then
        currentTime, err = time.format(time.unix(), "2006-01-02T15:04:05 -07:00", "UTC")
        -- As a last resort, avoid crashing: build a simple UTC timestamp via os.date
        if err then
            currentTime = os.date("!%Y-%m-%dT%H:%M:%S +00:00")
        end
    end

    return currentTime
end

--- nauthilus_util.table_length calculates the length of a Lua table.
---@param tbl table
---@return number
function nauthilus_util.table_length(tbl)
    local count = 0

    for _ in pairs(tbl) do
        count = count + 1
    end

    return count
end

--- nauthilus_util.raise_error checks if an error was set and calls the Lua error function to exit script execution.
---@param err string
---@return void
function nauthilus_util.if_error_raise(err)
    if err then
        -- Do nothing on "redis: nil" or "OK" messages
        if err ~= "redis: nil" and err ~= "OK" then
            error(err)
        end
    end
end

--- nauthilus_util.is_table returns true if the given parameter is of type table.
---@param object any
---@return boolean
function nauthilus_util.is_table(object)
    return type(object) == "table"
end

--- nauthilus_util.is_table returns true if the given parameter is of type string.
---@param object any
---@return boolean
function nauthilus_util.is_string(object)
    return type(object) == "string"
end

--- nauthilus_util.is_table returns true if the given parameter is of type number.
---@param object any
---@return boolean
function nauthilus_util.is_number(object)
    return type(object) == "number"
end

--- nauthilus_util.toboolean converts a boolean value into a string.
---@param str string
---@return boolean
function nauthilus_util.toboolean(str)
    local lower = string.lower(str)

    return not (lower == "false" or lower == "0" or lower == "")
end

--- nauthilus_util.generate_random_string is a helper function that creates a Nth-length random string.
---@param length number
---@return string
function nauthilus_util.generate_random_string(length)
    local res = ""
    local chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

    for _ = 1, length do
        local random_index = math.random(1, #chars)
        res = res .. string.sub(chars, random_index, random_index)
    end

    return res
end

--- nauthilus_util.is_routable_ip checks if an IP address is routable on the internet.
--- Returns true for routable IPs, false for non-routable IPs (private, reserved ranges).
---@param ip string
---@return boolean
function nauthilus_util.is_routable_ip(ip)
    -- Check if it's an IPv4 address
    local ipv4_pattern = "^(%d+)%.(%d+)%.(%d+)%.(%d+)$"
    local o1, o2, o3, o4 = ip:match(ipv4_pattern)

    if o1 and o2 and o3 and o4 then
        -- Convert to numbers
        o1, o2, o3, o4 = tonumber(o1), tonumber(o2), tonumber(o3), tonumber(o4)

        -- Check private IPv4 ranges
        -- 10.0.0.0/8
        if o1 == 10 then
            return false
        end

        -- 172.16.0.0/12
        if o1 == 172 and o2 >= 16 and o2 <= 31 then
            return false
        end

        -- 192.168.0.0/16
        if o1 == 192 and o2 == 168 then
            return false
        end

        -- 169.254.0.0/16 (Link-local)
        if o1 == 169 and o2 == 254 then
            return false
        end

        -- 127.0.0.0/8 (Loopback) - Special case, we check for 127.0.0.1 separately
        if o1 == 127 then
            return false
        end

        -- 0.0.0.0/8 (Current network)
        if o1 == 0 then
            return false
        end

        -- 100.64.0.0/10 (Shared address space for carrier-grade NAT)
        if o1 == 100 and o2 >= 64 and o2 <= 127 then
            return false
        end

        -- 192.0.0.0/24 (IETF Protocol Assignments)
        if o1 == 192 and o2 == 0 and o3 == 0 then
            return false
        end

        -- 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (Documentation)
        if (o1 == 192 and o2 == 0 and o3 == 2) or
           (o1 == 198 and o2 == 51 and o3 == 100) or
           (o1 == 203 and o2 == 0 and o3 == 113) then
            return false
        end

        -- 192.88.99.0/24 (IPv6 to IPv4 relay)
        if o1 == 192 and o2 == 88 and o3 == 99 then
            return false
        end

        -- 224.0.0.0/4 (Multicast)
        if o1 >= 224 and o1 <= 239 then
            return false
        end

        -- 240.0.0.0/4 (Reserved for future use)
        if o1 >= 240 and o1 <= 255 then
            return false
        end

        -- If we got here, it's a routable IPv4 address
        return true
    end

    -- Check if it's an IPv6 address
    -- Simple check for common non-routable IPv6 prefixes
    if ip:match("^[fF][cCdD]") or -- fc00::/7 (Unique local addresses)
       ip:match("^[fF][eE][8-9a-bA-B]") or -- fe80::/10 (Link-local addresses)
       ip:match("^::1$") or -- ::1 (Loopback)
       ip:match("^::$") then -- :: (Unspecified address)
        return false
    end

    -- If we got here and it contains colons, assume it's a routable IPv6 address
    if ip:find(":") then
        return true
    end

    -- If we can't determine, assume it's not routable
    return false
end

--- nauthilus_util.print_result is a helper function that creates a log line in different formats dependend on the logging object.
--- The result table is a set of key/value pairs to log. If the err_string is set, an additional error message and flag is added.
---@param logging table
---@param result table
---@param err_string string
---@return void
function nauthilus_util.print_result(logging, result, err_string)
    result.ts = nauthilus_util.get_current_timestamp()

    if err_string ~= nil and err_string ~= "" then
        result.level = "error"

        result.error = err_string
    end

    if logging.log_format == "json" then
        local result_json, err_jenc = json.encode(result)
        nauthilus_util.if_error_raise(err_jenc)

        print(result_json)
    else
        local output_str = {}

        for k, v in pairs(result) do
            if string.match(tostring(v), "%s") then
                v = '"' .. tostring(v) .. '"'
            end

            table.insert(output_str, k .. '=' .. tostring(v))
        end

        print(table.concat(output_str, " "))
    end
end

return nauthilus_util
