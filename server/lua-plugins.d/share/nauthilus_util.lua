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

dynamic_loader("nauthilus_gll_time")
local time = require("time")

dynamic_loader("nauthilus_gll_json")
local json = require("json")

local nauthilus_util = {}

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
    ---@type string currentTime
    ---@type string err
    local currentTime, err = time.format(time.unix(), "2006-01-02T15:04:05 -07:00", "Europe/Berlin")
    if err then
        error(err)
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
        -- Do nothing on "redis: nil" messages
        if err ~= "redis: nil" then
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
