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

-- Resolves the Redis handle of the bundled plugins. CUSTOM_REDIS_POOL_NAME names a pool that init/init.lua registers;
-- without it the plugins use the server's own Redis.

local nauthilus_util = require("nauthilus_util")
local nauthilus_redis = require("nauthilus_redis")

local M = {}

M.DEFAULT = "default"

local POOL_NAME = nauthilus_util.getenv("CUSTOM_REDIS_POOL_NAME", M.DEFAULT)

--- name returns the configured pool name.
---@return string
function M.name()
    return POOL_NAME
end

--- is_custom reports whether CUSTOM_REDIS_POOL_NAME selects a pool other than the server's own Redis.
---@return boolean
function M.is_custom()
    return POOL_NAME ~= M.DEFAULT
end

--- connection returns the first argument for nauthilus_redis calls: the literal "default", for which the server
--- picks its read or write handle per call, or the connection of the custom pool. The custom pool name itself is no
--- valid argument; the server would silently use its default handle instead.
---@return any
function M.connection()
    if not M.is_custom() then
        return M.DEFAULT
    end

    local conn, err = nauthilus_redis.get_redis_connection(POOL_NAME)
    nauthilus_util.if_error_raise(err)

    return conn
end

return M
