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

local nauthilus_util = require("nauthilus_util")

dynamic_loader("nauthilus_context")
local nauthilus_context = require("nauthilus_context")

dynamic_loader("nauthilus_gll_tcp")
local tcp = require("tcp")

function nauthilus_call_action(request)
    if not request.repeating then
        -- Send IP/Mask
        local conn, err = tcp.open(os.getenv('HAPROXY_STATS'))

        if request.protocol == "smtps" or request.protocol == "submission" then
            -- Use smtp-sink
            err = conn:write("add map " .. os.getenv('HAPROXY_SMTP_MAP') .. " " .. request.client_net .. " block_smtp\n")
        else
            -- Block connection
            err = conn:write("add map " .. os.getenv('HAPROXY_GENERIC_MAP') .. " " .. request.client_net .. " block_" .. request.protocol .. "\n")
        end

        nauthilus_util.if_error_raise(err)

        -- Get result table
        local rt = nauthilus_context.context_get("rt")
        if rt == nil then
            rt = {}
        end
        if nauthilus_util.is_table(rt) then
            rt.brute_force_haproxy = true

            nauthilus_context.context_set("rt", rt)
        end
    end

    return nauthilus_builtin.ACTION_RESULT_OK
end
