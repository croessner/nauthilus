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

local N = "analytics"

function nauthilus_call_action(request)
    if request.no_auth or request.authenticated then
        return nauthilus_builtin.ACTION_RESULT_OK
    end

    local nauthilus_util = require("nauthilus_util")

    dynamic_loader("nauthilus_context")
    local nauthilus_context = require("nauthilus_context")

    dynamic_loader("nauthilus_prometheus")
    local nauthilus_prometheus = require("nauthilus_prometheus")

    -- Get result table
    local rt = nauthilus_context.context_get("rt")
    if rt == nil then
        rt = {}
    end

    if nauthilus_util.is_table(rt) and nauthilus_util.table_length(rt) > 0 then
        nauthilus_prometheus.create_counter_vec(N .. "_count", "Count the criteria which caused rejection", {"feature"})

        -- brute_force_haproxy
        if rt.brute_force_haproxy then
            nauthilus_prometheus.increment_counter(N .. "_count", { feature = "brute_force" })
        end

        -- feature_haproxy (not part of demo plugins)
        if rt.feature_haproxy then
            send_message = true
            if request.feature and request.feature ~= "" then
                nauthilus_prometheus.increment_counter(N .. "_count", { feature = request.feature })
            else
                nauthilus_prometheus.increment_counter(N .. "_count", { feature = "unspec" })
            end
        end

        -- feature_blocklist
        if rt.feature_blocklist then
            nauthilus_prometheus.increment_counter(N .. "_count", { feature = "blocklist" })
        end

        -- filter_geoippolicyd
        if rt.filter_geoippolicyd then
            nauthilus_prometheus.increment_counter(N .. "_count", { feature = "geoip" })
        end
    end

    rt.post_analytics = true
    nauthilus_context.context_set("rt", rt)

    return nauthilus_builtin.ACTION_RESULT_OK
end