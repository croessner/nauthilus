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

local nauthilus_util = require("nauthilus_util")

local nauthilus_context = require("nauthilus_context")
local nauthilus_prometheus = require("nauthilus_prometheus")

function nauthilus_call_action(request)
    if request.no_auth or request.authenticated then
        return nauthilus_builtin.ACTION_RESULT_OK
    end

    local function fact(facts, namespace, key)
        if type(facts) ~= "table" or type(facts[namespace]) ~= "table" then
            return nil
        end

        return facts[namespace][key]
    end

    -- Get result table
    local rt = nauthilus_context.context_get("rt")
    if rt == nil then
        rt = {}
    end
    local policy_facts = nauthilus_context.context_get("policy_facts") or {}
    local rt_has_data = nauthilus_util.is_table(rt) and nauthilus_util.table_length(rt) > 0

    if rt_has_data then
        -- brute_force_haproxy
        if rt.brute_force_haproxy then
            nauthilus_prometheus.increment_counter(N .. "_count", { feature = "brute_force" })
        end

        -- environment_haproxy (not part of demo plugins)
        if rt.environment_haproxy then
            if request.feature and request.feature ~= "" then
                nauthilus_prometheus.increment_counter(N .. "_count", { feature = request.feature })
            else
                nauthilus_prometheus.increment_counter(N .. "_count", { feature = "unspec" })
            end
        end
    end

    -- environment_blocklist
    if (rt_has_data and rt.environment_blocklist) or fact(policy_facts, "blocklist", "matched") == true then
        nauthilus_prometheus.increment_counter(N .. "_count", { feature = "blocklist" })
    end

    -- subject_geoippolicyd
    if (rt_has_data and rt.subject_geoippolicyd) or fact(policy_facts, "geoip", "rejected") == true then
        nauthilus_prometheus.increment_counter(N .. "_count", { feature = "geoip" })
    end

    -- environment_failed_login_hotspot
    if (rt_has_data and rt.environment_failed_login_hotspot) or fact(policy_facts, "failed_login_hotspot", "triggered") == true then
        nauthilus_prometheus.increment_counter(N .. "_count", { feature = "failed_login_hotspot" })
    end

    if (rt_has_data and rt.subject_account_protection_mode) or fact(policy_facts, "account_protection", "active") == true then
        nauthilus_prometheus.increment_counter(N .. "_count", { feature = "account_protection" })
    end

    rt.post_analytics = true
    nauthilus_context.context_set("rt", rt)

    return nauthilus_builtin.ACTION_RESULT_OK
end
