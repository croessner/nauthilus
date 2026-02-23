-- Copyright (C) 2025 Christian Rößner
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

local nauthilus_context = require("nauthilus_context")
local nauthilus_util = require("nauthilus_util")

local N = "test_context_chain"

-- Helper: assert that a context key holds the expected value.
local function assert_context(key, expected, stage_label)
    local value = nauthilus_context.context_get(key)

    if value == nil then
        error(stage_label .. ": context key '" .. key .. "' is nil (expected '" .. tostring(expected) .. "')")
    end

    if tostring(value) ~= tostring(expected) then
        error(stage_label .. ": context key '" .. key .. "' = '" .. tostring(value) .. "', expected '" .. tostring(expected) .. "'")
    end
end

-- Filter stage: verify feature context, then set filter context values.
function nauthilus_call_filter(request)
    local label = N .. "/filter"
    local marker = tostring(request.session or "")

    if marker == "" then
        error(label .. ": request.session is empty, cannot run chain test")
    end

    -- Verify that the feature stage wrote the expected values.
    assert_context("test_stage_feature", "feature", label)
    assert_context("test_marker_feature", marker, label)

    -- Set filter-specific context values for the action stage.
    nauthilus_context.context_set("test_stage_filter", "filter")
    nauthilus_context.context_set("test_marker_filter", marker)

    if request.debug then
        nauthilus_util.log_debug(request, {
            caller = label,
            message = "Feature context verified, filter context values set successfully",
            test_stage_feature = nauthilus_context.context_get("test_stage_feature"),
            test_marker_feature = nauthilus_context.context_get("test_marker_feature"),
            test_stage_filter = "filter",
            test_marker_filter = marker,
            session = marker,
        })
    end

    return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
end
