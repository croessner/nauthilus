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

-- Skip localhost requests: the feature stage is not executed for local/empty
-- IPs (see isLocalOrEmptyIP in features.go), so the context keys it would set
-- are absent. Return early with OK to avoid nil-context assertions.
local function is_localhost(request)
    local ip = request.client_ip or ""

    return ip == "" or ip == "127.0.0.1" or ip == "::1"
end

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

-- Action stage: verify that both feature and filter stages wrote the expected context values.
function nauthilus_call_action(request)
    if is_localhost(request) then
        return nauthilus_builtin.ACTION_RESULT_OK
    end

    local label = N .. "/action"
    local marker = tostring(request.session or "")

    if marker == "" then
        error(label .. ": request.session is empty, cannot run chain test")
    end

    -- Verify feature stage values.
    assert_context("test_stage_feature", "feature", label)
    assert_context("test_marker_feature", marker, label)

    -- Verify filter stage values.
    assert_context("test_stage_filter", "filter", label)
    assert_context("test_marker_filter", marker, label)

    if request.debug then
        nauthilus_util.log_debug(request, {
            caller = label,
            message = "Full context chain verified successfully (feature -> filter -> action)",
            test_stage_feature = nauthilus_context.context_get("test_stage_feature"),
            test_marker_feature = nauthilus_context.context_get("test_marker_feature"),
            test_stage_filter = nauthilus_context.context_get("test_stage_filter"),
            test_marker_filter = nauthilus_context.context_get("test_marker_filter"),
            session = marker,
        })
    end

    return nauthilus_builtin.ACTION_RESULT_OK
end
