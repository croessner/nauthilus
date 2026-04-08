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

local function context_snapshot()
    return {
        test_stage_feature = nauthilus_context.context_get("test_stage_feature"),
        test_marker_feature = nauthilus_context.context_get("test_marker_feature"),
        test_stage_filter = nauthilus_context.context_get("test_stage_filter"),
        test_marker_filter = nauthilus_context.context_get("test_marker_filter"),
    }
end

local function log_info(request, message, extra)
    local fields = {
        caller = N .. "/action",
        message = message,
        session = tostring(request.session or ""),
        username = tostring(request.username or ""),
        client_ip = tostring(request.client_ip or ""),
        authenticated = request.authenticated == true,
        no_auth = request.no_auth == true,
        feature = tostring(request.feature or ""),
        status_message = tostring(request.status_message or ""),
    }

    local snapshot = context_snapshot()
    for key, value in pairs(snapshot) do
        fields[key] = value
    end

    if extra then
        for key, value in pairs(extra) do
            fields[key] = value
        end
    end

    nauthilus_util.log_info(request, fields)
end

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

local function should_skip_feature_assertions(request, marker)
    local feature_stage = nauthilus_context.context_get("test_stage_feature")
    local feature_marker = nauthilus_context.context_get("test_marker_feature")

    if feature_stage == nil and feature_marker == nil and request.no_auth == true then
        log_info(request, "Skipping feature context assertions because no-auth requests may bypass the feature stage", {
            expected_marker = marker,
        })

        return true
    end

    return false
end

local function should_skip_filter_assertions(request, marker)
    local feature_name = tostring(request.feature or "")
    if feature_name == "" then
        return false
    end

    local filter_stage = nauthilus_context.context_get("test_stage_filter")
    local filter_marker = nauthilus_context.context_get("test_marker_filter")

    if filter_stage == nil and filter_marker == nil then
        log_info(request, "Skipping filter context assertions because the request was already decided by a feature", {
            expected_marker = marker,
            feature_name = feature_name,
        })

        return true
    end

    return false
end

-- Action stage: verify that both feature and filter stages wrote the expected context values.
function nauthilus_call_action(request)
    log_info(request, "Entering action stage")

    if is_localhost(request) then
        log_info(request, "Skipping action stage for localhost request")
        return nauthilus_builtin.ACTION_RESULT_OK
    end

    local label = N .. "/action"
    local marker = tostring(request.session or "")

    if marker == "" then
        error(label .. ": request.session is empty, cannot run chain test")
    end

    -- Verify feature stage values.
    log_info(request, "Verifying feature context before action assertions", {
        expected_marker = marker,
    })
    if not should_skip_feature_assertions(request, marker) then
        assert_context("test_stage_feature", "feature", label)
        assert_context("test_marker_feature", marker, label)
    end

    if should_skip_filter_assertions(request, marker) then
        return nauthilus_builtin.ACTION_RESULT_OK
    end

    -- Verify filter stage values.
    log_info(request, "Verifying filter context before action assertions", {
        expected_marker = marker,
    })
    assert_context("test_stage_filter", "filter", label)
    assert_context("test_marker_filter", marker, label)

    log_info(request, "Full context chain verified successfully (feature -> filter -> action)", {
        expected_marker = marker,
    })

    return nauthilus_builtin.ACTION_RESULT_OK
end
