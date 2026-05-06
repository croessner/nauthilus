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
        test_stage_environment = nauthilus_context.context_get("test_stage_environment"),
        test_marker_environment = nauthilus_context.context_get("test_marker_environment"),
        test_stage_subject = nauthilus_context.context_get("test_stage_subject"),
        test_marker_subject = nauthilus_context.context_get("test_marker_subject"),
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
        environment_rejected = request.environment_rejected == true,
        environment_stage_expected = request.environment_stage_expected ~= false,
        subject_stage_expected = request.subject_stage_expected ~= false,
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

-- Skip localhost requests: the environment source stage is not executed for local/empty
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

local function should_skip_environment_assertions(request, marker)
    local environment_stage = nauthilus_context.context_get("test_stage_environment")
    local environment_marker = nauthilus_context.context_get("test_marker_environment")

    if request.environment_stage_expected == false then
        log_info(request, "Skipping environment context assertions because this request path does not include the Lua environment source stage", {
            expected_marker = marker,
        })

        return true
    end

    if environment_stage == nil and environment_marker == nil and request.no_auth == true then
        log_info(request, "Skipping environment context assertions because no-auth requests may bypass the environment source stage", {
            expected_marker = marker,
        })

        return true
    end

    if environment_stage == nil and environment_marker == nil and request.environment_rejected == true then
        log_info(request, "Skipping environment context assertions because the request was rejected before the Lua environment source stage ran", {
            expected_marker = marker,
        })

        return true
    end

    return false
end

local function should_skip_subject_assertions(request, marker)
    local subject_stage = nauthilus_context.context_get("test_stage_subject")
    local subject_marker = nauthilus_context.context_get("test_marker_subject")

    if request.subject_stage_expected == false and subject_stage == nil and subject_marker == nil then
        log_info(request, "Skipping subject context assertions because this request path does not include the subject analysis stage", {
            expected_marker = marker,
        })

        return true
    end

    if request.environment_rejected ~= true then
        return false
    end

    if subject_stage == nil and subject_marker == nil then
        log_info(request, "Skipping subject context assertions because an environment source rejected the request before subject analysis ran", {
            expected_marker = marker,
        })

        return true
    end

    return false
end

-- Action stage: verify that both environment and subject stages wrote the expected context values.
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

    -- Verify environment source stage values.
    log_info(request, "Verifying environment context before action assertions", {
        expected_marker = marker,
    })
    if not should_skip_environment_assertions(request, marker) then
        assert_context("test_stage_environment", "environment", label)
        assert_context("test_marker_environment", marker, label)
    end

    if should_skip_subject_assertions(request, marker) then
        return nauthilus_builtin.ACTION_RESULT_OK
    end

    -- Verify subject stage values.
    log_info(request, "Verifying subject context before action assertions", {
        expected_marker = marker,
    })
    assert_context("test_stage_subject", "subject", label)
    assert_context("test_marker_subject", marker, label)

    log_info(request, "Full context chain verified successfully (environment -> subject -> action)", {
        expected_marker = marker,
    })

    return nauthilus_builtin.ACTION_RESULT_OK
end
