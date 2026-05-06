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
        caller = N .. "/environment",
        message = message,
        session = tostring(request.session or ""),
        username = tostring(request.username or ""),
        client_ip = tostring(request.client_ip or ""),
        authenticated = request.authenticated == true,
        no_auth = request.no_auth == true,
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
-- IPs (see isLocalOrEmptyIP in environment.go). Downstream stages (subject/action)
-- must also skip to avoid nil-context assertions.
local function is_localhost(request)
    local ip = request.client_ip or ""

    return ip == "" or ip == "127.0.0.1" or ip == "::1"
end

-- Environment source stage: set two context values for downstream stages to verify.
function nauthilus_call_environment(request)
    log_info(request, "Entering environment source stage")

    if is_localhost(request) then
        log_info(request, "Skipping environment source stage for localhost request")
        return nauthilus_builtin.ENVIRONMENT_TRIGGER_NO, nauthilus_builtin.ENVIRONMENT_ABORT_NO, nauthilus_builtin.ENVIRONMENT_RESULT_OK
    end

    local marker = tostring(request.session or "")

    if marker == "" then
        error(N .. "/environment: request.session is empty, cannot run chain test")
    end

    nauthilus_context.context_set("test_stage_environment", "environment")
    nauthilus_context.context_set("test_marker_environment", marker)

    log_info(request, "Environment context values set successfully", {
        test_stage_environment = "environment",
        test_marker_environment = marker,
    })

    return nauthilus_builtin.ENVIRONMENT_TRIGGER_NO, nauthilus_builtin.ENVIRONMENT_ABORT_NO, nauthilus_builtin.ENVIRONMENT_RESULT_OK
end
