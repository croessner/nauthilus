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
-- IPs (see isLocalOrEmptyIP in features.go). Downstream stages (filter/action)
-- must also skip to avoid nil-context assertions.
local function is_localhost(request)
    local ip = request.client_ip or ""

    return ip == "" or ip == "127.0.0.1" or ip == "::1"
end

-- Feature stage: set two context values for downstream stages to verify.
function nauthilus_call_feature(request)
    if is_localhost(request) then
        return nauthilus_builtin.FEATURE_TRIGGER_NO, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_YES
    end

    local marker = tostring(request.session or "")

    if marker == "" then
        error(N .. "/feature: request.session is empty, cannot run chain test")
    end

    nauthilus_context.context_set("test_stage_feature", "feature")
    nauthilus_context.context_set("test_marker_feature", marker)

    if request.debug then
        nauthilus_util.log_debug(request, {
            caller = N .. "/feature",
            message = "Context values set successfully",
            test_stage_feature = "feature",
            test_marker_feature = marker,
            session = marker,
        })
    end

    return nauthilus_builtin.FEATURE_TRIGGER_NO, nauthilus_builtin.FEATURES_ABORT_NO, nauthilus_builtin.FEATURE_RESULT_YES
end
