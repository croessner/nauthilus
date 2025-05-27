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

dynamic_loader("nauthilus_http_request")
local nauthilus_http_request = require("nauthilus_http_request")

dynamic_loader("nauthilus_neural")
local nauthilus_neural = require("nauthilus_neural")

local N = "neural-feedback"

function nauthilus_run_hook(logging, session)
    local result = {}

    result.level = "info"
    result.caller = N .. ".lua"
    result.session = session

    -- Get query parameters
    local is_brute_force_param = nauthilus_http_request.get_http_query_param("is_brute_force")
    local request_id_param = nauthilus_http_request.get_http_query_param("request_id")
    local client_ip_param = nauthilus_http_request.get_http_query_param("client_ip")
    local username_param = nauthilus_http_request.get_http_query_param("username")

    -- Validate parameters
    if not request_id_param or request_id_param == "" then
        result.level = "error"
        result.error = "Missing required parameter: request_id"
        nauthilus_util.print_result(logging, result)
        return
    end

    if not client_ip_param or client_ip_param == "" then
        result.level = "error"
        result.error = "Missing required parameter: client_ip"
        nauthilus_util.print_result(logging, result)
        return
    end

    if not username_param or username_param == "" then
        result.level = "error"
        result.error = "Missing required parameter: username"
        nauthilus_util.print_result(logging, result)
        return
    end

    -- Convert is_brute_force parameter to boolean
    local is_brute_force = false
    if is_brute_force_param and is_brute_force_param ~= "" then
        is_brute_force = is_brute_force_param == "true" or is_brute_force_param == "1" or is_brute_force_param == "yes"
    end

    -- Call the provide_feedback function
    local success, error_message = nauthilus_neural.provide_feedback(is_brute_force, request_id_param, client_ip_param, username_param)

    if success then
        result.status = "success"
        result.message = "Feedback recorded successfully"
        result.is_brute_force = is_brute_force
        result.request_id = request_id_param
        result.client_ip = client_ip_param
        result.username = username_param
    else
        result.level = "error"
        result.status = "error"
        result.message = "Failed to record feedback"
        result.error = error_message
        result.is_brute_force = is_brute_force
        result.request_id = request_id_param
        result.client_ip = client_ip_param
        result.username = username_param
    end

    if logging.log_level == "debug" or logging.log_level == "info" then
        nauthilus_util.print_result(logging, result)
    end

    return result
end