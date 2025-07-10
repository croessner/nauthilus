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

local N = "learning-mode"

function nauthilus_run_hook(logging, session)
    local result = {}

    result.level = "info"
    result.caller = N .. ".lua"
    result.ts = nauthilus_util.get_current_timestamp()
    result.session = session

    -- Get query parameter for enabled
    local enabled_param = nauthilus_http_request.get_http_query_param("enabled")

    -- Default to current state if not specified
    local enabled
    local is_learning, error_message

    if enabled_param and enabled_param ~= "" then
        if enabled_param == "true" or enabled_param == "1" then
            enabled = true
        elseif enabled_param == "false" or enabled_param == "0" then
            enabled = false
        else
            result.level = "error"
            result.error = "Invalid enabled parameter: must be 'true', 'false', '1', or '0'"
            nauthilus_util.print_result(logging, result)

            return result
        end

        -- Call the set_learning_mode function to change the mode
        is_learning, error_message = nauthilus_neural.set_learning_mode(enabled)
    else
        -- No parameter provided, get the current learning mode
        is_learning = nauthilus_neural.get_learning_mode()
        result.status = "success"
        result.message = "Retrieved current learning mode"
    end

    if enabled_param and enabled_param ~= "" then
        if error_message then
            result.level = "error"
            result.status = "error"
            result.message = "Failed to set learning mode"
            result.error = error_message
            result.learning_mode = is_learning
        else
            result.status = "success"
            result.message = "Learning mode set successfully"
            result.learning_mode = is_learning
        end
    else
        -- We already set status and message for the query case
        result.learning_mode = is_learning
    end

    if logging.log_level == "debug" or logging.log_level == "info" then
        nauthilus_util.print_result(logging, result)
    end

    return result
end
