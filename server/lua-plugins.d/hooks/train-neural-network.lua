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

local N = "train-neural-network"

function nauthilus_run_hook(logging, session)
    local result = {}

    result.level = "info"
    result.caller = N .. ".lua"
    result.session = session

    -- Get query parameters for epochs and maxSamples
    local epochs_param = nauthilus_http_request.get_http_query_param("epochs")
    local samples_param = nauthilus_http_request.get_http_query_param("samples")

    -- Convert parameters to numbers with default values
    local epochs = 50  -- Default value
    local maxSamples = 5000  -- Default value

    if epochs_param and epochs_param ~= "" then
        local epochs_num = tonumber(epochs_param)
        if epochs_num and epochs_num > 0 then
            epochs = epochs_num
        else
            result.level = "error"
            result.error = "Invalid epochs parameter: must be a positive number"
            nauthilus_util.print_result(logging, result)

            return
        end
    end

    if samples_param and samples_param ~= "" then
        local samples_num = tonumber(samples_param)
        if samples_num and samples_num > 0 then
            maxSamples = samples_num
        else
            result.level = "error"
            result.error = "Invalid samples parameter: must be a positive number"
            nauthilus_util.print_result(logging, result)

            return
        end
    end

    -- Call the train_neural_network function
    local success, error_message = nauthilus_neural.train_neural_network(maxSamples, epochs)

    if success then
        result.status = "success"
        result.message = "Neural network training completed successfully"
        result.epochs = epochs
        result.samples = maxSamples
    else
        result.level = "error"
        result.status = "error"
        result.message = "Neural network training failed"
        result.error = error_message
        result.epochs = epochs
        result.samples = maxSamples
    end

    if logging.log_level == "debug" or logging.log_level == "info" then
        nauthilus_util.print_result(logging, result)
    end

    return result
end