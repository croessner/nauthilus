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

local N = "neural_reset"

local nauthilus_util = require("nauthilus_util")

dynamic_loader("nauthilus_neural")
local nauthilus_neural = require("nauthilus_neural")

-- This function can be called manually via the REST API to reset the neural network model
-- Example: curl -X POST http://localhost:8080/api/v1/lua/neural_reset
function nauthilus_call_neural_network(request)
    local logs = {}
    logs.caller = N .. ".lua"
    logs.ts = nauthilus_util.get_current_timestamp()
    logs.level = "info"
    logs.session = request.session
    logs.message = "Resetting neural network model to canonical features"

    -- Reset the neural network model
    local success, err = nauthilus_neural.reset_neural_network()
    
    if success then
        logs.result = "success"
        logs.message = "Successfully reset neural network model to canonical features"
    else
        logs.result = "error"
        logs.message = "Failed to reset neural network model: " .. tostring(err)
    end

    nauthilus_util.print_result({ log_format = "json" }, logs)
    
    return
end
