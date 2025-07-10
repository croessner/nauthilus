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

local N = "neural_remove_features"

local nauthilus_util = require("nauthilus_util")

dynamic_loader("nauthilus_neural")
local nauthilus_neural = require("nauthilus_neural")

dynamic_loader("nauthilus_gll_json")
local json = require("json")

-- This function can be called manually via the REST API to remove features from the canonical list in Redis
-- Example: curl -X POST -H "Content-Type: application/json" -d '{"features": ["feature1", "feature2"]}' http://localhost:8080/api/v1/lua/neural_remove_features
function nauthilus_call_neural_network(request)
    local logs = {}
    logs.caller = N .. ".lua"
    logs.level = "info"
    logs.message = "Removing features from canonical list in Redis"

    -- Parse the request body to get the features to remove
    local features_to_remove = {}
    local request_body = request.body

    if request_body and request_body ~= "" then
        local parsed_body, err = json.decode(request_body)
        if err then
            logs.result = "error"
            logs.message = "Failed to parse request body: " .. tostring(err)
            nauthilus_util.print_result({ log_format = "json" }, logs)
            return
        end

        if parsed_body.features and type(parsed_body.features) == "table" then
            features_to_remove = parsed_body.features
        end
    end

    -- Check if features to remove were provided
    if #features_to_remove == 0 then
        logs.result = "error"
        logs.message = "No features to remove were provided"
        nauthilus_util.print_result({ log_format = "json" }, logs)
        return
    end

    -- Remove the features from Redis
    local success, err = nauthilus_neural.remove_features_from_redis(features_to_remove)
    
    if success then
        logs.result = "success"
        logs.message = "Successfully removed features from canonical list in Redis"
        logs.removed_features = features_to_remove
    else
        logs.result = "error"
        logs.message = "Failed to remove features from canonical list in Redis: " .. tostring(err)
    end

    nauthilus_util.print_result({ log_format = "json" }, logs)
    
    return
end
