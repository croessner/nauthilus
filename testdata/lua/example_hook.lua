-- Example Lua hook for testing
-- This hook demonstrates HTTP request/response handling
--
-- Usage:
--   ./nauthilus/bin/nauthilus --test-lua testdata/lua/example_hook.lua \
--                             --test-callback hook \
--                             --test-mock testdata/lua/hook_test.json

local nauthilus_http_request = require("nauthilus_http_request")
local nauthilus_http_response = require("nauthilus_http_response")
local nauthilus_util = require("nauthilus_util")

function nauthilus_run_hook(request)
    local logging = request.logging
    local session = request.session

    -- Get HTTP request details
    local method = nauthilus_http_request.get_http_method()
    local path = nauthilus_http_request.get_http_path()

    -- Build simple response
    local html = [[
<!DOCTYPE html>
<html>
<head>
    <title>Test Hook</title>
</head>
<body>
    <h1>Hook Test Success</h1>
    <p>Method: ]] .. method .. [[</p>
    <p>Path: ]] .. path .. [[</p>
    <p>Session: ]] .. session .. [[</p>
</body>
</html>
]]

    -- Send HTML response
    nauthilus_http_response.set_http_response_header("Content-Type", "text/html; charset=utf-8")
    nauthilus_http_response.html(nauthilus_http_response.STATUS_OK, html)

    -- Log result
    if logging.log_level == "debug" or logging.log_level == "info" then
        local result = {
            level = "info",
            caller = "example_hook.lua",
            session = session,
            status = "success",
            message = "Hook executed successfully"
        }
        nauthilus_util.print_result(logging, result)
    end

    return nil
end
