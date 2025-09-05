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

-- http-head-get-demo.lua
--
-- A minimal demo hook to respond to GET and HEAD requests on the same endpoint.
-- - GET: returns a small text/plain body
-- - HEAD: returns the same headers (including Content-Length) but no body
--
-- Configure the same http_location twice in nauthilus.yml (once for GET, once for HEAD),
-- both pointing to this script, to test both methods on the same path.

local nauthilus_util = require("nauthilus_util")

dynamic_loader("nauthilus_http_request")
local nauthilus_http_request = require("nauthilus_http_request")

dynamic_loader("nauthilus_http_response")
local nauthilus_http_response = require("nauthilus_http_response")

local N = "http-head-get-demo"

local function rfc1123_now()
    return os.date("!%a, %d %b %Y %H:%M:%S GMT")
end

function nauthilus_run_hook(logging, session)
    local result = {
        level = "info",
        caller = N .. ".lua",
        session = session,
    }

    local method = nauthilus_http_request.get_http_method()
    local path = nauthilus_http_request.get_http_path()

    -- Demo content for GET
    local body = "Demo GET response from Nauthilus Lua hook\n"
    local content_length = tostring(#body)

    -- Common headers for both HEAD and GET
    nauthilus_http_response.set_http_response_header("Content-Type", "text/plain; charset=utf-8")
    nauthilus_http_response.set_http_response_header("Cache-Control", "no-cache, no-transform")
    nauthilus_http_response.set_http_response_header("ETag", "W/\"static-" .. content_length .. "\"")
    nauthilus_http_response.set_http_response_header("Last-Modified", rfc1123_now())

    if method == "HEAD" then
        -- HEAD: status + headers, but no body
        nauthilus_http_response.set_http_status(200)
        nauthilus_http_response.set_http_response_header("Content-Length", content_length)

        result.status = "success"
        result.message = "HEAD response sent (no body)"

        if logging.log_level == "debug" or logging.log_level == "info" then
            nauthilus_util.print_result(logging, result)
        end

        return nil
    elseif method == "GET" then
        -- GET: status + headers + body
        nauthilus_http_response.set_http_status(200)
        nauthilus_http_response.write_http_response_body(body)

        result.status = "success"
        result.message = "GET response sent"
        result.path = path

        if logging.log_level == "debug" or logging.log_level == "info" then
            nauthilus_util.print_result(logging, result)
        end

        return nil
    else
        -- For other methods, return 405 and Allow header
        nauthilus_http_response.set_http_status(405)
        nauthilus_http_response.set_http_response_header("Allow", "GET, HEAD")
        nauthilus_http_response.write_http_response_body("Method Not Allowed\n")

        result.status = "error"
        result.message = "Unsupported method"
        result.method = method

        if logging.log_level == "debug" or logging.log_level == "info" then
            nauthilus_util.print_result(logging, result)
        end

        return nil
    end
end
