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

-- Action: Set an HTTP response header when a brute‑force protection has been triggered.
-- Purpose: The new load-test client can tolerate rejections if this header is present.
--
-- Usage:
--   - Place this file in server/lua-plugins.d/actions/
--   - Enable it in your actions chain after the brute_force logic.
--   - The header name can be overridden via env BRUTEFORCE_HEADER_NAME (default: "X-Nauthilus-Bruteforce").
--   - Additional header with the bucket name will be set if available:
--       X-Nauthilus-Bruteforce-Bucket: <bucket>

local nauthilus_util = require("nauthilus_util")

local nauthilus_context = require("nauthilus_context")
local nauthilus_http_response = require("nauthilus_http_response")

local HEADER_NAME = nauthilus_util.getenv("BRUTEFORCE_HEADER_NAME", "X-Nauthilus-Bruteforce")
local HEADER_BUCKET = "X-Nauthilus-Bruteforce-Bucket"

function nauthilus_call_action(request)
    -- Detect if brute-force logic has been applied
    local is_bruteforce = false

    -- 1) Explicit flag set by other actions (e.g., actions/bruteforce.lua)
    local rt = nauthilus_context.context_get("rt")
    if nauthilus_util.is_table(rt) and rt.brute_force_haproxy then
        is_bruteforce = true
    end

    -- 2) Presence of brute-force classification/counter in request fields
    if (request.brute_force_bucket ~= nil and request.brute_force_bucket ~= "") then
        is_bruteforce = true
    elseif (request.brute_force_counter ~= nil) then
        -- Treat numeric or string values > 0 as a sign of brute-force triggering
        local n = tonumber(request.brute_force_counter)
        if n ~= nil and n > 0 then
            is_bruteforce = true
        end
    end

    -- If brute-force was detected, annotate the HTTP response headers
    if is_bruteforce then
        nauthilus_http_response.set_http_response_header(HEADER_NAME, "true")

        if request.brute_force_bucket ~= nil and request.brute_force_bucket ~= "" then
            nauthilus_http_response.set_http_response_header(HEADER_BUCKET, tostring(request.brute_force_bucket))
        end
    end

    return nauthilus_builtin.ACTION_RESULT_OK
end
