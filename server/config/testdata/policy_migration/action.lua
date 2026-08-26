-- Frozen B001-C2 synchronous action used by production generation tests.
local response = require("nauthilus_http_response")

function nauthilus_call_action(_request)
    if _request.session ~= nil and _request.session ~= "" then
        response.add_http_response_header("X-Nauthilus-Policy-Action", "b001-c2")
    end

    return 0
end
