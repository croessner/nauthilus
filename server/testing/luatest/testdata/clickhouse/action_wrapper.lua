local source = debug.getinfo(1, "S").source
local script_path = source:sub(2)
local script_dir = script_path:match("(.*/)")
if script_dir:sub(1, 1) ~= "/" then
    script_dir = "/" .. script_dir
end

dofile(script_dir .. "../../../../lua-plugins.d/actions/clickhouse.lua")

local original = nauthilus_call_action

function nauthilus_call_action(request)
    request.method = "password"
    request.oidc_cid = "oidc-client-1"
    request.saml_entity_id = "https://sp.example.com/metadata"
    request.grant_type = "client_credentials"
    request.mfa_method = "webauthn"
    request.client_hostname = "host.example.com"
    request.status_message = "OK"
    request.latency = 12
    request.http_status = 200

    return original(request)
end
