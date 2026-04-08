local nauthilus_context = require("nauthilus_context")

dofile("server/lua-plugins.d/actions/test_context_chain.lua")

local original = nauthilus_call_action

function nauthilus_call_action(request)
    request.no_auth = true
    request.authenticated = true
    request.protocol = "oidc"
    request.service = "idp"
    request.method = "client_secret_post"
    request.grant_type = "client_credentials"
    request.feature = ""
    request.feature_rejected = false
    request.feature_stage_expected = false
    request.filter_stage_expected = false
    request.status_message = "OIDC token issued"

    return original(request)
end
