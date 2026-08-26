local nauthilus_context = require("nauthilus_context")

dofile("server/lua-plugins.d/subject/idp_policy.lua")

local original = nauthilus_call_subject

function nauthilus_call_subject(request)
    request.oidc_cid = "admin-dashboard"
    request.oidc_client_name = "Admin Dashboard"
    request.grant_type = "authorization_code"
    request.redirect_uri = "https://admin.example.test/callback"
    request.mfa_completed = true
    request.mfa_method = "webauthn"
    request.requested_scopes = { "openid" }
    request.user_groups = { "employees" }

    local action, result = original(request)
    local facts = nauthilus_context.context_get("policy_facts") or {}
    local idp = facts.idp_policy or {}

    if idp.rejected ~= true or idp.oidc_cid ~= "admin-dashboard" then
        error("IdP Policy source did not emit its request-local rejection facts")
    end

    return action, result
end
