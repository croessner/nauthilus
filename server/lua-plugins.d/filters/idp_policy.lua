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

-- IdP Policy Filter Example
--
-- This filter demonstrates how to use the IdP-specific fields available in the
-- Lua request object to enforce access control policies for OIDC flows
-- (Authorization Code Grant, Device Code, Client Credentials).
--
-- Available IdP fields on the request object:
--   request.grant_type                 (string)  - OIDC grant type, e.g. "authorization_code",
--                                                  "urn:ietf:params:oauth:grant-type:device_code",
--                                                  "client_credentials"
--   request.oidc_cid                   (string)  - OIDC Client ID
--   request.oidc_client_name           (string)  - Human-readable OIDC client name
--   request.redirect_uri               (string)  - Requested redirect URI
--   request.mfa_completed              (bool)    - Whether MFA was successfully completed
--   request.mfa_method                 (string)  - MFA method used: "totp", "webauthn", "recovery"
--   request.requested_scopes           (table)   - OIDC scopes requested by the client
--   request.user_groups                (table)   - User's group memberships (e.g. from LDAP memberOf)
--   request.allowed_client_scopes      (table)   - Configured allowed scopes for the OIDC client
--   request.allowed_client_grant_types (table)   - Configured allowed grant types for the OIDC client
--
-- Additionally, the standard fields remain available:
--   request.authenticated, request.username, request.account, request.protocol,
--   request.client_ip, request.brute_force_bucket, etc.
--
-- Return values:
--   nauthilus_builtin.FILTER_ACCEPT  - Allow the request
--   nauthilus_builtin.FILTER_REJECT  - Deny the request
--   nauthilus_builtin.FILTER_RESULT_OK   - No error during filter execution
--   nauthilus_builtin.FILTER_RESULT_FAIL - Error during filter execution

local N = "idp_policy"

local nauthilus_util = require("nauthilus_util")

-- Helper: check if a user belongs to at least one of the given groups.
local function has_any_group(user_groups, required_groups)
    if not nauthilus_util.is_table(user_groups) then
        return false
    end

    for _, group in ipairs(required_groups) do
        if nauthilus_util.exists_in_table(user_groups, group) then
            return true
        end
    end

    return false
end

-- ============================================================================
-- Policy rules
-- ============================================================================

-- Rule 1: Require MFA for Device Code flow.
-- Device code flow is typically used on input-constrained devices (smart TVs, CLI tools).
-- Requiring MFA ensures that even if a user code is intercepted, the attacker cannot
-- complete the flow without the second factor.
local function require_mfa_for_device_code(request)
    if request.grant_type ~= "urn:ietf:params:oauth:grant-type:device_code" then
        return nil
    end

    if request.mfa_completed then
        return nil
    end

    return "Device code flow requires MFA"
end

-- Rule 2: Restrict offline_access scope to specific groups.
-- Refresh tokens (offline_access) are long-lived credentials. Limiting them to
-- trusted groups reduces the risk of token theft.
local function restrict_offline_access(request)
    if not nauthilus_util.exists_in_table(request.requested_scopes, "offline_access") then
        return nil
    end

    local allowed_groups = { "premium-users", "service-accounts" }

    if has_any_group(request.user_groups, allowed_groups) then
        return nil
    end

    return "Scope 'offline_access' requires membership in: " .. table.concat(allowed_groups, ", ")
end

-- Rule 3: Restrict specific OIDC clients to admin groups.
-- Sensitive applications (admin dashboards, infrastructure tools) should only be
-- accessible to users with appropriate group memberships.
local function restrict_admin_clients(request)
    local admin_clients = {
        ["admin-dashboard"] = { "admins", "sre-team" },
        ["infrastructure-portal"] = { "admins", "infrastructure" },
    }

    local required_groups = admin_clients[request.oidc_cid]

    if not required_groups then
        return nil
    end

    if has_any_group(request.user_groups, required_groups) then
        return nil
    end

    return "Client '" .. (request.oidc_client_name or request.oidc_cid) ..
        "' requires membership in: " .. table.concat(required_groups, ", ")
end

-- Rule 4: Enforce strong MFA for sensitive scopes.
-- When a client requests the "groups" scope (which exposes group memberships),
-- require that MFA was completed with a strong method (not recovery codes).
local function require_strong_mfa_for_groups_scope(request)
    if not nauthilus_util.exists_in_table(request.requested_scopes, "groups") then
        return nil
    end

    if not request.mfa_completed then
        return "Scope 'groups' requires MFA"
    end

    if request.mfa_method == "recovery" then
        return "Scope 'groups' requires strong MFA (TOTP or WebAuthn), not recovery codes"
    end

    return nil
end

-- Rule 5: Block specific redirect URIs for non-privileged users.
-- Prevent non-admin users from authorizing flows that redirect to internal/staging
-- environments, reducing the risk of token leakage to unintended targets.
local function restrict_internal_redirect_uris(request)
    local uri = request.redirect_uri or ""

    if uri == "" then
        return nil
    end

    -- Check if the redirect URI points to an internal or staging environment
    local is_internal = string.find(uri, "%.internal%.") ~= nil
        or string.find(uri, "%.staging%.") ~= nil
        or string.find(uri, "localhost") ~= nil

    if not is_internal then
        return nil
    end

    if has_any_group(request.user_groups, { "admins", "developers" }) then
        return nil
    end

    return "Redirect to internal/staging URIs requires 'admins' or 'developers' group"
end

-- ============================================================================
-- Main filter entry point
-- ============================================================================

function nauthilus_call_filter(request)
    -- Skip policy checks for non-authenticated or no-auth requests
    if request.no_auth then
        return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
    end

    -- Only apply IdP policies when an OIDC client is involved
    if not request.oidc_cid or request.oidc_cid == "" then
        return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
    end

    -- Evaluate all policy rules in order
    local rules = {
        require_mfa_for_device_code,
        restrict_offline_access,
        restrict_admin_clients,
        require_strong_mfa_for_groups_scope,
        restrict_internal_redirect_uris,
    }

    for _, rule in ipairs(rules) do
        local reason = rule(request)

        if reason then
            nauthilus_util.log_warn(request, {
                caller = N .. ".lua",
                message = "Policy rejected",
                reason = reason,
                username = request.username or "",
                account = request.account or "",
                client_ip = request.client_ip or "",
                oidc_cid = request.oidc_cid or "",
                oidc_client_name = request.oidc_client_name or "",
                grant_type = request.grant_type or "",
                mfa_completed = tostring(request.mfa_completed),
                mfa_method = request.mfa_method or "",
            })

            nauthilus_builtin.custom_log_add(N .. "_rejected_reason", reason)
            nauthilus_builtin.status_message_set("Access denied: " .. reason)

            return nauthilus_builtin.FILTER_REJECT, nauthilus_builtin.FILTER_RESULT_OK
        end
    end

    -- All policies passed
    nauthilus_util.log_info(request, {
        caller = N .. ".lua",
        message = "Policy accepted",
        username = request.username or "",
        oidc_cid = request.oidc_cid or "",
        grant_type = request.grant_type or "",
    })

    return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
end
