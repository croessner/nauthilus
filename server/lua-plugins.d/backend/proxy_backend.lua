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

-- proxy_backend.lua
-- Implements a full Lua proxy backend that forwards all backend operations
-- to an upstream Nauthilus instance via HTTP, including WebAuthn CRUD calls.

local nauthilus_util = require("nauthilus_util")
local http = require("glua_http")
local json = require("json")
local nauthilus_prometheus = require("nauthilus_prometheus")
local nauthilus_otel = require("nauthilus_opentelemetry")

local METRIC_CONCURRENCY = "proxy_backend_http_concurrent_requests_total"
local METRIC_DURATION = "proxy_backend_http_duration_seconds"
local METRIC_ERRORS = "proxy_backend_http_errors_total"

local function getenv_cached(key, fallback)
    local cache = rawget(_G, "__proxy_backend_env_cache")
    if cache == nil then
        cache = {}
        rawset(_G, "__proxy_backend_env_cache", cache)
    end

    if cache[key] == nil then
        local value = os.getenv(key)
        if value == nil or value == "" then
            value = fallback
        end
        cache[key] = value
    end

    return cache[key]
end

local function load_config()
    local config = rawget(_G, "nauthilus_proxy_backend")
    if nauthilus_util.is_table(config) then
        return config
    end

    return {
        base_url = getenv_cached("PROXY_BACKEND_UPSTREAM_URL", "http://127.0.0.1:9080"),
        auth_path = getenv_cached("PROXY_BACKEND_AUTH_PATH", "/api/v1/auth/json"),
        mfa_path = getenv_cached("PROXY_BACKEND_MFA_PATH", "/api/v1/mfa-backchannel"),
        timeout = getenv_cached("PROXY_BACKEND_TIMEOUT", "5s"),
        list_accounts_username = getenv_cached("PROXY_BACKEND_LIST_ACCOUNTS_USERNAME", "list-accounts"),
        backend = getenv_cached("PROXY_BACKEND_TYPE", "lua"),
        backend_name = getenv_cached("PROXY_BACKEND_NAME", "default"),
        auth_token = getenv_cached("PROXY_BACKEND_AUTH_TOKEN", ""),
        basic_user = getenv_cached("PROXY_BACKEND_BASIC_USER", ""),
        basic_pass = getenv_cached("PROXY_BACKEND_BASIC_PASS", ""),
        headers = {},
    }
end

local function build_headers(config, base_headers)
    local headers = {}
    for k, v in pairs(base_headers or {}) do
        headers[k] = v
    end
    if nauthilus_util.is_table(config.headers) then
        for k, v in pairs(config.headers) do
            headers[k] = v
        end
    end
    if config.auth_token ~= nil and config.auth_token ~= "" then
        headers["Authorization"] = "Bearer " .. config.auth_token
    end

    return headers
end

local function build_auth_option(config)
    if config.basic_user ~= nil and config.basic_user ~= "" then
        return {
            user = config.basic_user,
            pass = config.basic_pass or "",
        }
    end

    return nil
end

local function with_span(name, attrs, fn)
    if nauthilus_otel ~= nil and nauthilus_otel.is_enabled and nauthilus_otel.is_enabled() then
        local tracer = nauthilus_otel.tracer("nauthilus/proxy-backend")

        return tracer:with_span(name, function(span)
            if attrs ~= nil then
                span:set_attributes(attrs)
            end
            return fn(span)
        end, { kind = "client" })
    end

    return fn(nil)
end

local function start_timer(method, endpoint)
    if nauthilus_prometheus ~= nil and nauthilus_prometheus.start_histogram_timer then
        return nauthilus_prometheus.start_histogram_timer(METRIC_DURATION, { method = method, endpoint = endpoint })
    end

    return nil
end

local function stop_timer(timer)
    if timer ~= nil and nauthilus_prometheus ~= nil and nauthilus_prometheus.stop_timer then
        nauthilus_prometheus.stop_timer(timer)
    end
end

local function increment_concurrency(endpoint)
    if nauthilus_prometheus ~= nil and nauthilus_prometheus.increment_gauge then
        nauthilus_prometheus.increment_gauge(METRIC_CONCURRENCY, { endpoint = endpoint })
    end
end

local function decrement_concurrency(endpoint)
    if nauthilus_prometheus ~= nil and nauthilus_prometheus.decrement_gauge then
        nauthilus_prometheus.decrement_gauge(METRIC_CONCURRENCY, { endpoint = endpoint })
    end
end

local function record_error(endpoint, reason)
    if nauthilus_prometheus ~= nil and nauthilus_prometheus.increment_counter then
        nauthilus_prometheus.increment_counter(METRIC_ERRORS, { endpoint = endpoint, reason = reason })
    end
end

local function do_request(method, url, options, endpoint_label)
    local timer = start_timer(method, endpoint_label)
    increment_concurrency(endpoint_label)

    local response, err = http.request(method, url, options)

    stop_timer(timer)
    decrement_concurrency(endpoint_label)

    if err ~= nil then
        record_error(endpoint_label, "request_error")
        return nil, err
    end

    if response.status_code < 200 or response.status_code >= 300 then
        record_error(endpoint_label, "status_" .. tostring(response.status_code))
        return nil, "unexpected_status=" .. tostring(response.status_code)
    end

    return response, nil
end

local function add_if_set(payload, key, value)
    if value ~= nil and value ~= "" then
        payload[key] = value
    end
end

local function build_auth_payload(request)
    local payload = {}
    add_if_set(payload, "username", request.username)
    add_if_set(payload, "password", request.password)
    add_if_set(payload, "client_ip", request.client_ip)
    add_if_set(payload, "client_port", request.client_port)
    add_if_set(payload, "client_hostname", request.client_hostname)
    add_if_set(payload, "client_id", request.client_id)
    add_if_set(payload, "user_agent", request.user_agent)
    add_if_set(payload, "local_ip", request.local_ip)
    add_if_set(payload, "local_port", request.local_port)
    add_if_set(payload, "protocol", request.protocol)
    add_if_set(payload, "method", request.method)
    add_if_set(payload, "ssl", request.ssl)
    add_if_set(payload, "ssl_session_id", request.ssl_session_id)
    add_if_set(payload, "ssl_client_verify", request.ssl_client_verify)
    add_if_set(payload, "ssl_client_dn", request.ssl_client_dn)
    add_if_set(payload, "ssl_client_cn", request.ssl_client_cn)
    add_if_set(payload, "ssl_issuer", request.ssl_issuer)
    add_if_set(payload, "ssl_client_notbefore", request.ssl_client_notbefore)
    add_if_set(payload, "ssl_client_notafter", request.ssl_client_notafter)
    add_if_set(payload, "ssl_subject_dn", request.ssl_subject_dn)
    add_if_set(payload, "ssl_issuer_dn", request.ssl_issuer_dn)
    add_if_set(payload, "ssl_client_subject_dn", request.ssl_client_subject_dn)
    add_if_set(payload, "ssl_client_issuer_dn", request.ssl_client_issuer_dn)
    add_if_set(payload, "ssl_protocol", request.ssl_protocol)
    add_if_set(payload, "ssl_cipher", request.ssl_cipher)
    add_if_set(payload, "ssl_serial", request.ssl_serial)
    add_if_set(payload, "ssl_fingerprint", request.ssl_fingerprint)
    add_if_set(payload, "oidc_cid", request.oidc_cid)
    add_if_set(payload, "auth_login_attempt", request.auth_login_attempt)

    return payload
end

local function build_mfa_payload(request, config)
    return {
        username = request.username,
        backend = config.backend,
        backend_name = config.backend_name,
    }
end

local function decode_json(body)
    if body == nil or body == "" then
        return nil, "empty_body"
    end

    local value, err = json.decode(body)
    if err ~= nil then
        return nil, err
    end

    return value, nil
end

local function request_json(method, url, payload, endpoint_label, accept)
    local config = load_config()
    local headers = build_headers(config, {
        ["Content-Type"] = "application/json",
        ["Accept"] = accept or "application/json",
    })

    local options = {
        timeout = config.timeout,
        headers = headers,
        body = json.encode(payload),
    }

    local auth = build_auth_option(config)
    if auth ~= nil then
        options.auth = auth
    end

    return do_request(method, url, options, endpoint_label)
end

local function request_no_body(method, url, endpoint_label)
    local config = load_config()
    local headers = build_headers(config, {
        ["Accept"] = "application/json",
    })

    local options = {
        timeout = config.timeout,
        headers = headers,
    }

    local auth = build_auth_option(config)
    if auth ~= nil then
        options.auth = auth
    end

    return do_request(method, url, options, endpoint_label)
end

function nauthilus_backend_verify_password(request)
    local b = nauthilus_backend_result.new()
    local config = load_config()
    local url = config.base_url .. config.auth_path

    local payload = build_auth_payload(request)

    local response, err = with_span("proxy_backend.verify_password", nauthilus_otel.semconv.http_client_attrs({
        method = "POST",
        url = url,
    }), function()
        return request_json("POST", url, payload, "auth.verify")
    end)

    if err ~= nil then
        b:user_found(false)
        b:authenticated(false)
        b:attributes({ error = tostring(err) })
        return nauthilus_builtin.BACKEND_RESULT_ERROR, b
    end

    local decoded, decode_err = decode_json(response.body)
    if decode_err ~= nil then
        b:user_found(false)
        b:authenticated(false)
        b:attributes({ error = tostring(decode_err) })
        return nauthilus_builtin.BACKEND_RESULT_ERROR, b
    end

    if decoded.ok == true then
        b:user_found(true)
        b:authenticated(true)
        if decoded.account_field ~= nil and decoded.account_field ~= "" then
            b:account_field(decoded.account_field)
        end
        if decoded.totp_secret_field ~= nil and decoded.totp_secret_field ~= "" then
            b:totp_secret_field(decoded.totp_secret_field)
        end
        if nauthilus_util.is_table(decoded.attributes) then
            b:attributes(decoded.attributes)
        end
    else
        b:user_found(false)
        b:authenticated(false)
        if nauthilus_util.is_table(decoded.attributes) then
            b:attributes(decoded.attributes)
        end
    end

    return nauthilus_builtin.BACKEND_RESULT_OK, b
end

function nauthilus_backend_list_accounts()
    local config = load_config()
    local url = config.base_url .. config.auth_path .. "?mode=list-accounts"
    local payload = { username = config.list_accounts_username }

    local response, err = with_span("proxy_backend.list_accounts", nauthilus_otel.semconv.http_client_attrs({
        method = "POST",
        url = url,
    }), function()
        return request_json("POST", url, payload, "auth.list-accounts", "application/json")
    end)

    if err ~= nil then
        return nauthilus_builtin.BACKEND_RESULT_ERROR, {}
    end

    local decoded, decode_err = decode_json(response.body)
    if decode_err ~= nil then
        return nauthilus_builtin.BACKEND_RESULT_ERROR, {}
    end

    if not nauthilus_util.is_table(decoded) then
        return nauthilus_builtin.BACKEND_RESULT_ERROR, {}
    end

    return nauthilus_builtin.BACKEND_RESULT_OK, decoded
end

function nauthilus_backend_add_totp(request)
    local config = load_config()
    local payload = build_mfa_payload(request, config)
    payload.totp_secret = request.totp_secret

    local url = config.base_url .. config.mfa_path .. "/totp"
    local _, err = request_json("POST", url, payload, "mfa.add-totp")
    if err ~= nil then
        return nauthilus_builtin.BACKEND_RESULT_ERROR
    end

    return nauthilus_builtin.BACKEND_RESULT_OK
end

function nauthilus_backend_delete_totp(request)
    local config = load_config()
    local payload = build_mfa_payload(request, config)
    local url = config.base_url .. config.mfa_path .. "/totp"

    local _, err = request_json("DELETE", url, payload, "mfa.delete-totp")
    if err ~= nil then
        return nauthilus_builtin.BACKEND_RESULT_ERROR
    end

    return nauthilus_builtin.BACKEND_RESULT_OK
end

function nauthilus_backend_add_totp_recovery_codes(request)
    local config = load_config()
    local payload = build_mfa_payload(request, config)
    payload.codes = request.totp_recovery_codes or {}

    local url = config.base_url .. config.mfa_path .. "/totp/recovery-codes"
    local _, err = request_json("POST", url, payload, "mfa.add-recovery")
    if err ~= nil then
        return nauthilus_builtin.BACKEND_RESULT_ERROR
    end

    return nauthilus_builtin.BACKEND_RESULT_OK
end

function nauthilus_backend_delete_totp_recovery_codes(request)
    local config = load_config()
    local payload = build_mfa_payload(request, config)
    local url = config.base_url .. config.mfa_path .. "/totp/recovery-codes"

    local _, err = request_json("DELETE", url, payload, "mfa.delete-recovery")
    if err ~= nil then
        return nauthilus_builtin.BACKEND_RESULT_ERROR
    end

    return nauthilus_builtin.BACKEND_RESULT_OK
end

function nauthilus_backend_get_webauthn_credentials(request)
    local config = load_config()
    local url = config.base_url .. config.mfa_path .. "/webauthn/credential"
        .. "?username=" .. tostring(request.username)
        .. "&backend=" .. tostring(config.backend)
        .. "&backend_name=" .. tostring(config.backend_name)

    local response, err = request_no_body("GET", url, "mfa.get-webauthn")
    if err ~= nil then
        return nauthilus_builtin.BACKEND_RESULT_ERROR, {}
    end

    local decoded, decode_err = decode_json(response.body)
    if decode_err ~= nil or not nauthilus_util.is_table(decoded) then
        return nauthilus_builtin.BACKEND_RESULT_ERROR, {}
    end

    local credentials = decoded.credentials
    if not nauthilus_util.is_table(credentials) then
        return nauthilus_builtin.BACKEND_RESULT_OK, {}
    end

    return nauthilus_builtin.BACKEND_RESULT_OK, credentials
end

function nauthilus_backend_save_webauthn_credential(request)
    local config = load_config()
    local payload = build_mfa_payload(request, config)
    payload.credential = request.webauthn_credential

    local url = config.base_url .. config.mfa_path .. "/webauthn/credential"
    local _, err = request_json("POST", url, payload, "mfa.save-webauthn")
    if err ~= nil then
        return nauthilus_builtin.BACKEND_RESULT_ERROR
    end

    return nauthilus_builtin.BACKEND_RESULT_OK
end

function nauthilus_backend_delete_webauthn_credential(request)
    local config = load_config()
    local payload = build_mfa_payload(request, config)
    payload.credential = request.webauthn_credential

    local url = config.base_url .. config.mfa_path .. "/webauthn/credential"
    local _, err = request_json("DELETE", url, payload, "mfa.delete-webauthn")
    if err ~= nil then
        return nauthilus_builtin.BACKEND_RESULT_ERROR
    end

    return nauthilus_builtin.BACKEND_RESULT_OK
end

function nauthilus_backend_update_webauthn_credential(request)
    local config = load_config()
    local payload = build_mfa_payload(request, config)
    payload.credential = request.webauthn_credential
    payload.old_credential = request.webauthn_old_credential

    local url = config.base_url .. config.mfa_path .. "/webauthn/credential"
    local _, err = request_json("PUT", url, payload, "mfa.update-webauthn")
    if err ~= nil then
        return nauthilus_builtin.BACKEND_RESULT_ERROR
    end

    return nauthilus_builtin.BACKEND_RESULT_OK
end
