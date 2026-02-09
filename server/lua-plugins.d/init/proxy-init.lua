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

-- proxy-init.lua
-- Configuration bootstrap for the proxy backend. Load it via
-- lua.config.init_script_path(s) to avoid modifying the default init.lua.

local nauthilus_prometheus = require("nauthilus_prometheus")
local nauthilus_psnet = require("nauthilus_psnet")

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

local function parse_endpoint(base_url)
    if base_url == nil then
        return ""
    end
    local trimmed = tostring(base_url)
    trimmed = trimmed:gsub("^https?://", "")
    trimmed = trimmed:gsub("/.*$", "")
    return trimmed
end

local function init_proxy_backend_config()
    local config = {
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

    rawset(_G, "nauthilus_proxy_backend", config)

    local endpoint = parse_endpoint(config.base_url)
    if endpoint ~= "" then
        nauthilus_psnet.register_connection_target(endpoint, "remote", "proxy_backend")
    end

    nauthilus_prometheus.create_gauge_vec(
        "proxy_backend_http_concurrent_requests_total",
        "Measure the number of concurrent proxy-backend HTTP requests",
        { "endpoint" }
    )
    nauthilus_prometheus.create_histogram_vec(
        "proxy_backend_http_duration_seconds",
        "Duration of proxy-backend HTTP requests",
        { "method", "endpoint" }
    )
    nauthilus_prometheus.create_counter_vec(
        "proxy_backend_http_errors_total",
        "Count proxy-backend HTTP errors",
        { "endpoint", "reason" }
    )
end

init_proxy_backend_config()
