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

-- ClickHouse Query Hook
--
-- Purpose: Provide a safe frontend-accessible hook to operate with data stored in ClickHouse.
-- Supports a small set of read-only operations with parameter constraints to avoid SQL injection.
--
-- Environment:
--   CLICKHOUSE_SELECT_BASE - Base URL of ClickHouse HTTP endpoint, e.g. http://clickhouse:8123
--   CLICKHOUSE_TABLE       - Table name, e.g. nauthilus.failed_logins
--   CLICKHOUSE_USER        - (optional) user for basic auth via headers
--   CLICKHOUSE_PASSWORD    - (optional) password for basic auth via headers
--
-- Supported actions (via query parameter `action`):
--   recent   - list recent rows; params: limit (default 100, max 1000)
--   by_user  - list recent rows for a specific username; params: username, limit (default 100, max 1000)
--   by_ip    - list recent rows for a client_ip; params: ip, limit (default 100, max 1000)

dynamic_loader("nauthilus_http_request")
local nauthilus_http_request = require("nauthilus_http_request")

dynamic_loader("nauthilus_gluahttp")
local http = require("glua_http")

local N = "clickhouse-query"

local function clamp(n, minv, maxv)
    n = tonumber(n or 0) or 0
    if n < minv then return minv end
    if n > maxv then return maxv end
    return n
end

local function escape_sql_ident(s)
    -- very conservative: allow alnum, underscore, dot
    if not s then return nil end
    if string.match(s, "^[%w_%.]+$") then
        return s
    end
    return nil
end

local function build_select_url(base, sql)
    -- Construct URL with query parameter `query=...`; naive-encode spaces and newlines
    -- http library will not encode for us; replace spaces and newlines
    sql = string.gsub(sql, "\n", " ")
    sql = string.gsub(sql, " ", "%20")
    return base .. "/?query=" .. sql
end

function nauthilus_run_hook(logging, session)
    local result = {
        level = "info",
        caller = N .. ".lua",
        session = session,
    }

    local action = nauthilus_http_request.get_http_query_param("action") or "recent"
    local limit = clamp(nauthilus_http_request.get_http_query_param("limit") or 100, 1, 1000)

    local base = os.getenv("CLICKHOUSE_SELECT_BASE") or ""
    local table_name = os.getenv("CLICKHOUSE_TABLE") or "nauthilus.failed_logins"

    local safe_table = escape_sql_ident(table_name)
    if base == "" or not safe_table then
        result.status = "error"
        result.message = "CLICKHOUSE_SELECT_BASE or CLICKHOUSE_TABLE misconfigured"
        return result
    end

    local where = ""
    if action == "by_user" then
        local username = nauthilus_http_request.get_http_query_param("username") or ""
        -- Parameterize safely by using ClickHouse functions; we still must quote safely.
        -- Minimal escape: replace single quotes with doubled quotes.
        username = username:gsub("'", "''")
        where = " WHERE username = '" .. username .. "'"
    elseif action == "by_ip" then
        local ip = nauthilus_http_request.get_http_query_param("ip") or ""
        ip = ip:gsub("'", "''")
        where = " WHERE client_ip = '" .. ip .. "'"
    else
        -- recent (no where)
    end

    local fields = table.concat({
        -- core identifiers and network
        "ts","session","service","client_ip","client_port","client_net","client_id",
        "hostname","proto","user_agent","local_ip","local_port",
        -- user/account info
        "display_name","account","account_field","unique_user_id","username","password_hash",
        -- security and feature info
        "pwnd_info","brute_force_bucket","brute_force_counter","oidc_cid",
        -- hotspot / geoip / pattern
        "failed_login_count","failed_login_rank","failed_login_recognized",
        "geoip_guid","geoip_country","geoip_iso_codes","geoip_status",
        "gp_attempts","gp_unique_ips","gp_unique_users","gp_ips_per_user",
        -- protection and dynamic response
        "prot_active","prot_reason","prot_backoff","prot_delay_ms",
        "dyn_threat","dyn_response",
        -- flags and TLS
        "debug","repeating","user_found","authenticated","no_auth",
        "xssl_protocol","xssl_cipher","ssl_fingerprint"
    }, ",")

    local sql = "SELECT " .. fields .. " FROM " .. safe_table .. where .. " ORDER BY ts DESC LIMIT " .. tostring(limit) .. " FORMAT JSON"

    local url = build_select_url(base, sql)

    local headers = {}
    local user = os.getenv("CLICKHOUSE_USER")
    local pass = os.getenv("CLICKHOUSE_PASSWORD")
    if user and user ~= "" then headers["X-ClickHouse-User"] = user end
    if pass and pass ~= "" then headers["X-ClickHouse-Key"] = pass end

    local res, err = http.get(url, {
        timeout = "10s",
        headers = headers,
    })

    if err or not res or (res.status_code ~= 200 and res.status_code ~= 204) then
        result.status = "error"
        result.message = "ClickHouse query failed"
        result.http_status = res and res.status_code or nil
        result.error = err and tostring(err) or nil
        return result
    end

    result.status = "success"
    result.message = "Query executed"
    result.clickhouse = {
        action = action,
        limit = limit,
        table = table_name,
        raw = res.body, -- JSON from ClickHouse
    }

    -- If this hook is used to render HTTP directly, return nil; otherwise return result to be serialized.
    return result
end
