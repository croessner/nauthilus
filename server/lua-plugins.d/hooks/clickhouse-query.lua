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
--   CLICKHOUSE_TABLE       - Table name, e.g. nauthilus.logins
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

dynamic_loader("nauthilus_gll_json")
local json = require("json")

local N = "clickhouse-query"

-- Sanitize strings to be safely embeddable into JSON by removing control characters
-- Replace common whitespace controls (CR, LF, TAB) with a single space to keep readability,
-- and strip remaining control characters (U+0000–U+001F) which may break JSON serializers.
local function sanitize_json_string(s)
    if type(s) ~= "string" then return s end
    -- normalize common whitespace controls to spaces
    s = s:gsub("[\r\n\t]", " ")
    -- remove any remaining control characters
    s = s:gsub("%c", "")
    return s
end

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

local function build_select_endpoint(base)
    -- Use POST to avoid URL encoding issues; ClickHouse accepts SQL in the request body
    if string.sub(base, -1) == "/" then
        return base
    end
    return base .. "/"
end

local function trim(s)
    return (s or ""):gsub("^%s+", ""):gsub("%s+$", "")
end

local function strip_comments(s)
    -- remove /* ... */ and -- ... end-of-line
    s = s:gsub("/%*.-%*/", " ")
    s = s:gsub("%-%-.-\n", " ")
    s = s:gsub("%-%-.*$", " ")
    return s
end

local function is_safe_select(sql)
    local raw = trim(sql or "")
    local s = strip_comments(raw)
    local lower = string.lower(s)
    if string.find(lower, ";", 1, true) then
        return false, "Semicolons are not allowed"
    end
    local starts = string.match(lower, "^%s*select%s") or string.match(lower, "^%s*with%s")
    if not starts then
        return false, "Only SELECT/WITH queries are allowed"
    end
    local forbidden = { "insert","update","delete","alter","drop","truncate","create","attach","rename","grant","revoke","optimize","system","kill","set","use" }
    for _, kw in ipairs(forbidden) do
        if string.match(lower, "%f[%w]" .. kw .. "%f[%W]") then
            return false, "Forbidden keyword: " .. kw
        end
    end
    return true, s
end

local function ensure_limit_and_format(sql, limit)
    local s = trim(sql or "")
    local lower = string.lower(s)
    if not string.match(lower, "%f[%w]limit%f[%W]") then
        s = s .. " LIMIT " .. tostring(limit)
        lower = string.lower(s)
    end
    if not string.match(lower, "%f[%w]format%f[%W]") then
        s = s .. " FORMAT JSON"
    end
    return s
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
    local table_name = os.getenv("CLICKHOUSE_TABLE") or "nauthilus.logins"

    local safe_table = escape_sql_ident(table_name)
    if base == "" or not safe_table then
        result.status = "error"
        result.message = "CLICKHOUSE_SELECT_BASE or CLICKHOUSE_TABLE misconfigured"
        return result
    end

    local sql
    if action == "raw_sql" then
        local user_sql = nauthilus_http_request.get_http_query_param("sql") or ""
        local ok_safe, safe_or_reason = is_safe_select(user_sql)
        if not ok_safe then
            result.status = "error"
            result.message = "Rejected SQL: " .. tostring(safe_or_reason)
            result.clickhouse = {
                action = action,
                limit = limit,
                table = table_name,
            }
            return result
        end
        sql = ensure_limit_and_format(safe_or_reason, limit)
    else
        local where = ""
        if action == "by_user" then
            local username = nauthilus_http_request.get_http_query_param("username") or ""
            -- Parameterize safely by using ClickHouse functions; we still must quote safely.
            -- Minimal escape: replace single quotes with doubled quotes.
            username = username:gsub("'", "''")
            where = " WHERE username = '" .. username .. "'"
        elseif action == "by_account" then
            local account = nauthilus_http_request.get_http_query_param("account") or ""
            -- Parameterize safely by using ClickHouse functions; we still must quote safely.
            -- Minimal escape: replace single quotes with doubled quotes.
            account = account:gsub("'", "''")
            where = " WHERE account = '" .. account .. "'"
        elseif action == "by_ip" then
            local ip = nauthilus_http_request.get_http_query_param("ip") or ""
            ip = ip:gsub("'", "''")
            where = " WHERE client_ip = '" .. ip .. "'"
        else
            -- recent (no where)
        end

        local fields = table.concat({
            -- core identifiers and network
            "ts","session","service","features","client_ip","client_port","client_net","client_id",
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

        sql = "SELECT " .. fields .. " FROM " .. safe_table .. where .. " ORDER BY ts DESC LIMIT " .. tostring(limit) .. " FORMAT JSON"
    end

    local endpoint = build_select_endpoint(base)

    local headers = { ["Content-Type"] = "text/plain; charset=utf-8" }
    local user = os.getenv("CLICKHOUSE_USER")
    local pass = os.getenv("CLICKHOUSE_PASSWORD")
    if user and user ~= "" then headers["X-ClickHouse-User"] = user end
    if pass and pass ~= "" then headers["X-ClickHouse-Key"] = pass end

    local res, err = http.post(endpoint, {
        timeout = "10s",
        headers = headers,
        body = sql,
    })

    if err or not res or (res.status_code ~= 200 and res.status_code ~= 204) then
        result.status = "error"
        local full_body = res and res.body and tostring(res.body) or ""
        local body_snip = full_body
        if body_snip ~= "" then
            -- limit size for logging/string return only
            if #body_snip > 500 then body_snip = string.sub(body_snip, 1, 500) .. "..." end
        end
        result.message = "ClickHouse query failed" .. (res and res.status_code and (" (status " .. tostring(res.status_code) .. ")") or "")
        result.http_status = res and res.status_code or nil
        result.error = (err and tostring(err) or nil)
        -- Try to decode JSON error body if present; otherwise return a short raw snippet
        local ok, decoded = pcall(json.decode, full_body)
        if ok and type(decoded) == "table" then
            result.clickhouse = {
                action = action,
                limit = limit,
                table = table_name,
                query_result = decoded,
            }
        else
            result.clickhouse = {
                action = action,
                limit = limit,
                table = table_name,
                raw = sanitize_json_string(body_snip),
                parse_error = (not ok and sanitize_json_string(tostring(decoded))) or nil,
            }
        end
        return result
    end

    result.status = "success"
    result.message = "Query executed"
    -- Decode ClickHouse JSON body to return a proper JSON object to the client
    local ok, decoded = pcall(json.decode, res.body)
    if ok and type(decoded) == "table" then
        result.clickhouse = {
            action = action,
            limit = limit,
            table = table_name,
            query_result = decoded,
        }
    else
        -- Fallback for unexpected non-JSON bodies; keep previous behavior
        result.clickhouse = {
            action = action,
            limit = limit,
            table = table_name,
            raw = sanitize_json_string(tostring(res.body or "")),
            parse_error = (not ok and sanitize_json_string(tostring(decoded))) or nil,
        }
    end

    -- If this hook is used to render HTTP directly, return nil; otherwise return result to be serialized.
    return result
end
