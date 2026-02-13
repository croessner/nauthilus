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

local nauthilus_util = require("nauthilus_util")

local nauthilus_http_request = require("nauthilus_http_request")

local http = require("glua_http")
local json = require("json")

local N = "clickhouse-query"

local CLICKHOUSE_SELECT_BASE = nauthilus_util.getenv("CLICKHOUSE_SELECT_BASE", "")
local CLICKHOUSE_TABLE = nauthilus_util.getenv("CLICKHOUSE_TABLE", "nauthilus.logins")
local CLICKHOUSE_USER = nauthilus_util.getenv("CLICKHOUSE_USER", "")
local CLICKHOUSE_PASSWORD = nauthilus_util.getenv("CLICKHOUSE_PASSWORD", "")

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

local function ensure_limit_and_format(sql, limit, offset)
    local s = trim(sql or "")
    local lower = string.lower(s)

    local function has_real_limit(txt)
        local pos = 1
        while true do
            local i = string.find(txt, "limit", pos, true)

            if not i then return false end

            local prev_char = (i > 1) and txt:sub(i-1, i-1) or ""
            local next_char = txt:sub(i+5, i+5)
            local prev_is_alpha = prev_char:match("%a") ~= nil
            local next_is_alpha = next_char:match("%a") ~= nil

            if not prev_is_alpha and not next_is_alpha then
                local rest = txt:sub(i+5)
                rest = rest:gsub("^%s+", "")
                if rest:match("^%d") then
                    return true
                end
            end

            pos = i + 5
        end
    end

    if not has_real_limit(lower) then
        s = s .. " LIMIT " .. tostring(limit)
        if (tonumber(offset or 0) or 0) > 0 then
            s = s .. " OFFSET " .. tostring(offset)
        end
        lower = string.lower(s)
    end

    -- Always enforce JSON output for UI consumption, regardless of any user-specified FORMAT.
    s = s .. " FORMAT JSON"

    return s
end

-- Server-side filter parsing and safety caps
local FILTER_MAX_LEN = 600
local FILTER_MAX_TOKENS = 200
local REGEX_MAX_LEN = 256
local MAX_NESTING = 16

local function escape_sql_literal(s)
    s = tostring(s or "")
    return s:gsub("'", "''")
end

-- Whitelisted columns by type
local TEXT_COLS = {
    "session","service","features","client_ip","client_net","client_id",
    "hostname", "proto", "method", "user_agent", "local_ip",
    "display_name","account","username","password_hash",
    "pwnd_info","brute_force_bucket","oidc_cid",
    "geoip_guid","geoip_country","geoip_iso_codes","geoip_status",
    "dyn_threat", "dyn_response", "xssl_protocol", "xssl_cipher", "ssl_fingerprint", "prot_reason", "status_msg"
}

local BOOL_COL = {
    repeating = true, rwp = true, user_found = true, authenticated = true, prot_active = true, failed_login_recognized = true
}

local NUM_COL = {
    client_port=true, local_port=true, brute_force_counter=true,
    failed_login_count=true, failed_login_rank=true,
    gp_attempts=true, gp_unique_ips=true, gp_unique_users=true, gp_ips_per_user=true,
    prot_backoff = true, prot_delay_ms = true,
    latency = true, http_status = true
}

local function is_allowed_key(key)
    if BOOL_COL[key] or NUM_COL[key] then return true end
    for _,k in ipairs(TEXT_COLS) do if k==key then return true end end
    return false
end

local function regex_pred(pattern, flags, col)
    if #pattern > REGEX_MAX_LEN then
        return nil, "regex too long"
    end
    local esc = escape_sql_literal(pattern)
    local prefix = ""
    if flags and flags:match("i") then prefix = "(?i)" end

    -- If a specific column is provided and allowed, only match on that column
    if col and is_allowed_key(col) then
        return "match(toString("..col.."), '"..prefix..esc.."')"
    end

    -- Otherwise, match across all text columns (global regex search)
    local ors = {}
    for _, c in ipairs(TEXT_COLS) do
        table.insert(ors, "match(toString("..c.."), '"..prefix..esc.."')")
    end
    if #ors == 0 then return "1" end
    return "(".. table.concat(ors, " OR ") .. ")"
end

-- Tokenizer producing a sequence with types: LPAREN, RPAREN, AND, OR, NOT, TERM{kind='string'|'regex', value/pattern, flags}, COMP{key,op,valueType('string'|'number'|'bool'|'regex'), value/pattern, flags}
local function tokenize_filter(s)
    local tokens = {}
    local i, n = 1, #s
    local token_count = 0
    local depth = 0
    local function add(t)
        token_count = token_count + 1
        if token_count > FILTER_MAX_TOKENS then error("too many tokens") end
        tokens[#tokens+1] = t
    end
    local function skip_ws()
        while i <= n and s:sub(i,i):match("%s") do i = i + 1 end
    end
    local function parse_quoted()
        local quote = s:sub(i,i); i = i + 1
        local buf = {}
        while i <= n do
            local c = s:sub(i,i)
            if c == "\\" and i < n then
                buf[#buf+1] = s:sub(i, i+1); i = i + 2
            elseif c == quote then
                i = i + 1; break
            else
                buf[#buf+1] = c; i = i + 1
            end
        end
        return table.concat(buf, "")
    end
    local function parse_regex()
        -- starting at '/'
        i = i + 1
        local buf = {}
        local closed = false
        while i <= n do
            local c = s:sub(i,i)
            if c == "\\" and i < n then
                buf[#buf+1] = s:sub(i, i+1); i = i + 2
            elseif c == '/' then
                i = i + 1
                closed = true
                break
            else
                buf[#buf+1] = c; i = i + 1
            end
        end
        local flags = ""
        while i <= n and s:sub(i,i):match("[a-zA-Z]") do
            flags = flags .. s:sub(i,i); i = i + 1
        end
        local pat = table.concat(buf, "")
        return pat, flags, closed
    end

    while i <= n do
        skip_ws()
        if i > n then break end
        local c = s:sub(i,i)
        if c == '(' then
            depth = depth + 1
            if depth > MAX_NESTING then error("too deep") end
            add({type='LPAREN'}); i = i + 1
        elseif c == ')' then
            depth = math.max(0, depth - 1)
            add({type='RPAREN'}); i = i + 1
        elseif c == '"' or c == '\'' then
            local val = parse_quoted()
            add({ type='TERM', kind='string', value=val })
        elseif c == '/' then
            local pat, flags, closed = parse_regex()
            if not closed then error("unterminated regex") end
            add({ type='TERM', kind='regex', pattern=pat, flags=flags })
        elseif c == '!' then
            add({type='NOT'})
            i = i + 1
        else
            -- word or comparison or operator
            local start = i
            while i <= n and not s:sub(i,i):match("[%s%(%)]") do
                i = i + 1
            end
            local word = s:sub(start, i-1)
            -- Try to parse comparison possibly with spaces around operator
            local key, op, rest = word:match("^([%w_%.]+)([=!<>]=?)(.+)$")
            if key and op then
                -- Validate operator is one of the supported set; discard single '='
                if not (op == '==' or op == '!=' or op == '<=' or op == '>=' or op == '<' or op == '>') then
                    key, op, rest = nil, nil, nil
                end
            end
            if not key then
                -- maybe spaced operator: key [ws] op [ws] value
                local key2 = word:match("^([%w_%.]+)$")
                if key2 then
                    local save = i; skip_ws();
                    local two = s:sub(i,i+1)
                    local one = s:sub(i,i)
                    local found_op
                    if two == '==' or two == '!=' or two == '<=' or two == '>=' then
                        found_op = two; i = i + 2
                    elseif one == '<' or one == '>' then
                        found_op = one; i = i + 1
                    end
                    if found_op then
                        skip_ws()
                        local v
                        if i <= n and (s:sub(i,i) == '"' or s:sub(i,i) == '\'') then
                            v = parse_quoted()
                            add({ type='COMP', key=key2, op=found_op, valueType='string', value=v })
                            -- handled; prevent further processing of this word in current iteration
                            word = ''
                            key = nil; op = nil; rest = nil
                        elseif i <= n and s:sub(i,i) == '/' then
                            local pat, flags, closed = parse_regex(); if not closed then error("unterminated regex") end
                            add({ type='COMP', key=key2, op=found_op, valueType='regex', pattern=pat, flags=flags })
                            word = ''
                            key = nil; op = nil; rest = nil
                        else
                            local vs = i
                            while i <= n and not s:sub(i,i):match("[%s%(%)]") do i = i + 1 end
                            local vword = s:sub(vs, i-1)
                            add({ type='COMP', key=key2, op=found_op, valueType='raw', value=vword })
                            word = ''
                            key = nil; op = nil; rest = nil
                        end
                    else
                        i = save
                    end
                end
            end
            if key then
                rest = rest or ""
                if rest:sub(1,1) == '"' or rest:sub(1,1) == '\'' then
                    local v = rest
                    -- strip quotes if present
                    v = v:gsub('^"', ''):gsub('"$', '')
                    v = v:gsub("^'", ""):gsub("'$", "")
                    add({ type='COMP', key=key, op=op, valueType='string', value=v })
                elseif rest:sub(1,1) == '/' then
                    local pat, flags = rest:match('^/(.*)/([a-zA-Z]*)$')
                    if not pat then
                        -- try to recover by treating as plain term
                        add({ type='TERM', kind='string', value=word })
                    else
                        add({ type='COMP', key=key, op=op, valueType='regex', pattern=pat, flags=flags })
                    end
                else
                    add({ type='COMP', key=key, op=op, valueType='raw', value=rest })
                end
            else
                local lw = string.lower(word)
                if lw == 'and' or word == '&&' then add({type='AND'})
                elseif lw == 'or' or word == '||' then add({type='OR'})
                elseif lw == 'not' or word == '!' then add({type='NOT'})
                elseif word ~= '' then add({ type='TERM', kind='string', value=word }) end
            end
        end
    end

    return tokens
end

local function rewrite_implicit_and_before_not_between_expressions(tokens)
    if #tokens < 3 then return tokens end
    local out = {}
    local i = 1
    while i <= #tokens do
        local prev = tokens[i]
        local cur  = tokens[i+1]
        local next = tokens[i+2]
        if prev and cur and next
            and (prev.type == 'COMP' or prev.type == 'RPAREN')
            and cur.type == 'NOT'
            and (next.type == 'COMP' or next.type == 'LPAREN') then
            -- emit prev, AND, NOT, next
            table.insert(out, prev)
            table.insert(out, { type = 'AND' })
            table.insert(out, cur)
            table.insert(out, next)
            i = i + 3
        else
            table.insert(out, prev)
            i = i + 1
        end
    end
    return out
end

local function comp_to_sql(t)
    local key = t.key
    if not is_allowed_key(key) then return "1" end
    local op = t.op
    if BOOL_COL[key] then
        local b
        if t.valueType == 'raw' or t.valueType == 'string' then
            local v = string.lower(t.value or '')
            if v == 'true' or v == '1' then b = 'true' elseif v == 'false' or v == '0' then b = 'false' end
        end
        if not b then return "1" end
        if op == '==' then return key .. " = " .. b
        elseif op == '!=' then return key .. " != " .. b
        else return "1" end
    elseif NUM_COL[key] then
        local num
        if t.valueType == 'raw' or t.valueType == 'string' then
            num = tonumber(t.value)
        end
        if not num then return "1" end
        if op == '==' then return key .. " = " .. tostring(num)
        elseif op == '!=' then return key .. " != " .. tostring(num)
        elseif op == '<' or op == '>' or op == '<=' or op == '>=' then
            return key .. " " .. op .. " " .. tostring(num)
        else return "1" end
    else
        -- text columns
        if t.valueType == 'regex' then
            -- field-specific regex: restrict match() to this key
            local ok, pred = pcall(regex_pred, t.pattern or '', t.flags or '', key)
            if not ok then return "1" end
            if op == '==' then return pred elseif op == '!=' then return "NOT "..pred else return "1" end
        else
            local v = escape_sql_literal(t.value or '')
            if op == '==' then return "toString("..key..") = '"..v.."'"
            elseif op == '!=' then return "toString("..key..") != '"..v.."'"
            else return "1" end
        end
    end
end

local function parse_filter_to_where(s)
    if not s or s == '' then return nil end
    if #s > FILTER_MAX_LEN then error("filter too long") end
    local ok, tokens = pcall(tokenize_filter, s)
    if not ok then return nil, tokens end
    -- Insert implicit AND for EXPRESSION NOT EXPRESSION (no shortcut for field NOT value)
    tokens = rewrite_implicit_and_before_not_between_expressions(tokens)
    local pos = 1
    local function peek() return tokens[pos] end
    local function take()
        local t = tokens[pos]; pos = pos + 1; return t
    end
    local function parse_expr()
        local function parse_unary()
            local t = peek()
            if t and t.type == 'NOT' then take(); return "(NOT " .. parse_unary() .. ")" end
            local t2 = peek()
            if t2 and t2.type == 'LPAREN' then
                take(); local inner = parse_or(); local t3 = take(); if not t3 or t3.type ~= 'RPAREN' then error('missing )') end; return "("..inner..")"
            elseif t2 and t2.type == 'COMP' then
                take(); return comp_to_sql(t2)
            elseif t2 and t2.type == 'TERM' then
                error('bare terms are disabled; use field comparisons')
            else
                error('unexpected token')
            end
        end
        local function parse_and()
            local left = parse_unary()
            while true do
                local t = peek()
                if t and t.type == 'AND' then take(); local right = parse_unary(); left = "("..left.." AND "..right..")" else break end
            end
            return left
        end
        local function parse_or()
            local left = parse_and()
            while true do
                local t = peek()
                if t and t.type == 'OR' then take(); local right = parse_and(); left = "("..left.." OR "..right..")" else break end
            end
            return left
        end
        return parse_or()
    end
    local ok2, where = pcall(parse_expr)
    if not ok2 then return nil, where end
    return where
end

function nauthilus_run_hook(request)
    local logging = request.logging
    local session = request.session
    local result = {
        level = "info",
        caller = N .. ".lua",
        session = session,
    }

    local action = nauthilus_http_request.get_http_query_param("action") or "recent"
    local limit = clamp(nauthilus_http_request.get_http_query_param("limit") or 100, 1, 10000)
    local offset = clamp(nauthilus_http_request.get_http_query_param("offset") or 0, 0, 100000000)

    local base = CLICKHOUSE_SELECT_BASE
    local table_name = CLICKHOUSE_TABLE

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
                offset = offset,
                table = table_name,
            }
            return result
        end
        sql = ensure_limit_and_format(safe_or_reason, limit, offset)
    else
        local where_clauses = {}
        if action == "by_user" then
            local username = nauthilus_http_request.get_http_query_param("username") or ""
            username = username:gsub("'", "''")
            table.insert(where_clauses, "username = '" .. username .. "'")
        elseif action == "by_account" then
            local account = nauthilus_http_request.get_http_query_param("account") or ""
            account = account:gsub("'", "''")
            table.insert(where_clauses, "account = '" .. account .. "'")
        elseif action == "by_ip" then
            local ip = nauthilus_http_request.get_http_query_param("ip") or ""
            ip = ip:gsub("'", "''")
            table.insert(where_clauses, "client_ip = '" .. ip .. "'")
        else
            -- recent: no action-specific filter
        end

        -- Status filter: authenticated true/false
        local status = nauthilus_http_request.get_http_query_param("status") or "all"
        if status == "success" then
            table.insert(where_clauses, "authenticated = true")
        elseif status == "failed" then
            table.insert(where_clauses, "authenticated = false")
        end

        -- Time range filters (inclusive). Accept ISO8601 and let CH parse best-effort.
        -- Normalize trailing 'Z' to '+00:00' for better compatibility across ClickHouse versions,
        -- and prefer DateTime64 parsing to match typical ts column precision.
        local ts_start = nauthilus_http_request.get_http_query_param("ts_start")
        if ts_start and ts_start ~= "" then
            ts_start = ts_start:gsub("Z$","+00:00")
            ts_start = ts_start:gsub("'", "''")
            table.insert(where_clauses, "ts >= parseDateTime64BestEffort('" .. ts_start .. "')"
            )
        end
        local ts_end = nauthilus_http_request.get_http_query_param("ts_end")
        if ts_end and ts_end ~= "" then
            ts_end = ts_end:gsub("Z$","+00:00")
            ts_end = ts_end:gsub("'", "''")
            table.insert(where_clauses, "ts <= parseDateTime64BestEffort('" .. ts_end .. "')"
            )
        end

        -- Server-side filter parsing (search-as-you-type)
        local filter = nauthilus_http_request.get_http_query_param("filter")
        if filter and filter ~= "" then
            local okf, clause_or_err = pcall(parse_filter_to_where, filter)
            if okf and clause_or_err and clause_or_err ~= "" then
                table.insert(where_clauses, "(" .. clause_or_err .. ")")
            else
                result.status = "error"
                result.message = "Invalid filter expression"
                result.clickhouse = {
                    action = action,
                    limit = limit,
                    offset = offset,
                    table = table_name,
                    filter = sanitize_json_string(filter),
                    parse_error = sanitize_json_string(tostring(clause_or_err))
                }
                return result
            end
        end

        local where = ""
        if #where_clauses > 0 then
            where = " WHERE " .. table.concat(where_clauses, " AND ")
        end

        local fields = table.concat({
            -- core identifiers and network
            "ts","session","service","features","client_ip","client_port","client_net","client_id",
            "hostname", "proto", "method", "user_agent", "local_ip", "local_port",
            -- user/account info
            "display_name","account","username","password_hash",
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
            "repeating", "rwp", "user_found", "authenticated",
            "xssl_protocol", "xssl_cipher", "ssl_fingerprint",
            "latency", "http_status", "status_msg"
        }, ",")

        local limit_clause = " LIMIT " .. tostring(limit)
        if (tonumber(offset or 0) or 0) > 0 then
            limit_clause = limit_clause .. " OFFSET " .. tostring(offset)
        end
        sql = "SELECT " .. fields .. " FROM " .. safe_table .. where .. " ORDER BY ts DESC" .. limit_clause .. " FORMAT JSON"
    end

    local endpoint = build_select_endpoint(base)

    local headers = { ["Content-Type"] = "text/plain; charset=utf-8" }
    local user = CLICKHOUSE_USER
    local pass = CLICKHOUSE_PASSWORD
    if user and user ~= "" then headers["X-ClickHouse-User"] = user end
    if pass and pass ~= "" then headers["X-ClickHouse-Key"] = pass end

    -- Debugging: log the effective SQL query if debug is enabled
    if logging.log_level == "debug" then
        local debug_info = {}
        for k, v in pairs(result) do
            debug_info[k] = v
        end

        debug_info.level = "debug"
        debug_info.message = "Effective ClickHouse SQL"
        debug_info.sql = sql

        nauthilus_util.print_result(logging, debug_info)
    end

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
                offset = offset,
                table = table_name,
                query_result = decoded,
                debug = debug_info,
            }
        else
            result.clickhouse = {
                action = action,
                limit = limit,
                table = table_name,
                raw = sanitize_json_string(body_snip),
                parse_error = (not ok and sanitize_json_string(tostring(decoded))) or nil,
                debug = debug_info,
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
            debug = debug_info,
        }
    else
        -- Fallback for unexpected non-JSON bodies; keep previous behavior
        result.clickhouse = {
            action = action,
            limit = limit,
            offset = offset,
            table = table_name,
            raw = sanitize_json_string(tostring(res.body or "")),
            parse_error = (not ok and sanitize_json_string(tostring(decoded))) or nil,
            debug = debug_info,
        }
    end

    -- If this hook is used to render HTTP directly, return nil; otherwise return result to be serialized.
    return result
end
