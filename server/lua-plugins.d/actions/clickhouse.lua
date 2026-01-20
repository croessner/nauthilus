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

-- ClickHouse Post-Action
--
-- Purpose: Collect the same metrics as telegram.lua for non-authenticated requests,
-- including requests without an existing account, and batch-insert them into ClickHouse.
-- Batching is implemented using the nauthilus_cache module.
--
-- Environment variables:
--   CLICKHOUSE_INSERT_URL   - Full HTTP endpoint with SQL query, e.g.:
--                             http://clickhouse:8123/?query=INSERT%20INTO%20nauthilus.logins%20FORMAT%20JSONEachRow
--   CLICKHOUSE_USER         - (optional) auth user (used for Basic Auth and X-ClickHouse-User)
--   CLICKHOUSE_PASSWORD     - (optional) auth password (used for Basic Auth and X-ClickHouse-Key)
--   CLICKHOUSE_BATCH_SIZE   - (optional) default 100
--   CLICKHOUSE_CACHE_KEY    - (optional) key for cache list, default "clickhouse:batch:logins"
--
-- Data format: JSONEachRow with fields documented in README.

local N = "clickhouse"

local nauthilus_util = require("nauthilus_util")
local nauthilus_password = require("nauthilus_password")
local nauthilus_context = require("nauthilus_context")
local nauthilus_cache = require("nauthilus_cache")
local nauthilus_redis = require("nauthilus_redis")
local time = require("time")

local json = require("json")
local http = require("glua_http")
local base64 = require("base64")

local HCCR = "http_client_concurrent_requests_total"

local CLICKHOUSE_INSERT_URL = nauthilus_util.getenv("CLICKHOUSE_INSERT_URL", "")
local CLICKHOUSE_USER = nauthilus_util.getenv("CLICKHOUSE_USER", "")
local CLICKHOUSE_PASSWORD = nauthilus_util.getenv("CLICKHOUSE_PASSWORD", "")
local CLICKHOUSE_BATCH_SIZE = tonumber(nauthilus_util.getenv("CLICKHOUSE_BATCH_SIZE", "100")) or 100
local CLICKHOUSE_CACHE_KEY = nauthilus_util.getenv("CLICKHOUSE_CACHE_KEY", "clickhouse:batch:logins")

function nauthilus_call_action(request)
    if request.no_auth then
        return nauthilus_builtin.ACTION_RESULT_OK
    end

    local function log_line(level, message, extra, err_string)
        local logs = { caller = N .. ".lua", message = message }
        if extra and type(extra) == "table" then
            for k, v in pairs(extra) do logs[k] = v end
        end
        nauthilus_util.log(request, level, logs, err_string)
    end

    -- Utility: sanitize unsigned integers for ClickHouse (returns nil if negative or not a number)
    local function to_uint(value)
        local n = tonumber(value)
        if n == nil then return nil end
        if n < 0 then return nil end
        if n ~= n then return nil end -- NaN guard (just in case)
        return math.floor(n)
    end

    -- Normalize timestamp strings for ClickHouse DateTime64(3, 'UTC') JSONEachRow input
    -- - Replace 'T' with space
    -- - Remove trailing 'Z'
    -- - Remove trailing timezone offset like ' +HH:MM' or ' -HH:MM'
    -- - Truncate fractional seconds to 3 digits (milliseconds)
    local function normalize_ts_for_clickhouse(s)
        if type(s) ~= "string" or s == "" then return s end
        local t = s
        -- unify separator
        t = t:gsub("T", " ")
        -- remove trailing Z (already UTC)
        t = t:gsub("Z$", "")
        -- remove trailing offset (space then +HH:MM or -HH:MM)
        t = t:gsub(" [%+%-]%d%d:%d%d$", "")
        -- truncate fractional seconds to 3 digits if longer
        -- patterns: .123456 -> .123 ; .123 -> .123 ; .1 -> .1 (left as-is)
        t = t:gsub("(%.[0-9][0-9][0-9])%d+", "%1")
        return t
    end

    -- Return current UTC timestamp as 'YYYY-MM-DD HH:MM:SS.mmm'
    -- We avoid relying on nauthilus_util.get_current_timestamp() because it may honor TZ.
    local function utc_now_ts_ms()
        -- Use UTC with os.date('!'), seconds resolution
        local base = time.format(time.unix(), "2006-01-02 15:04:05", "UTC")
        -- Best-effort milliseconds: Lua standard libs don't provide wall-clock ms reliably.
        -- We use .000 to keep a stable DateTime64(3) compatible format.
        local ms = "000"
        return string.format("%s.%s", base, ms)
    end

    local feature_from_ctx = {}
    local builtin_features = nauthilus_context.context_get("__lua_ctx_builtin__")
    if nauthilus_util.is_table(builtin_features) and nauthilus_util.table_length(builtin_features) > 0 then
        for _, v in ipairs(builtin_features) do
            table.insert(feature_from_ctx, v)
        end
    end
    local pwnd_info = ""
    local brute_force_bucket = ""
    local password_hash = ""

    -- Get result table
    local rt = nauthilus_context.context_get("rt") or {}

    if type(rt) == "table" and nauthilus_util.table_length(rt) > 0 then
        if rt.feature_blocklist then
            table.insert(feature_from_ctx, "blocklist")
        end
        if rt.filter_geoippolicyd and rt.geoip_info and rt.geoip_info.status and rt.geoip_info.status == "reject" then
            table.insert(feature_from_ctx, "geoip_policyd")
        end
        if rt.filter_account_protection_mode or (rt.account_protection and rt.account_protection.active) then
            table.insert(feature_from_ctx, "account_protection")
        end
    end

    local features = table.concat(feature_from_ctx, ",")

    local hibp = nauthilus_context.context_get("haveibeenpwnd_hash_info")
    if hibp then pwnd_info = hibp else pwnd_info = "" end

    -- For authenticated requests, throttle writes (username+client_ip) to at most once per 5 minutes via Redis
    local allowed = true
    if request.authenticated == true then
        local username = (request.username ~= "" and request.username) or ""
        local cip = (request.client_ip ~= "" and request.client_ip) or ""
        if username ~= "" and cip ~= "" then
            local dedup_key = nauthilus_util.get_redis_key(request, "clickhouse:authdedup:" .. tostring(username) .. ":" .. tostring(cip))
            -- Use SET NX EX to reduce roundtrips (atomic gate)
            local ok, rerr = nauthilus_redis.redis_set("default", dedup_key, "1", { nx = true, ex = 300 })
            if rerr then
                -- Fail-open on Redis errors to avoid losing data; log for visibility
                log_line("error", "clickhouse: redis dedup failed", { key = dedup_key }, tostring(rerr))
            else
                if ok == nil then
                    -- Key already exists within TTL → skip this write
                    allowed = false
                else
                    allowed = true
                end
            end
        end
    end

    if allowed then
        -- Build row (same values as telegram), tolerate missing account
        local ts = utc_now_ts_ms()

        local proto = (request.protocol ~= "" and request.protocol) or ""
        local method = (request.method ~= "" and request.method) or ""
        local username = (request.username ~= "" and request.username) or ""
        local account = (request.account ~= nil and request.account ~= "" and request.account) or ""

        if request.password and request.password ~= "" then
            password_hash = nauthilus_password.generate_password_hash(request.password)
        end

        local display_name = (request.display_name ~= "" and request.display_name) or ""
        local hostname = (request.client_hostname ~= "" and request.client_hostname) or ""

        if request.brute_force_bucket and request.brute_force_bucket ~= "" then
            brute_force_bucket = request.brute_force_bucket
        end

        -- Failed-login hotspot details if present
        local failed_login_count
        local failed_login_rank
        local failed_login_recognized
        if rt and rt.failed_login_info then
            if rt.failed_login_info.new_count ~= nil then failed_login_count = to_uint(rt.failed_login_info.new_count) end
            if rt.failed_login_info.rank ~= nil then failed_login_rank = to_uint(rt.failed_login_info.rank) end
            if rt.failed_login_info.recognized_account ~= nil then failed_login_recognized = (rt.failed_login_info.recognized_account == true) end
        end

        -- GeoIP details if present
        local geoip_guid = ""
        local geoip_country = ""
        local geoip_iso_codes = ""
        local geoip_status = ""
        if rt and rt.geoip_info then
            if rt.geoip_info.guid and rt.geoip_info.guid ~= "" then geoip_guid = rt.geoip_info.guid end
            if rt.geoip_info.current_country_code and rt.geoip_info.current_country_code ~= "" then geoip_country = rt.geoip_info.current_country_code end
            if rt.geoip_info.status and rt.geoip_info.status ~= "" then geoip_status = rt.geoip_info.status end
            if rt.geoip_info.iso_codes_seen and type(rt.geoip_info.iso_codes_seen) == "table" then
                local parts = {}
                for _, v in ipairs(rt.geoip_info.iso_codes_seen) do
                    local s = tostring(v)
                    if s:match("^[A-Z][A-Z]$") then table.insert(parts, s) end
                end
                if #parts == 0 then
                    if rt.geoip_info.current_country_code and rt.geoip_info.current_country_code:match("^[A-Z][A-Z]$") then
                        geoip_iso_codes = rt.geoip_info.current_country_code
                    end
                else
                    geoip_iso_codes = table.concat(parts, ",")
                end
            end
        end

        -- Global pattern details if present
        local gp_attempts
        local gp_unique_ips
        local gp_unique_users
        local gp_ips_per_user
        if rt and rt.global_pattern_info then
            local gpi = rt.global_pattern_info
            if gpi.attempts ~= nil then gp_attempts = to_uint(gpi.attempts) end
            if gpi.unique_ips ~= nil then gp_unique_ips = to_uint(gpi.unique_ips) end
            if gpi.unique_users ~= nil then gp_unique_users = to_uint(gpi.unique_users) end
            if gpi.ips_per_user ~= nil then gp_ips_per_user = to_uint(gpi.ips_per_user) end
        end

        -- Account protection details
        local prot_active
        local prot_reason = ""
        local prot_backoff
        local prot_delay_ms
        if rt and rt.account_protection then
            if rt.account_protection.active ~= nil then prot_active = (rt.account_protection.active == true) end
            if rt.account_protection.reason ~= nil then prot_reason = tostring(rt.account_protection.reason) end
            if rt.account_protection.backoff_level ~= nil then prot_backoff = to_uint(rt.account_protection.backoff_level) end
            if rt.account_protection.delay_ms ~= nil then prot_delay_ms = to_uint(rt.account_protection.delay_ms) end
        end

        -- Dynamic response details
        local dyn_threat
        local dyn_response = ""
        if rt and rt.dynamic_response then
            if rt.dynamic_response.threat_level ~= nil then dyn_threat = to_uint(rt.dynamic_response.threat_level) end
            if rt.dynamic_response.response ~= nil then dyn_response = tostring(rt.dynamic_response.response) end
        end

        -- Build row for ClickHouse
        local row = {
            ts = normalize_ts_for_clickhouse(ts),
            session = request.session,
            service = request.service or "",
            features = features,
            client_ip = request.client_ip,
            client_port = request.client_port or "",
            client_net = request.client_net or "",
            client_id = request.client_id or "",
            hostname = hostname,
            proto = proto,
            method = method,
            user_agent = request.user_agent or "",
            local_ip = request.local_ip or "",
            local_port = request.local_port or "",
            display_name = display_name,
            account = account,
            username = username,
            password_hash = password_hash,
            pwnd_info = pwnd_info,
            brute_force_bucket = brute_force_bucket,
            brute_force_counter = (request.brute_force_counter ~= nil) and to_uint(request.brute_force_counter) or nil,
            oidc_cid = request.oidc_cid or "",
            failed_login_count = failed_login_count,
            failed_login_rank = failed_login_rank,
            failed_login_recognized = failed_login_recognized,
            geoip_guid = geoip_guid,
            geoip_country = geoip_country,
            geoip_iso_codes = geoip_iso_codes,
            geoip_status = geoip_status,
            gp_attempts = gp_attempts,
            gp_unique_ips = gp_unique_ips,
            gp_unique_users = gp_unique_users,
            gp_ips_per_user = gp_ips_per_user,
            prot_active = prot_active,
            prot_reason = prot_reason,
            prot_backoff = prot_backoff,
            prot_delay_ms = prot_delay_ms,
            dyn_threat = dyn_threat,
            dyn_response = dyn_response,
            repeating = (request.repeating == true),
            user_found = (request.user_found == true),
            authenticated = (request.authenticated == true),
            xssl_protocol = request.xssl_protocol or "",
            xssl_cipher = request.xssl_cipher or "",
            ssl_fingerprint = request.ssl_fingerprint or "",
            latency = to_uint(request.latency) or 0,
            http_status = to_uint(request.http_status) or 0,
            status_msg = request.status_message or "",
        }

        -- Batch into cache
        local cache_key = CLICKHOUSE_CACHE_KEY
        local batch_size = CLICKHOUSE_BATCH_SIZE

        -- Store JSON-encoded row to ensure stability of types
        local ok, row_json = pcall(json.encode, row)
        if not ok then
            -- best-effort: drop this row if encoding fails
            log_line("error", "clickhouse: encode row failed; dropping")
            row_json = nil
        end

        local to_send = {}
        if row_json then
            local new_len = nauthilus_cache.cache_push(cache_key, row_json)
            log_line("debug", "clickhouse: queued row", { key = cache_key, length = new_len, threshold = batch_size })
            if tonumber(new_len) and tonumber(new_len) >= batch_size then
                to_send = nauthilus_cache.cache_pop_all(cache_key) or {}
            end
        end

        if #to_send > 0 then
            -- Prepare HTTP client and request
            log_line("info", "clickhouse: flushing batch", { count = #to_send })
            local nauthilus_prometheus = require("nauthilus_prometheus")

            local insert_url = CLICKHOUSE_INSERT_URL
            if insert_url and insert_url ~= "" then
                nauthilus_prometheus.increment_gauge(HCCR, { service = N })

                -- Build NDJSON body (JSONEachRow): one JSON document per line
                local body_lines = {}
                for _, line in ipairs(to_send) do table.insert(body_lines, line) end
                local body = table.concat(body_lines, "\n")

                local headers = {
                    Accept = "*/*",
                    ["User-Agent"] = "Nauthilus",
                    ["Content-Type"] = "application/json",
                }
                local user = CLICKHOUSE_USER
                local pass = CLICKHOUSE_PASSWORD
                local auth_method = "none"

                -- Prefer Basic auth if both user and pass are provided; do NOT send X- headers simultaneously.
                -- If Basic cannot be created (e.g., base64 unavailable), fall back to X- headers.
                if user and user ~= "" and pass and pass ~= "" then
                    local credentials = tostring(user) .. ":" .. tostring(pass)
                    local encoded
                    local ok_enc, err_enc = pcall(function() encoded = base64.RawStdEncoding:encode_to_string(credentials) end)
                    if ok_enc and encoded and encoded ~= "" then
                        headers["Authorization"] = "Basic " .. encoded
                        auth_method = "basic"
                    else
                        -- Fallback to X- headers when Basic cannot be formed
                        headers["X-ClickHouse-User"] = user
                        headers["X-ClickHouse-Key"] = pass
                        auth_method = "x-headers"
                        log_line("debug", "clickhouse: base64 encode failed; falling back to X- headers", { err = err_enc and tostring(err_enc) or nil })
                    end
                else
                    -- If only one of user/password is present, use X- headers (best effort)
                    if user and user ~= "" then
                        headers["X-ClickHouse-User"] = user
                        auth_method = "x-headers"
                    end
                    if pass and pass ~= "" then
                        headers["X-ClickHouse-Key"] = pass
                        if auth_method == "none" then auth_method = "x-headers" end
                    end
                end

                log_line("debug", "clickhouse: posting batch", { url_configured = true, count = #to_send, auth_method = auth_method })

                local timer = nauthilus_prometheus.start_histogram_timer(N .. "_duration_seconds", { op = "insert" })
                local res, err = http.post(insert_url, {
                    timeout = "10s",
                    headers = headers,
                    body = body,
                })
                nauthilus_prometheus.stop_timer(timer)
                nauthilus_prometheus.decrement_gauge(HCCR, { service = N })

                -- Ensure we always log the outcome of http.post
                local status = res and res.status_code or nil
                local resp_body = res and res.body or nil

                if not err and res and (status == 200 or status == 204) then
                    log_line("info", "clickhouse: batch inserted", { count = #to_send, status = status })
                elseif err or not res or (status ~= 200 and status ~= 204) then
                    -- Requeue on failure (best-effort)
                    for _, v in ipairs(to_send) do nauthilus_cache.cache_push(cache_key, v) end
                    -- Truncate body to avoid excessive log size
                    local body_preview
                    if resp_body and type(resp_body) == "string" then body_preview = string.sub(resp_body, 1, 512) end
                    log_line("error", "clickhouse: insert failed; re-queued", { count = #to_send, status = status, body = body_preview }, err and tostring(err) or nil)
                    if err then
                        nauthilus_util.if_error_raise(err)
                    else
                        -- Surface HTTP status as error
                        error("clickhouse insert failed, status " .. tostring(status))
                    end
                else
                    -- Unexpected branch: neither success nor explicit failure matched
                    log_line("warn", "clickhouse: unexpected HTTP result state", { status = status, has_err = err ~= nil })
                end
            else
                -- No endpoint configured, keep queued
                for _, v in ipairs(to_send) do nauthilus_cache.cache_push(cache_key, v) end
                log_line("info", "clickhouse: no insert URL configured; keeping batch in cache", { count = #to_send, key = cache_key })
            end
        end
    end

    -- annotate context for debugging/visibility
    local rt2 = rt or {}
    rt2.post_clickhouse = true
    nauthilus_context.context_set("rt", rt2)

    return nauthilus_builtin.ACTION_RESULT_OK
end
