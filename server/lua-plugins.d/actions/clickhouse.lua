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
local geoip_bridge = require("nauthilus_geoip_bridge")
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
    local is_oidc_token_post_action = request.no_auth
        and request.protocol == "oidc"
        and request.service == "idp"
        and request.grant_type ~= nil
        and tostring(request.grant_type) ~= ""

    if request.no_auth and not is_oidc_token_post_action then
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

    local function to_float(value)
        local n = tonumber(value)
        if n == nil then return nil end
        if n ~= n then return nil end -- NaN guard
        return n
    end

    local function to_string(value)
        if value == nil then return "" end
        return tostring(value)
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

    local decision_sources_from_ctx = {}
    local builtin_decision_sources = nauthilus_context.context_get("__lua_ctx_builtin__")
    if nauthilus_util.is_table(builtin_decision_sources) and nauthilus_util.table_length(builtin_decision_sources) > 0 then
        for _, v in ipairs(builtin_decision_sources) do
            table.insert(decision_sources_from_ctx, v)
        end
    end
    local pwnd_info = ""
    local brute_force_bucket = ""
    local password_hash = ""

    -- Get result table
    geoip_bridge.attach()

    local rt = nauthilus_context.context_get("rt") or {}
    local policy_facts = nauthilus_context.context_get("policy_facts") or {}

    local function fact(namespace, key)
        if type(policy_facts) ~= "table" or type(policy_facts[namespace]) ~= "table" then
            return nil
        end

        return policy_facts[namespace][key]
    end

    -- reputation_from_runtime_or_facts keeps ClickHouse writes resilient when
    -- subject runtime details are absent but policy facts were emitted.
    local function reputation_from_runtime_or_facts()
        if type(rt) == "table" and type(rt.geoip_reputation) == "table" then
            return rt.geoip_reputation, to_string(rt.geoip_reputation.source)
        end

        local reputation_facts = policy_facts.geoip_reputation
        if type(reputation_facts) ~= "table" or nauthilus_util.table_length(reputation_facts) == 0 then
            return nil, ""
        end

        return reputation_facts, "policy_facts"
    end

    local function add_decision_source(name)
        if not nauthilus_util.exists_in_table(decision_sources_from_ctx, name) then
            table.insert(decision_sources_from_ctx, name)
        end
    end

    if type(rt) == "table" and nauthilus_util.table_length(rt) > 0 then
        if rt.environment_blocklist then
            add_decision_source("blocklist")
        end
        if rt.subject_geoippolicyd and rt.geoip_info and rt.geoip_info.status and rt.geoip_info.status == "reject" then
            add_decision_source("geoip_policyd")
        end
        if rt.subject_account_protection_mode or (rt.account_protection and rt.account_protection.active) then
            add_decision_source("account_protection")
        end
    end

    if fact("blocklist", "matched") == true then
        add_decision_source("blocklist")
    end
    if fact("geoip", "rejected") == true then
        add_decision_source("geoip_policyd")
    end
    if fact("failed_login_hotspot", "triggered") == true then
        add_decision_source("failed_login_hotspot")
    end
    if fact("account_protection", "active") == true then
        add_decision_source("account_protection")
    end

    local decision_sources = table.concat(decision_sources_from_ctx, ",")

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
        local geoip_source = ""
        local geoip_matched
        local geoip_country_name = ""
        local geoip_city_name = ""
        local geoip_asn
        local geoip_asn_org = ""
        local geoip_asn_prefix = ""
        local geoip_asn_registry = ""
        local geoip_asn_country = ""
        local geoip_asn_allocated = ""
        local geoip_asn_status = ""
        if rt and rt.geoip_info then
            if rt.geoip_info.guid and rt.geoip_info.guid ~= "" then geoip_guid = rt.geoip_info.guid end
            if rt.geoip_info.current_country_code and rt.geoip_info.current_country_code ~= "" then geoip_country = rt.geoip_info.current_country_code end
            if rt.geoip_info.status and rt.geoip_info.status ~= "" then geoip_status = rt.geoip_info.status end
            if rt.geoip_info.source and rt.geoip_info.source ~= "" then geoip_source = rt.geoip_info.source end
            if rt.geoip_info.matched ~= nil then geoip_matched = (rt.geoip_info.matched == true) end
            if rt.geoip_info.native_matched ~= nil then geoip_matched = (rt.geoip_info.native_matched == true) end
            geoip_country_name = to_string(rt.geoip_info.country_name)
            geoip_city_name = to_string(rt.geoip_info.city_name)
            geoip_asn = to_uint(rt.geoip_info.asn)
            geoip_asn_org = to_string(rt.geoip_info.asn_org)
            geoip_asn_prefix = to_string(rt.geoip_info.asn_prefix)
            geoip_asn_registry = to_string(rt.geoip_info.asn_registry)
            geoip_asn_country = to_string(rt.geoip_info.asn_country_iso)
            geoip_asn_allocated = to_string(rt.geoip_info.asn_allocated)
            geoip_asn_status = to_string(rt.geoip_info.asn_status)
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

        -- Reputation details if present. Producers are intentionally separate
        -- from GeoIP enrichment so policy can decide on explicit scores.
        local reputation_score
        local reputation_positive_score
        local reputation_negative_score
        local reputation_ip_score
        local reputation_asn_score
        local reputation_country_score
        local reputation_asn_country_score
        local reputation_samples
        local reputation_source = ""
        local reputation_decision = ""
        local reputation, reputation_default_source = reputation_from_runtime_or_facts()
        if reputation then
            reputation_score = to_float(reputation.score)
            reputation_positive_score = to_float(reputation.positive_score)
            reputation_negative_score = to_float(reputation.negative_score)
            reputation_ip_score = to_float(reputation.ip_score)
            reputation_asn_score = to_float(reputation.asn_score)
            reputation_country_score = to_float(reputation.country_score)
            reputation_asn_country_score = to_float(reputation.asn_country_score)
            reputation_samples = to_uint(reputation.samples)
            reputation_source = reputation_default_source
            if reputation.source ~= nil then
                reputation_source = to_string(reputation.source)
            end
            reputation_decision = to_string(reputation.decision)
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
            decision_sources = decision_sources,
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
            saml_entity_id = request.saml_entity_id or "",
            grant_type = request.grant_type or "",
            mfa_method = request.mfa_method or "",
            failed_login_count = failed_login_count,
            failed_login_rank = failed_login_rank,
            failed_login_recognized = failed_login_recognized,
            geoip_guid = geoip_guid,
            geoip_country = geoip_country,
            geoip_iso_codes = geoip_iso_codes,
            geoip_status = geoip_status,
            geoip_source = geoip_source,
            geoip_matched = geoip_matched,
            geoip_country_name = geoip_country_name,
            geoip_city_name = geoip_city_name,
            geoip_asn = geoip_asn,
            geoip_asn_org = geoip_asn_org,
            geoip_asn_prefix = geoip_asn_prefix,
            geoip_asn_registry = geoip_asn_registry,
            geoip_asn_country = geoip_asn_country,
            geoip_asn_allocated = geoip_asn_allocated,
            geoip_asn_status = geoip_asn_status,
            reputation_score = reputation_score,
            reputation_positive_score = reputation_positive_score,
            reputation_negative_score = reputation_negative_score,
            reputation_ip_score = reputation_ip_score,
            reputation_asn_score = reputation_asn_score,
            reputation_country_score = reputation_country_score,
            reputation_asn_country_score = reputation_asn_country_score,
            reputation_samples = reputation_samples,
            reputation_source = reputation_source,
            reputation_decision = reputation_decision,
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
            rwp = (request.rwp == true),
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
