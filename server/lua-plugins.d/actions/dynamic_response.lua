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

local N = "dynamic_response"

local nauthilus_util = require("nauthilus_util")
local nauthilus_keys = require("nauthilus_keys")

local nauthilus_mail = require("nauthilus_mail")
local nauthilus_redis = require("nauthilus_redis")
local nauthilus_context = require("nauthilus_context")
local nauthilus_otel = require("nauthilus_opentelemetry")
local time = require("time")

local template = require("template")

local ALERTS_ENABLED = nauthilus_util.toboolean(nauthilus_util.getenv("ADMIN_ALERTS_ENABLED", "true"))
local CUSTOM_REDIS_POOL = nauthilus_util.getenv("CUSTOM_REDIS_POOL_NAME", "default")
local ADMIN_ALERT_MIN_UNIQUE_IPS = tonumber(nauthilus_util.getenv("ADMIN_ALERT_MIN_UNIQUE_IPS", "100")) or 100
local ADMIN_ALERT_MIN_IPS_PER_USER = tonumber(nauthilus_util.getenv("ADMIN_ALERT_MIN_IPS_PER_USER", "2.5")) or 2.5
local ADMIN_ALERT_REQUIRE_EVIDENCE = nauthilus_util.toboolean(nauthilus_util.getenv("ADMIN_ALERT_REQUIRE_EVIDENCE", "false"))
local ADMIN_ALERT_COOLDOWN_SECONDS = tonumber(nauthilus_util.getenv("ADMIN_ALERT_COOLDOWN_SECONDS", "900")) or 900

local SMTP_USE_LMTP = nauthilus_util.getenv("SMTP_USE_LMTP", "false")
local SMTP_SERVER = nauthilus_util.getenv("SMTP_SERVER", "localhost")
local SMTP_PORT = nauthilus_util.getenv("SMTP_PORT", "25")
local SMTP_HELO_NAME = nauthilus_util.getenv("SMTP_HELO_NAME", "localhost")
local SMTP_TLS = nauthilus_util.getenv("SMTP_TLS", "false")
local SMTP_STARTTLS = nauthilus_util.getenv("SMTP_STARTTLS", "false")
local SMTP_USERNAME = nauthilus_util.getenv("SMTP_USERNAME", "")
local SMTP_PASSWORD = nauthilus_util.getenv("SMTP_PASSWORD", "")
local SMTP_MAIL_FROM = nauthilus_util.getenv("SMTP_MAIL_FROM", "postmaster@localhost")
local ADMIN_EMAIL_ADDRESSES = nauthilus_util.getenv("ADMIN_EMAIL_ADDRESSES", "")

local DYN_WARMUP_SECONDS = tonumber(nauthilus_util.getenv("DYNAMIC_RESPONSE_WARMUP_SECONDS", "3600")) or 3600
local DYN_WARMUP_MIN_USERS = tonumber(nauthilus_util.getenv("DYNAMIC_RESPONSE_WARMUP_MIN_USERS", "1000")) or 1000
local DYN_WARMUP_MIN_ATTEMPTS = tonumber(nauthilus_util.getenv("DYNAMIC_RESPONSE_WARMUP_MIN_ATTEMPTS", "10000")) or 10000
local MONITORING_OK_STREAK_MIN = tonumber(nauthilus_util.getenv("MONITORING_OK_STREAK_MIN", "10")) or 10

-- Email template for administrator notifications
local admin_email_template = [[
Subject: [NAUTHILUS ALERT] {{subject}}

Dear Administrator,

A security alert has been detected by the Nauthilus system:

Alert: {{subject}}
Timestamp: {{timestamp}}

Metrics:
{{#metrics}}
- {{key}}: {{value}}
{{/metrics}}

Please review this alert and take appropriate action if necessary.

Regards,
Nauthilus Security System
]]

-- Notify administrators about the threat
local function notify_administrators(request, subject, metrics)
    local alerts_enabled = ALERTS_ENABLED

    -- Resolve Redis client for rate limiting
    local client = "default"
    if CUSTOM_REDIS_POOL ~= "default" then
        local err
        client, err = nauthilus_redis.get_redis_connection(CUSTOM_REDIS_POOL)
        nauthilus_util.if_error_raise(err)
    end

    local now = time.unix()

    -- Evidence-based gating and thresholds to reduce false positives
    local min_unique_ips = ADMIN_ALERT_MIN_UNIQUE_IPS
    local min_ips_per_user = ADMIN_ALERT_MIN_IPS_PER_USER
    local require_evidence = ADMIN_ALERT_REQUIRE_EVIDENCE

    local uniq_ips = tonumber(metrics.unique_ips or 0) or 0
    local ips_per_user = tonumber(metrics.ips_per_user or 0) or 0

    local suspicious_regions = (type(metrics.suspicious_regions) == "table") and metrics.suspicious_regions or {}
    local suspicious_ips = (type(metrics.suspicious_ips) == "table") and metrics.suspicious_ips or {}

    local has_evidence = (suspicious_regions and #suspicious_regions > 0) or (suspicious_ips and #suspicious_ips > 0)
    local passes_baseline = (ips_per_user >= min_ips_per_user) and (uniq_ips >= min_unique_ips)

    -- Cooldown window per subject to prevent alert storms
    local cooldown_sec = ADMIN_ALERT_COOLDOWN_SECONDS
    local gate_key = nauthilus_util.get_redis_key(request, "alerts:last_sent:" .. subject)
    local last_sent = tonumber(nauthilus_redis.redis_get(client, gate_key) or "0")
    local in_cooldown = (last_sent ~= nil and (now - last_sent) < cooldown_sec)

    -- Decide whether to notify:
    --  - If alerts disabled -> skip
    --  - If require_evidence=true and no evidence -> skip
    --  - If neither passes_baseline nor has_evidence -> skip
    --  - If within cooldown -> skip
    local should_notify = alerts_enabled and (not (require_evidence and not has_evidence)) and ((passes_baseline or has_evidence)) and (not in_cooldown)

    -- Log the decision
    local notify_logs = {}
    notify_logs.caller = N .. ".lua"
    notify_logs.message = subject
    notify_logs.metrics = metrics
    notify_logs.alert_decision = {
        alerts_enabled = alerts_enabled,
        require_evidence = require_evidence,
        min_unique_ips = min_unique_ips,
        min_ips_per_user = min_ips_per_user,
        passes_baseline = passes_baseline,
        has_evidence = has_evidence,
        cooldown_sec = cooldown_sec,
        in_cooldown = in_cooldown
    }

    if should_notify then
        nauthilus_util.log_warn(request, notify_logs)
    else
        nauthilus_util.log_info(request, notify_logs)
    end

    if not should_notify then
        return
    end

    -- Mark send time (rate limit)
    nauthilus_redis.redis_set(client, gate_key, tostring(now), cooldown_sec)

    -- Send email notification
    -- Get SMTP configuration
    local smtp_use_lmtp = SMTP_USE_LMTP
    local smtp_server = SMTP_SERVER
    local smtp_port = SMTP_PORT
    local smtp_helo_name = SMTP_HELO_NAME
    local smtp_tls = SMTP_TLS
    local smtp_starttls = SMTP_STARTTLS
    local smtp_username = SMTP_USERNAME
    local smtp_password = SMTP_PASSWORD
    local smtp_mail_from = SMTP_MAIL_FROM

    -- Get admin email addresses (comma-separated list)
    local admin_emails_str = ADMIN_EMAIL_ADDRESSES
    if not admin_emails_str or admin_emails_str == "" then
        -- No admin emails configured, just log and return
        local error_logs = {}
        error_logs.caller = N .. ".lua"
        error_logs.message = "No admin email addresses configured for notifications"
        nauthilus_util.log_error(request, error_logs)
        return
    end

    -- Parse admin email addresses
    local admin_emails = {}
    for email in string.gmatch(admin_emails_str, "([^,]+)") do
        -- Trim whitespace
        email = string.match(email, "^%s*(.-)%s*$")
        if email ~= "" then
            table.insert(admin_emails, email)
        end
    end

    -- Prepare template data
    local timestamp_str = time.format(now, "2006-01-02 15:04:05", "UTC")

    -- Convert metrics table to array of key-value pairs for template (skip empties, format numbers)
    local function format_number(x)
        if type(x) == "number" then
            if math.type and math.type(x) == "integer" then
                return tostring(x)
            end
            -- round to 2 decimals
            return string.format("%.2f", x)
        end
        return tostring(x)
    end

    local metrics_array = {}
    for k, v in pairs(metrics) do
        if type(v) == "table" then
            if #v > 0 then
                local value_str = ""
                for _, item in ipairs(v) do
                    if value_str ~= "" then
                        value_str = value_str .. ", "
                    end
                    value_str = value_str .. tostring(item)
                end
                table.insert(metrics_array, { key = k, value = value_str })
            end
        elseif v ~= nil and tostring(v) ~= "" then
            table.insert(metrics_array, { key = k, value = format_number(v) })
        end
    end

    local tmpl_data = {
        subject = subject,
        timestamp = timestamp_str,
        metrics = metrics_array
    }

    -- Render email template
    local mustache, err_tmpl = template.choose("mustache")
    if err_tmpl then
        local error_logs = {}
        error_logs.caller = N .. ".lua"
        error_logs.message = "Failed to initialize template engine"
        nauthilus_util.log_error(request, error_logs, err_tmpl)
        return
    end

    local email_body = mustache:render(admin_email_template, tmpl_data)

    -- Send email to administrators (instrumented)
    local err_smtp
    if nauthilus_otel and nauthilus_otel.is_enabled() then
        local tr = nauthilus_otel.tracer("nauthilus/lua/dynamic_response")
        tr:with_span("smtp.send", function(span)
            -- client span semantics
            span:set_attributes({
                ["peer.service"] = "smtp",
                ["rpc.system"] = "smtp",
                ["server.address"] = tostring(smtp_server or ""),
                ["server.port"] = tonumber(smtp_port) or 0,
                from = tostring(smtp_mail_from or ""),
                recipients = #admin_emails,
                lmtp = nauthilus_util.toboolean(smtp_use_lmtp) and true or false,
                starttls = nauthilus_util.toboolean(smtp_starttls) and true or false,
                tls = nauthilus_util.toboolean(smtp_tls) and true or false,
            })

            err_smtp = nauthilus_mail.send_mail({
                lmtp = nauthilus_util.toboolean(smtp_use_lmtp),
                server = smtp_server,
                port = tonumber(smtp_port),
                helo_name = smtp_helo_name,
                username = smtp_username,
                password = smtp_password,
                tls = nauthilus_util.toboolean(smtp_tls),
                starttls = nauthilus_util.toboolean(smtp_starttls),
                from = smtp_mail_from,
                to = admin_emails,
                subject = "[NAUTHILUS ALERT] " .. subject,
                body = email_body
            })

            if err_smtp then
                span:record_error(tostring(err_smtp))
            end
        end, { kind = "client" })
    else
        err_smtp = nauthilus_mail.send_mail({
            lmtp = nauthilus_util.toboolean(smtp_use_lmtp),
            server = smtp_server,
            port = tonumber(smtp_port),
            helo_name = smtp_helo_name,
            username = smtp_username,
            password = smtp_password,
            tls = nauthilus_util.toboolean(smtp_tls),
            starttls = nauthilus_util.toboolean(smtp_starttls),
            from = smtp_mail_from,
            to = admin_emails,
            subject = "[NAUTHILUS ALERT] " .. subject,
            body = email_body
        })
    end

    if err_smtp then
        local error_logs = {}
        error_logs.caller = N .. ".lua"
        error_logs.message = "Failed to send admin notification email"
        nauthilus_util.log_error(request, error_logs, err_smtp)
    else
        local success_logs = {}
        success_logs.caller = N .. ".lua"
        success_logs.message = "Admin notification email sent successfully"
        success_logs.recipients = #admin_emails
        nauthilus_util.log_info(request, success_logs)
    end
end

-- Apply severe measures for high threat levels
local function apply_severe_measures(request, custom_pool, metrics)
    -- Enable global captcha using atomic Redis Lua script
    local _, err_script = nauthilus_redis.redis_run_script(
        custom_pool, 
        "", 
        "HSetMultiExpire",
            { nauthilus_util.get_redis_key(request, "multilayer:global:settings") },
        {
            0, -- Permanent
            "captcha_enabled", "true",
            "rate_limit_enabled", "true",
            "rate_limit_max", "10" -- 10 requests per minute
        }
    )
    nauthilus_util.if_error_raise(err_script)

    -- Enable geographic filtering if suspicious regions are detected using atomic Redis Lua script
    if metrics.suspicious_regions and #metrics.suspicious_regions > 0 then
        local args = {3600} -- Expire after 1 hour
        for _, region in ipairs(metrics.suspicious_regions) do
            table.insert(args, region)
        end

        local _, err_script_regions = nauthilus_redis.redis_run_script(
            custom_pool, 
            "", 
            "SAddMultiExpire",
                { nauthilus_util.get_redis_key(request, "multilayer:global:blocked_regions") },
            args
        )
        nauthilus_util.if_error_raise(err_script_regions)
    end


    -- Notify administrators
    notify_administrators(request, "SEVERE THREAT ALERT", metrics)
end

-- Apply high measures for high threat levels
local function apply_high_measures(request, custom_pool, metrics)
    -- Enable targeted captcha for affected accounts using atomic Redis Lua script
    if metrics.targeted_accounts and #metrics.targeted_accounts > 0 then
        local args = {3600} -- Expire after 1 hour
        for _, account in ipairs(metrics.targeted_accounts) do
            table.insert(args, account)
        end

        local _, err_script = nauthilus_redis.redis_run_script(
            custom_pool, 
            "", 
            "SAddMultiExpire",
                { nauthilus_util.get_redis_key(request, "multilayer:global:captcha_accounts") },
            args
        )
        nauthilus_util.if_error_raise(err_script)
    end

    -- Enable targeted rate limiting for suspicious IPs using atomic Redis Lua script
    if metrics.suspicious_ips and #metrics.suspicious_ips > 0 then
        local args = {3600} -- Expire after 1 hour
        for _, ip in ipairs(metrics.suspicious_ips) do
            table.insert(args, ip)
        end

        local _, err_script = nauthilus_redis.redis_run_script(
            custom_pool, 
            "", 
            "SAddMultiExpire",
                { nauthilus_util.get_redis_key(request, "multilayer:global:rate_limited_ips") },
            args
        )
        nauthilus_util.if_error_raise(err_script)
    end

    -- Notify administrators
    notify_administrators(request, "HIGH THREAT ALERT", metrics)
end

-- Apply moderate measures for moderate threat levels
local function apply_moderate_measures(request, custom_pool, metrics)
    -- Enable monitoring mode using atomic Redis Lua script
    local _, err_script = nauthilus_redis.redis_run_script(
        custom_pool, 
        "", 
        "HSetMultiExpire",
            { nauthilus_util.get_redis_key(request, "multilayer:global:settings") },
        {
            0, -- Permanent
            "monitoring_mode", "true"
        }
    )
    nauthilus_util.if_error_raise(err_script)

    -- Notify administrators
    notify_administrators(request, "MODERATE THREAT ALERT", metrics)
end

function nauthilus_call_action(request)
    if request.no_auth then
        return
    end

    -- Get Redis connection
    local custom_pool = "default"
    if CUSTOM_REDIS_POOL ~= "default" then
        local err_redis_client

        custom_pool, err_redis_client = nauthilus_redis.get_redis_connection(CUSTOM_REDIS_POOL)
        nauthilus_util.if_error_raise(err_redis_client)
    end

    -- Get current timestamp
    local timestamp = time.unix()
    local username = request.username
    local client_ip = request.client_ip

    -- Calculate threat level based on various factors
    local threat_level = 0.0
    local metrics = {}

    -- Prepare Redis keys
    local attacked_accounts_key = nauthilus_util.get_redis_key(request, "multilayer:distributed_attack:accounts")
    local current_metrics_key = nauthilus_util.get_redis_key(request, "multilayer:global:current_metrics")

    -- Batch: ZSCORE (attack_score) + HMGET (current metrics) in one read pipeline
    local read_cmds = {}
    if username and username ~= "" then
        table.insert(read_cmds, {"zscore", attacked_accounts_key, username})
    else
        -- placeholder to keep indices simple; will be ignored later
        table.insert(read_cmds, {"echo", "noop"})
    end
    table.insert(read_cmds, {"hmget", current_metrics_key, "attempts", "unique_ips", "unique_users", "ips_per_user"})

    local res, rp_err = nauthilus_redis.redis_pipeline(custom_pool, "read", read_cmds)
    nauthilus_util.if_error_raise(rp_err)

    local idx = 1
    local attack_score
    if username and username ~= "" then
        if type(res) == "table" and type(res[idx]) == "table" and res[idx].ok ~= false then
            attack_score = res[idx].value
        end
    end
    idx = idx + 1

    local attempts, unique_ips, unique_users, ips_per_user = 0, 0, 0, 0
    if type(res) == "table" and type(res[idx]) == "table" and res[idx].ok ~= false and type(res[idx].value) == "table" then
        local vals = res[idx].value
        attempts = tonumber(vals[1] or 0) or 0
        unique_ips = tonumber(vals[2] or 0) or 0
        unique_users = tonumber(vals[3] or 0) or 0
        ips_per_user = tonumber(vals[4] or 0) or 0
    end

    if attack_score then
        threat_level = math.max(threat_level, 0.7) -- High threat level if account is under attack
        metrics.targeted_accounts = {username}
    end

    -- Store metrics for response
    metrics.attempts = attempts
    metrics.unique_ips = unique_ips
    metrics.unique_users = unique_users
    metrics.ips_per_user = ips_per_user

    -- Check for abnormal global patterns
    if ips_per_user > 10 then
        -- Many IPs per user indicates a distributed attack
        threat_level = math.max(threat_level, 0.8)
    elseif ips_per_user > 5 then
        threat_level = math.max(threat_level, 0.6)
    end

    -- Check historical patterns to detect sudden spikes (HMGET in same style)
    local hour_key = time.format(timestamp - 3600, "2006-01-02-15", "UTC") -- Previous hour
    local historical_metrics_key = nauthilus_util.get_redis_key(request, "multilayer:global:historical_metrics:" .. hour_key)

    local hist_res, hist_err = nauthilus_redis.redis_pipeline(custom_pool, "read", {
        {"hmget", historical_metrics_key, "attempts", "unique_ips"},
    })
    nauthilus_util.if_error_raise(hist_err)

    local prev_attempts, prev_unique_ips = 0, 0
    if type(hist_res) == "table" and type(hist_res[1]) == "table" and hist_res[1].ok ~= false and type(hist_res[1].value) == "table" then
        local v = hist_res[1].value
        prev_attempts = tonumber(v[1] or 0) or 0
        prev_unique_ips = tonumber(v[2] or 0) or 0
    end

    -- Calculate rate of change
    local attempts_change = 0
    local ips_change = 0

    if prev_attempts > 0 then
        attempts_change = (attempts - prev_attempts) / prev_attempts
    end

    if prev_unique_ips > 0 then
        ips_change = (unique_ips - prev_unique_ips) / prev_unique_ips
    end

    -- Store change metrics
    metrics.attempts_change = attempts_change
    metrics.ips_change = ips_change

    -- Check for sudden spikes
    if attempts_change > 1.0 or ips_change > 1.0 then
        -- More than 100% increase indicates a sudden spike
        threat_level = math.max(threat_level, 0.9)
    elseif attempts_change > 0.5 or ips_change > 0.5 then
        -- More than 50% increase indicates a significant change
        threat_level = math.max(threat_level, 0.7)
    end

    -- Get suspicious regions based on IP geolocation
    local suspicious_regions = {}

    -- Get country code from context (set by geoip.lua)
    local iso_codes_seen = nauthilus_context.context_get("geoippolicyd_iso_codes_seen")
    local country_code = ""

    -- Prefer current_country_code from rt.geoip_info (Info-Mode works without auth)
    do
        local rt = nauthilus_context.context_get("rt") or {}
        if type(rt) == "table" and rt.geoip_info and type(rt.geoip_info.current_country_code) == "string" then
            if rt.geoip_info.current_country_code:match("^[A-Z][A-Z]$") then
                country_code = rt.geoip_info.current_country_code
            end
        end
    end

    -- Fallback to first valid ISO code from iso_codes_seen
    if country_code == "" and iso_codes_seen and #iso_codes_seen > 0 then
        for _, cc in ipairs(iso_codes_seen) do
            if type(cc) == "string" and cc:match("^[A-Z][A-Z]$") then
                country_code = cc
                break
            end
        end
    end

    if country_code and country_code ~= "" then
        -- Add country code to custom log for debugging
        nauthilus_builtin.custom_log_add(N .. "_country_code", country_code)

        -- Get count of attempts from this country
        local country_key = nauthilus_util.get_redis_key(request, "multilayer:global:country:" .. country_code)
        local country_count = nauthilus_redis.redis_get(custom_pool, country_key) or "0"
        country_count = tonumber(country_count) or 0

        -- Increment country count using atomic Redis Lua script
        local _, err_script = nauthilus_redis.redis_run_script(
                custom_pool, 
            "", 
            "IncrementAndExpire", 
            {country_key}, 
            {24 * 3600} -- Expire after 24 hours
        )
        nauthilus_util.if_error_raise(err_script)

        -- Get total countries using atomic Redis Lua script
        local countries_key = nauthilus_util.get_redis_key(request, "multilayer:global:countries")
        local _, err_script_countries = nauthilus_redis.redis_run_script(
                custom_pool, 
            "", 
            "AddToSetAndExpire", 
            {countries_key}, 
            {country_code, 24 * 3600} -- Expire after 24 hours
        )
        nauthilus_util.if_error_raise(err_script_countries)

        local total_countries = nauthilus_redis.redis_scard(custom_pool, countries_key) or 1

        -- If this country has a disproportionate number of attempts, mark it as suspicious
        if total_countries > 1 and country_count > (attempts / total_countries) * 2 then
            table.insert(suspicious_regions, country_code)
        end
    end

    metrics.suspicious_regions = suspicious_regions

    -- Store suspicious IPs
    metrics.suspicious_ips = {}

    -- If this is a failed authentication attempt, add the IP to suspicious IPs
    if not request.authenticated and client_ip and client_ip ~= "" then
        table.insert(metrics.suspicious_ips, client_ip)
    end

    -- Per-account step-up hint: if a step-up flag exists for this username,
    -- add the account temporarily to captcha/step-up set to help HTTP/OIDC flows.
    if username and username ~= "" then
        local stepup_key = nauthilus_util.get_redis_key(request, "acct:" .. nauthilus_keys.account_tag(username) .. username .. ":stepup")
        local required = nauthilus_redis.redis_hget(custom_pool, stepup_key, "required")
        if required == "true" then
            local args = {15 * 60} -- 15 minutes TTL
            table.insert(args, username)
            local _, err_script = nauthilus_redis.redis_run_script(
                custom_pool,
                "",
                "SAddMultiExpire",
                    { nauthilus_util.get_redis_key(request, "multilayer:global:captcha_accounts") },
                args
            )
            nauthilus_util.if_error_raise(err_script)
        end
    end

    -- Determine bootstrap/warm-up state to prevent global blast radius on first deployment
    local now_ts = timestamp
    local warmup_seconds = DYN_WARMUP_SECONDS
    local warmup_min_users = DYN_WARMUP_MIN_USERS
    local warmup_min_attempts = DYN_WARMUP_MIN_ATTEMPTS

    local first_seen_key = nauthilus_util.get_redis_key(request, "multilayer:bootstrap:first_seen_ts")
    local first_seen_val = nauthilus_redis.redis_get(custom_pool, first_seen_key)
    local first_seen_ts = tonumber(first_seen_val or "0") or 0
    if first_seen_ts == 0 then
        -- set first seen (permanent)
        local _, err_set = nauthilus_redis.redis_set(custom_pool, first_seen_key, tostring(now_ts))
        nauthilus_util.if_error_raise(err_set)
        first_seen_ts = now_ts
    end

    local warmed_up = ((now_ts - first_seen_ts) >= warmup_seconds) and (unique_users >= warmup_min_users) and (attempts >= warmup_min_attempts)

    -- Apply dynamic response based on threat level (with warm-up gating)
    if threat_level >= 0.9 and warmed_up then
        -- Severe threat: Implement strict measures
        apply_severe_measures(request, custom_pool, metrics)

        -- Log the response
        local severe_logs = {}
        severe_logs.caller = N .. ".lua"
        severe_logs.message = "Severe threat detected, implementing strict measures"
        severe_logs.threat_level = threat_level
        severe_logs.metrics = metrics

        nauthilus_util.log_warn(request, severe_logs)

        -- Add to custom log for monitoring
        nauthilus_builtin.custom_log_add(N .. "_threat_level", threat_level)
        nauthilus_builtin.custom_log_add(N .. "_response", "severe")
    elseif threat_level >= 0.7 then
        if warmed_up then
            -- High threat: Implement moderate measures
            apply_high_measures(request, custom_pool, metrics)

            -- Log the response
            local high_logs = {}
            high_logs.caller = N .. ".lua"
            high_logs.message = "High threat detected, implementing moderate measures"
            high_logs.threat_level = threat_level
            high_logs.metrics = metrics
            high_logs.warmup_gating = false

            nauthilus_util.log_warn(request, high_logs)

            -- Add to custom log for monitoring
            nauthilus_builtin.custom_log_add(N .. "_threat_level", threat_level)
            nauthilus_builtin.custom_log_add(N .. "_response", "high")
        else
            -- Cold-start gating: only light measures in warm-up window
            apply_moderate_measures(request, custom_pool, metrics)

            local gated_logs = {}
            gated_logs.caller = N .. ".lua"
            gated_logs.message = "High threat detected but warm-up gating active; applying light measures"
            gated_logs.threat_level = threat_level
            gated_logs.metrics = metrics
            gated_logs.warmup_gating = true
            gated_logs.warmup = {
                warmup_seconds = warmup_seconds,
                warmup_min_users = warmup_min_users,
                warmup_min_attempts = warmup_min_attempts,
                first_seen_ts = first_seen_ts,
                now_ts = now_ts,
                unique_users = unique_users,
                attempts = attempts
            }
            nauthilus_util.log_warn(request, gated_logs)

            nauthilus_builtin.custom_log_add(N .. "_threat_level", threat_level)
            nauthilus_builtin.custom_log_add(N .. "_response", "moderate")
        end
    elseif threat_level >= 0.5 then
        -- Moderate threat: Implement light measures
        apply_moderate_measures(request, custom_pool, metrics)

        -- Log the response
        local moderate_logs = {}
        moderate_logs.caller = N .. ".lua"
        moderate_logs.message = "Moderate threat detected, implementing light measures"
        moderate_logs.threat_level = threat_level
        moderate_logs.metrics = metrics

        nauthilus_util.log_warn(request, moderate_logs)

        -- Add to custom log for monitoring
        nauthilus_builtin.custom_log_add(N .. "_threat_level", threat_level)
        nauthilus_builtin.custom_log_add(N .. "_response", "moderate")
    else
        -- Low threat: No special measures needed
        -- Log the normal state
        local normal_logs = {}
        normal_logs.caller = N .. ".lua"
        normal_logs.message = "Normal operation, no special measures needed"
        normal_logs.threat_level = threat_level
        normal_logs.metrics = metrics

        nauthilus_util.log_info(request, normal_logs)

        -- Add to custom log for monitoring
        nauthilus_builtin.custom_log_add(N .. "_threat_level", threat_level)
        nauthilus_builtin.custom_log_add(N .. "_response", "normal")
    end

    -- Adaptive reset/hysteresis for monitoring_mode to avoid getting stuck in permanent monitoring
    local ok_threshold = MONITORING_OK_STREAK_MIN
    local ok_streak_key = nauthilus_util.get_redis_key(request, "multilayer:global:ok_streak")
    local attacked_accounts_key_reset = nauthilus_util.get_redis_key(request, "multilayer:distributed_attack:accounts")

    local function disable_monitoring_mode()
        local _, err_clear = nauthilus_redis.redis_run_script(
            custom_pool,
            "",
            "HSetMultiExpire",
                { nauthilus_util.get_redis_key(request, "multilayer:global:settings") },
            {
                0, -- Permanent
                "monitoring_mode", "false"
            }
        )
        nauthilus_util.if_error_raise(err_clear)

        local info_logs = {}
        info_logs.caller = N .. ".lua"
        info_logs.level = "info"
        info_logs.message = "Monitoring mode disabled after sustained normal activity"
        info_logs.ok_streak_required = ok_threshold
        nauthilus_util.print_result({ log_format = "json" }, info_logs)
        nauthilus_builtin.custom_log_add(N .. "_monitoring_reset", "true")
    end

    -- Update OK streak based on current threat assessment
    if threat_level < 0.3 then
        local streak_val = nauthilus_redis.redis_incr(custom_pool, ok_streak_key)
        local streak = tonumber(streak_val or "0") or 0
        -- ensure streak key does not grow unbounded in idle periods
        nauthilus_redis.redis_expire(custom_pool, ok_streak_key, 3600)

        if streak >= ok_threshold then
            -- Only disable monitoring if there are no currently attacked accounts
            local attacked_accounts = nauthilus_redis.redis_zrange(custom_pool, attacked_accounts_key_reset, 0, -1, "WITHSCORES") or {}
            local any_attacked = nauthilus_util.table_length(attacked_accounts)

            -- Require also that global ratios look benign to prevent flapping
            local benign_ips_per_user = (metrics.ips_per_user or 0) < 2
            local benign_unique_ips = (metrics.unique_ips or 0) < 50

            if any_attacked == 0 and benign_ips_per_user and benign_unique_ips then
                disable_monitoring_mode()
                -- reset streak after action
                nauthilus_redis.redis_del(custom_pool, ok_streak_key)
            end
        end
    else
        -- Elevated threat -> reset OK streak
        nauthilus_redis.redis_del(custom_pool, ok_streak_key)
    end

    -- Store the current threat level in Redis for other components to use using atomic Redis Lua script
    local _, err_script_settings = nauthilus_redis.redis_run_script(
            custom_pool, 
        "", 
        "HSetMultiExpire",
            { nauthilus_util.get_redis_key(request, "multilayer:global:settings") },
        {
            0, -- Permanent (no EXPIRE called by HSetMultiExpire)
            "threat_level", threat_level
        }
    )
    nauthilus_util.if_error_raise(err_script_settings)

    -- Enrich rt for downstream actions (e.g., telegram)
    do
        local rt = nauthilus_context.context_get("rt") or {}
        if type(rt) == "table" then
            -- Determine response string selected earlier via custom_log
            local response = "normal"
            -- Try to reflect thresholds
            if threat_level >= 0.9 then
                response = "severe"
            elseif threat_level >= 0.7 then
                -- warmed_up gating could have switched to moderate; best-effort use custom log hint not accessible here
                response = "high"
            elseif threat_level >= 0.5 then
                response = "moderate"
            end
            rt.dynamic_response = {
                threat_level = threat_level,
                response = response,
            }
            nauthilus_context.context_set("rt", rt)
        end
    end

    return nauthilus_builtin.ACTION_RESULT_OK
end
