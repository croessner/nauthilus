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

local template = require("template")

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
local function notify_administrators(subject, metrics)
    -- Basic toggle to disable alert emails entirely (defaults to enabled)
    local alerts_enabled_env = os.getenv("ADMIN_ALERTS_ENABLED")
    local alerts_enabled = true
    if alerts_enabled_env ~= nil and alerts_enabled_env ~= "" then
        alerts_enabled = nauthilus_util.toboolean(alerts_enabled_env)
    end

    -- Resolve Redis client for rate limiting
    local client = "default"
    local pool_name = os.getenv("CUSTOM_REDIS_POOL_NAME")
    if pool_name ~= nil and pool_name ~= "" then
        local err
        client, err = nauthilus_redis.get_redis_connection(pool_name)
        nauthilus_util.if_error_raise(err)
    end

    local now = os.time()

    -- Evidence-based gating and thresholds to reduce false positives
    local min_unique_ips = tonumber(os.getenv("ADMIN_ALERT_MIN_UNIQUE_IPS") or "100")
    local min_ips_per_user = tonumber(os.getenv("ADMIN_ALERT_MIN_IPS_PER_USER") or "2.5")
    local require_evidence = nauthilus_util.toboolean(os.getenv("ADMIN_ALERT_REQUIRE_EVIDENCE") or "false")

    local uniq_ips = tonumber(metrics.unique_ips or 0) or 0
    local ips_per_user = tonumber(metrics.ips_per_user or 0) or 0

    local suspicious_regions = (type(metrics.suspicious_regions) == "table") and metrics.suspicious_regions or {}
    local suspicious_ips = (type(metrics.suspicious_ips) == "table") and metrics.suspicious_ips or {}

    local has_evidence = (suspicious_regions and #suspicious_regions > 0) or (suspicious_ips and #suspicious_ips > 0)
    local passes_baseline = (ips_per_user >= min_ips_per_user) and (uniq_ips >= min_unique_ips)

    -- Cooldown window per subject to prevent alert storms
    local cooldown_sec = tonumber(os.getenv("ADMIN_ALERT_COOLDOWN_SECONDS") or "900")
    local gate_key = "ntc:alerts:last_sent:" .. subject
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
    notify_logs.level = should_notify and "warning" or "info"
    notify_logs.message = subject
    notify_logs.metrics = metrics
    notify_logs.timestamp = now
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

    nauthilus_util.print_result({ log_format = "json" }, notify_logs)

    if not should_notify then
        return
    end

    -- Mark send time (rate limit)
    nauthilus_redis.redis_set(client, gate_key, tostring(now), cooldown_sec)

    -- Send email notification
    -- Get SMTP configuration from environment variables
    local smtp_use_lmtp = os.getenv("SMTP_USE_LMTP")
    local smtp_server = os.getenv("SMTP_SERVER")
    local smtp_port = os.getenv("SMTP_PORT")
    local smtp_helo_name = os.getenv("SMTP_HELO_NAME")
    local smtp_tls = os.getenv("SMTP_TLS")
    local smtp_starttls = os.getenv("SMTP_STARTTLS")
    local smtp_username = os.getenv("SMTP_USERNAME")
    local smtp_password = os.getenv("SMTP_PASSWORD")
    local smtp_mail_from = os.getenv("SMTP_MAIL_FROM")

    -- Get admin email addresses from environment variable (comma-separated list)
    local admin_emails_str = os.getenv("ADMIN_EMAIL_ADDRESSES")
    if not admin_emails_str or admin_emails_str == "" then
        -- No admin emails configured, just log and return
        local error_logs = {}
        error_logs.caller = N .. ".lua"
        error_logs.level = "error"
        error_logs.message = "No admin email addresses configured for notifications"
        nauthilus_util.print_result({ log_format = "json" }, error_logs)
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
    local timestamp_str = os.date("%Y-%m-%d %H:%M:%S", now)

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
        error_logs.level = "error"
        error_logs.message = "Failed to initialize template engine"
        error_logs.error = err_tmpl
        nauthilus_util.print_result({ log_format = "json" }, error_logs)
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
        error_logs.level = "error"
        error_logs.message = "Failed to send admin notification email"
        error_logs.error = err_smtp
        nauthilus_util.print_result({ log_format = "json" }, error_logs)
    else
        local success_logs = {}
        success_logs.caller = N .. ".lua"
        success_logs.level = "info"
        success_logs.message = "Admin notification email sent successfully"
        success_logs.recipients = #admin_emails
        nauthilus_util.print_result({ log_format = "json" }, success_logs)
    end
end

-- Apply severe measures for high threat levels
local function apply_severe_measures(custom_pool, metrics)
    -- Enable global captcha using atomic Redis Lua script
    local _, err_script = nauthilus_redis.redis_run_script(
        custom_pool, 
        "", 
        "HSetMultiExpire", 
        {"ntc:multilayer:global:settings"}, 
        {
            3600, -- Enable for 1 hour
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
            {"ntc:multilayer:global:blocked_regions"}, 
            args
        )
        nauthilus_util.if_error_raise(err_script_regions)
    end


    -- Notify administrators
    notify_administrators("SEVERE THREAT ALERT", metrics)
end

-- Apply high measures for high threat levels
local function apply_high_measures(custom_pool, metrics)
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
            {"ntc:multilayer:global:captcha_accounts"}, 
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
            {"ntc:multilayer:global:rate_limited_ips"}, 
            args
        )
        nauthilus_util.if_error_raise(err_script)
    end

    -- Notify administrators
    notify_administrators("HIGH THREAT ALERT", metrics)
end

-- Apply moderate measures for moderate threat levels
local function apply_moderate_measures(custom_pool, metrics)
    -- Enable monitoring mode using atomic Redis Lua script
    local _, err_script = nauthilus_redis.redis_run_script(
        custom_pool, 
        "", 
        "HSetMultiExpire", 
        {"ntc:multilayer:global:settings"}, 
        {
            3600, -- Enable for 1 hour
            "monitoring_mode", "true"
        }
    )
    nauthilus_util.if_error_raise(err_script)

    -- Notify administrators
    notify_administrators("MODERATE THREAT ALERT", metrics)
end

function nauthilus_call_action(request)
    if request.no_auth then
        return
    end

    -- Get Redis connection
    local custom_pool = "default"
    local custom_pool_name =  os.getenv("CUSTOM_REDIS_POOL_NAME")
    if custom_pool_name ~= nil and  custom_pool_name ~= "" then
        local err_redis_client

        custom_pool, err_redis_client = nauthilus_redis.get_redis_connection(custom_pool_name)
        nauthilus_util.if_error_raise(err_redis_client)
    end

    -- Get current timestamp
    local timestamp = os.time()
    local username = request.username
    local client_ip = request.client_ip

    -- Calculate threat level based on various factors
    local threat_level = 0.0
    local metrics = {}

    -- Prepare Redis keys
    local attacked_accounts_key = "ntc:multilayer:distributed_attack:accounts"
    local current_metrics_key = "ntc:multilayer:global:current_metrics"

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
    local hour_key = os.date("%Y-%m-%d-%H", timestamp - 3600) -- Previous hour
    local historical_metrics_key = "ntc:multilayer:global:historical_metrics:" .. hour_key

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
        local country_key = "ntc:multilayer:global:country:" .. country_code
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
        local countries_key = "ntc:multilayer:global:countries"
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
        local stepup_key = "ntc:acct:" .. nauthilus_keys.account_tag(username) .. username .. ":stepup"
        local required = nauthilus_redis.redis_hget(custom_pool, stepup_key, "required")
        if required == "true" then
            local args = {15 * 60} -- 15 minutes TTL
            table.insert(args, username)
            local _, err_script = nauthilus_redis.redis_run_script(
                custom_pool,
                "",
                "SAddMultiExpire",
                {"ntc:multilayer:global:captcha_accounts"},
                args
            )
            nauthilus_util.if_error_raise(err_script)
        end
    end

    -- Determine bootstrap/warm-up state to prevent global blast radius on first deployment
    local now_ts = timestamp
    local warmup_seconds = tonumber(os.getenv("DYNAMIC_RESPONSE_WARMUP_SECONDS") or "3600")
    local warmup_min_users = tonumber(os.getenv("DYNAMIC_RESPONSE_WARMUP_MIN_USERS") or "1000")
    local warmup_min_attempts = tonumber(os.getenv("DYNAMIC_RESPONSE_WARMUP_MIN_ATTEMPTS") or "10000")

    local first_seen_key = "ntc:multilayer:bootstrap:first_seen_ts"
    local first_seen_val = nauthilus_redis.redis_get(custom_pool, first_seen_key)
    local first_seen_ts = tonumber(first_seen_val or "0") or 0
    if first_seen_ts == 0 then
        -- set first seen with TTL 30d (best-effort; not strictly atomic)
        local _, err_set = nauthilus_redis.redis_set(custom_pool, first_seen_key, tostring(now_ts), 30 * 24 * 3600)
        nauthilus_util.if_error_raise(err_set)
        first_seen_ts = now_ts
    end

    local warmed_up = ((now_ts - first_seen_ts) >= warmup_seconds) and (unique_users >= warmup_min_users) and (attempts >= warmup_min_attempts)

    -- Apply dynamic response based on threat level (with warm-up gating)
    if threat_level >= 0.9 and warmed_up then
        -- Severe threat: Implement strict measures
        apply_severe_measures(custom_pool, metrics)

        -- Log the response
        local severe_logs = {}
        severe_logs.caller = N .. ".lua"
        severe_logs.level = "warning"
        severe_logs.message = "Severe threat detected, implementing strict measures"
        severe_logs.threat_level = threat_level
        severe_logs.metrics = metrics

        nauthilus_util.print_result({ log_format = "json" }, severe_logs)

        -- Add to custom log for monitoring
        nauthilus_builtin.custom_log_add(N .. "_threat_level", threat_level)
        nauthilus_builtin.custom_log_add(N .. "_response", "severe")
    elseif threat_level >= 0.7 then
        if warmed_up then
            -- High threat: Implement moderate measures
            apply_high_measures(custom_pool, metrics)

            -- Log the response
            local high_logs = {}
            high_logs.caller = N .. ".lua"
            high_logs.level = "warning"
            high_logs.message = "High threat detected, implementing moderate measures"
            high_logs.threat_level = threat_level
            high_logs.metrics = metrics
            high_logs.warmup_gating = false

            nauthilus_util.print_result({ log_format = "json" }, high_logs)

            -- Add to custom log for monitoring
            nauthilus_builtin.custom_log_add(N .. "_threat_level", threat_level)
            nauthilus_builtin.custom_log_add(N .. "_response", "high")
        else
            -- Cold-start gating: only light measures in warm-up window
            apply_moderate_measures(custom_pool, metrics)

            local gated_logs = {}
            gated_logs.caller = N .. ".lua"
            gated_logs.level = "warning"
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
            nauthilus_util.print_result({ log_format = "json" }, gated_logs)

            nauthilus_builtin.custom_log_add(N .. "_threat_level", threat_level)
            nauthilus_builtin.custom_log_add(N .. "_response", "moderate")
        end
    elseif threat_level >= 0.5 then
        -- Moderate threat: Implement light measures
        apply_moderate_measures(custom_pool, metrics)

        -- Log the response
        local moderate_logs = {}
        moderate_logs.caller = N .. ".lua"
        moderate_logs.level = "warning"
        moderate_logs.message = "Moderate threat detected, implementing light measures"
        moderate_logs.threat_level = threat_level
        moderate_logs.metrics = metrics

        nauthilus_util.print_result({ log_format = "json" }, moderate_logs)

        -- Add to custom log for monitoring
        nauthilus_builtin.custom_log_add(N .. "_threat_level", threat_level)
        nauthilus_builtin.custom_log_add(N .. "_response", "moderate")
    else
        -- Low threat: No special measures needed
        -- Log the normal state
        local normal_logs = {}
        normal_logs.caller = N .. ".lua"
        normal_logs.level = "info"
        normal_logs.message = "Normal operation, no special measures needed"
        normal_logs.threat_level = threat_level
        normal_logs.metrics = metrics

        nauthilus_util.print_result({ log_format = "json" }, normal_logs)

        -- Add to custom log for monitoring
        nauthilus_builtin.custom_log_add(N .. "_threat_level", threat_level)
        nauthilus_builtin.custom_log_add(N .. "_response", "normal")
    end

    -- Adaptive reset/hysteresis for monitoring_mode to avoid getting stuck in permanent monitoring
    local ok_threshold = tonumber(os.getenv("MONITORING_OK_STREAK_MIN") or "10")
    local ok_streak_key = "ntc:multilayer:global:ok_streak"
    local attacked_accounts_key = "ntc:multilayer:distributed_attack:accounts"

    local function disable_monitoring_mode()
        local _, err_clear = nauthilus_redis.redis_run_script(
            custom_pool,
            "",
            "HSetMultiExpire",
            {"ntc:multilayer:global:settings"},
            {
                3600, -- keep visibility for 1h, but set to false
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
            local attacked_accounts = nauthilus_redis.redis_zrange(custom_pool, attacked_accounts_key, 0, -1, "WITHSCORES") or {}
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
    local _, err_script = nauthilus_redis.redis_run_script(
            custom_pool, 
        "", 
        "HSetMultiExpire", 
        {"ntc:multilayer:global:settings"}, 
        {
            3600, -- Expire after 1 hour
            "threat_level", threat_level
        }
    )
    nauthilus_util.if_error_raise(err_script)

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
