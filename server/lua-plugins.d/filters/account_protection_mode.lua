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

-- Phase 3: Automated per-account protection mode and protocol-aware backoff
-- Implements protection mode decisions based on long-window account metrics and
-- account-centric attack flags. Applies progressive backoff (sleep) and, for
-- failing authentications, can return a temporary rejection via filter semantics.
-- For HTTP/OIDC, we set a Redis flag to allow a frontend to enforce Step-Up/PoW.
--
-- Keys used:
--  - ntc:acct:<username>:proto:<protocol>:longwindow (HSET by account_longwindow_metrics.lua)
--  - ntc:multilayer:distributed_attack:accounts:proto:<protocol> (ZSET by account_centric_monitoring.lua)
--  - ntc:acct:<username>:proto:<protocol>:protection (HASH: active, reason, backoff_level, until_ts)
--  - ntc:acct:<username>:proto:<protocol>:stepup (HASH: required=true, reason, until_ts)
--  - ntc:acct:protection_active:proto:<protocol> (SET: active usernames)
--
-- Env thresholds (defaults conservative):
--  - PROTECT_THRESH_UNIQ24 default 12
--  - PROTECT_THRESH_UNIQ7D default 30
--  - PROTECT_THRESH_FAIL24 default 7
--  - PROTECT_THRESH_FAIL7D default 15
--  - PROTECT_BACKOFF_MIN_MS default 150
--  - PROTECT_BACKOFF_MAX_MS default 1000
--  - PROTECT_BACKOFF_MAX_LEVEL default 5
--  - PROTECT_MODE_TTL_SEC default 3600 (1h)
--  - CUSTOM_REDIS_POOL_NAME optional pool

local N = "account_protection_mode"

local nauthilus_util = require("nauthilus_util")
local nauthilus_keys = require("nauthilus_keys")

local nauthilus_redis = require("nauthilus_redis")
local nauthilus_prometheus = require("nauthilus_prometheus")
local nauthilus_http_response = require("nauthilus_http_response")
local nauthilus_otel = require("nauthilus_opentelemetry")
local nauthilus_cache = require("nauthilus_cache")
local nauthilus_context = require("nauthilus_context")

local time = require("time")

-- env helpers
local function getenv_num(name, def)
    local v = tonumber(nauthilus_util.getenv(name, "") or "")
    if v == nil then return def end
    return v
end

local function protocol_segment(request)
    local protocol = request.protocol
    if protocol == nil or protocol == "" then
        return "unknown"
    end
    return protocol
end

local THRESH_UNIQ24 = getenv_num("PROTECT_THRESH_UNIQ24", 12)
local THRESH_UNIQ7D = getenv_num("PROTECT_THRESH_UNIQ7D", 30)
local THRESH_FAIL24 = getenv_num("PROTECT_THRESH_FAIL24", 7)
local THRESH_FAIL7D = getenv_num("PROTECT_THRESH_FAIL7D", 15)
local BACKOFF_MIN_MS = getenv_num("PROTECT_BACKOFF_MIN_MS", 150)
local BACKOFF_MAX_MS = getenv_num("PROTECT_BACKOFF_MAX_MS", 1000)
local BACKOFF_MAX_LEVEL = getenv_num("PROTECT_BACKOFF_MAX_LEVEL", 5)
local MODE_TTL = getenv_num("PROTECT_MODE_TTL_SEC", 3600)
local CUSTOM_REDIS_POOL = nauthilus_util.getenv("CUSTOM_REDIS_POOL_NAME", "default")
local ENFORCE_REJECT = nauthilus_util.toboolean(nauthilus_util.getenv("PROTECT_ENFORCE_REJECT", "false"))

local function clamp(v, lo, hi)
    if v < lo then return lo end
    if v > hi then return hi end
    return v
end

local function compute_under_protection(pool, username, request)
    -- Check short-lived in-process cache first
    local protocol = protocol_segment(request)

    local ckey = "prot:" .. (username or "") .. ":proto:" .. protocol
    local cached = nauthilus_cache.cache_get(ckey)
    if cached and type(cached) == "table" then
        return cached.under, cached.metrics, cached.backoff_level, true
    end

    local tag = nauthilus_keys.account_tag(username)
    local lw_key = nauthilus_util.get_redis_key(request, "acct:" .. tag .. username .. ":proto:" .. protocol .. ":longwindow")
    local prot_key = nauthilus_util.get_redis_key(request, "acct:" .. tag .. username .. ":proto:" .. protocol .. ":protection")

    -- Pipeline the related user-specific reads (same slot)
    local cmds = {
        { "hget", lw_key, "uniq_ips_24h" },
        { "hget", lw_key, "uniq_ips_7d" },
        { "hget", lw_key, "fails_24h" },
        { "hget", lw_key, "fails_7d" },
        { "hget", prot_key, "backoff_level" },
    }
    local res, err = nauthilus_redis.redis_pipeline(pool, "read", cmds)
    nauthilus_util.if_error_raise(err)

    -- Normalize structured pipeline results
    if type(res) ~= "table" then res = {} end
    local function val(i)
        local e = res[i]
        if type(e) ~= "table" then return nil end
        if e.ok == false then return nil end
        return e.value
    end

    local uniq24 = tonumber(val(1) or "0") or 0
    local uniq7d = tonumber(val(2) or "0") or 0
    local fail24 = tonumber(val(3) or "0") or 0
    local fail7d = tonumber(val(4) or "0") or 0
    local backoff_level = tonumber(val(5) or "0") or 0

    -- Separate call for the global attack set to avoid cross-slot pipeline issues
    local attacked_val, err_a = nauthilus_redis.redis_zscore(pool, nauthilus_util.get_redis_key(request, "multilayer:distributed_attack:accounts:proto:" .. protocol), username)
    nauthilus_util.if_error_raise(err_a)
    local attacked = (attacked_val ~= nil and attacked_val ~= false and attacked_val ~= "")

    local hits = {}
    if uniq24 >= THRESH_UNIQ24 then table.insert(hits, "uniq24") end
    if uniq7d >= THRESH_UNIQ7D then table.insert(hits, "uniq7d") end
    if fail24 >= THRESH_FAIL24 then table.insert(hits, "fail24") end
    if fail7d >= THRESH_FAIL7D then table.insert(hits, "fail7d") end
    if attacked then table.insert(hits, "attacked") end

    local under = (#hits > 0)

    local metrics = {
        uniq24 = uniq24,
        uniq7d = uniq7d,
        fail24 = fail24,
        fail7d = fail7d,
        attacked = attacked,
        hits = hits
    }

    -- Cache result briefly (5s) to smooth spikes while keeping decisions fresh
    nauthilus_cache.cache_set(ckey, { under = under, metrics = metrics, backoff_level = backoff_level }, 5)

    return under, metrics, backoff_level, false
end

function nauthilus_call_filter(request)
    if request.no_auth then
        return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
    end

    local username = request.username or request.account
    if not username or username == "" then
        return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
    end

    local ip = request.client_ip
    local now = time.unix()
    local protocol = protocol_segment(request)

    -- Evaluate protection state
    local under, m, current_backoff, from_cache = compute_under_protection(CUSTOM_REDIS_POOL, username, request)

    if under then
        local backoff_level = clamp(current_backoff + 1, 1, BACKOFF_MAX_LEVEL)

        -- Calculate delay (progressive)
        local base = BACKOFF_MIN_MS * math.pow(2, backoff_level - 1)
        local jitter = math.random(0, math.floor(BACKOFF_MIN_MS / 2))
        local applied_ms = clamp(math.floor(base + jitter), BACKOFF_MIN_MS, BACKOFF_MAX_MS)

        -- Sleep to add backoff
        if nauthilus_otel and nauthilus_otel.is_enabled() then
            local tr = nauthilus_otel.tracer("nauthilus/lua/account_protection_mode")
            tr:with_span("account_protection_mode.backoff", function(span)
                span:set_attributes({
                    username = username or "",
                    backoff_level = backoff_level,
                    applied_delay_ms = applied_ms,
                })
                time.sleep(applied_ms / 1000.0)
            end)
        else
            time.sleep(applied_ms / 1000.0)
        end

        local tag = nauthilus_keys.account_tag(username)
        local hits_str = table.concat(m.hits, ",")

        -- Record state and hints in Redis only if not from cache, to save write-RTTs
        if not from_cache then
            local until_ts = now + MODE_TTL
            local pipe_cmds = {
                {
                    "run_script", "", "HSetMultiExpire", { nauthilus_util.get_redis_key(request, "acct:" .. tag .. username .. ":proto:" .. protocol .. ":protection") },
                    {
                        MODE_TTL,
                        "active", "true",
                        "reason", hits_str,
                        "backoff_level", backoff_level,
                        "until_ts", until_ts,
                        "updated", now
                    }
                },
                {
                    "run_script", "", "SAddMultiExpire", { nauthilus_util.get_redis_key(request, "acct:protection_active:proto:" .. protocol) },
                    { MODE_TTL, username }
                },
                {
                    "run_script", "", "HSetMultiExpire", { nauthilus_util.get_redis_key(request, "acct:" .. tag .. username .. ":proto:" .. protocol .. ":stepup") },
                    {
                        MODE_TTL,
                        "required", "true",
                        "reason", "protection:" .. hits_str,
                        "until_ts", until_ts,
                        "updated", now
                    }
                }
            }
            local _, err = nauthilus_redis.redis_pipeline(CUSTOM_REDIS_POOL, "write", pipe_cmds)
            nauthilus_util.if_error_raise(err)
        end

        -- Count a slow-attack suspicion
        nauthilus_prometheus.increment_counter("security_slow_attack_suspicions_total", {})
        nauthilus_prometheus.increment_counter("security_stepup_challenges_issued_total", {})

        -- Expose a response header so frontends (e.g., Keycloak) can enforce a CAPTCHA/Step-Up
        pcall(function()
            nauthilus_http_response.set_http_response_header("X-Nauthilus-Protection", "stepup")
            nauthilus_http_response.set_http_response_header("X-Nauthilus-Protection-Reason", hits_str)
        end)

        -- Logging
        local logs = {
            caller = N .. ".lua",
            message = "Protection mode active",
            username = username,
            protocol = protocol,
            client_ip = ip,
            uniq_ips_24h = m.uniq24,
            uniq_ips_7d = m.uniq7d,
            fails_24h = m.fail24,
            fails_7d = m.fail7d,
            attacked = m.attacked,
            hits = m.hits,
            backoff_level = backoff_level,
            applied_delay_ms = applied_ms,
        }
        nauthilus_util.log_warn(request, logs)

        -- Enrich rt so downstream actions (e.g., telegram) can include protection info
        local rt = nauthilus_context.context_get("rt") or {}
        if type(rt) == "table" then
            rt.account_protection = {
                active = true,
                reason = hits_str,
                backoff_level = backoff_level,
                delay_ms = applied_ms,
                ts = now,
            }
            rt.filter_account_protection_mode = true
            nauthilus_context.context_set("rt", rt)
        end

        -- Decide filter result: If authentication failed, we either reject (enforcement) or allow (dry-run)
        if not request.authenticated then
            if ENFORCE_REJECT then
                nauthilus_builtin.status_message_set("Temporary protection active")
                return nauthilus_builtin.FILTER_REJECT, nauthilus_builtin.FILTER_RESULT_OK
            else
                -- Dry-run mode: expose header for frontends and do not block here
                pcall(function()
                    nauthilus_http_response.set_http_response_header("X-Nauthilus-Protection-Mode", "dry-run")
                end)
            end
        end
    end

    -- Default accept
    return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
end
