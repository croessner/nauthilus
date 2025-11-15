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

-- Phase 3: Automated per-account protection mode and protocol-agnostic backoff
-- Implements protection mode decisions based on long-window account metrics and
-- account-centric attack flags. Applies progressive backoff (sleep) and, for
-- failing authentications, can return a temporary rejection via filter semantics.
-- For HTTP/OIDC, we set a Redis flag to allow a frontend to enforce Step-Up/PoW.
--
-- Keys used:
--  - ntc:acct:<username>:longwindow (HSET by account_longwindow_metrics.lua)
--  - ntc:multilayer:distributed_attack:accounts (ZSET by account_centric_monitoring.lua)
--  - ntc:acct:<username>:protection (HASH: active, reason, backoff_level, until_ts)
--  - ntc:acct:<username>:stepup (HASH: required=true, reason, until_ts)
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

local nauthilus_redis = require("nauthilus_redis")
local nauthilus_prometheus = require("nauthilus_prometheus")
local nauthilus_http_response = require("nauthilus_http_response")
local nauthilus_cache = require("nauthilus_cache")
local nauthilus_context = require("nauthilus_context")

local time = require("time")

-- env helpers
local function getenv_num(name, def)
    local v = tonumber(os.getenv(name) or "")
    if v == nil then return def end
    return v
end

local THRESH_UNIQ24 = getenv_num("PROTECT_THRESH_UNIQ24", 12)
local THRESH_UNIQ7D = getenv_num("PROTECT_THRESH_UNIQ7D", 30)
local THRESH_FAIL24 = getenv_num("PROTECT_THRESH_FAIL24", 7)
local THRESH_FAIL7D = getenv_num("PROTECT_THRESH_FAIL7D", 15)
local BACKOFF_MIN_MS = getenv_num("PROTECT_BACKOFF_MIN_MS", 150)
local BACKOFF_MAX_MS = getenv_num("PROTECT_BACKOFF_MAX_MS", 1000)
local BACKOFF_MAX_LEVEL = getenv_num("PROTECT_BACKOFF_MAX_LEVEL", 5)
local MODE_TTL = getenv_num("PROTECT_MODE_TTL_SEC", 3600)

local function clamp(v, lo, hi)
    if v < lo then return lo end
    if v > hi then return hi end
    return v
end

-- Env switch: if false or unset (default), do not reject in protection mode (dry-run)
local function protect_enforce_reject()
    local v = os.getenv("PROTECT_ENFORCE_REJECT")
    if v == nil or v == "" then return false end
    return nauthilus_util.toboolean(v)
end

local function get_redis_client()
    local client = "default"
    local pool_name = os.getenv("CUSTOM_REDIS_POOL_NAME")
    if pool_name ~= nil and pool_name ~= "" then
        local err
        client, err = nauthilus_redis.get_redis_connection(pool_name)
        nauthilus_util.if_error_raise(err)
    end
    return client
end

local function compute_under_protection(client, username)
    -- Check short-lived in-process cache first
    local ckey = "prot:" .. (username or "")
    local cached = nauthilus_cache.cache_get(ckey)
    if cached and type(cached) == "table" then
        return cached.under, cached.metrics
    end

    local key = "ntc:acct:" .. username .. ":longwindow"
    -- Pipeline the related reads to minimize latency
    local cmds = {
        {"hget", key, "uniq_ips_24h"},
        {"hget", key, "uniq_ips_7d"},
        {"hget", key, "fails_24h"},
        {"hget", key, "fails_7d"},
        {"zscore", "ntc:multilayer:distributed_attack:accounts", username},
    }
    local res, err = nauthilus_redis.redis_pipeline(client, "read", cmds)
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
    local attacked_val = val(5)
    local attacked = (attacked_val ~= nil and attacked_val ~= false and attacked_val ~= "")

    local hits = {}
    if uniq24 >= THRESH_UNIQ24 then table.insert(hits, "uniq24") end
    if uniq7d >= THRESH_UNIQ7D then table.insert(hits, "uniq7d") end
    if fail24 >= THRESH_FAIL24 then table.insert(hits, "fail24") end
    if fail7d >= THRESH_FAIL7D then table.insert(hits, "fail7d") end
    if attacked then table.insert(hits, "attacked") end

    local under = (#hits > 0)

    local metrics = {
        uniq24 = uniq24, uniq7d = uniq7d,
        fail24 = fail24, fail7d = fail7d,
        attacked = attacked,
        hits = hits
    }

    -- Cache result briefly (5s) to smooth spikes while keeping decisions fresh
    nauthilus_cache.cache_set(ckey, { under = under, metrics = metrics }, 5)

    return under, metrics
end

local function record_protection_state(client, username, reason, backoff_level, ttl)
    local now = os.time()
    local until_ts = now + ttl
    local _, err = nauthilus_redis.redis_run_script(
        client,
        "",
        "HSetMultiExpire",
        {"ntc:acct:" .. username .. ":protection"},
        {
            ttl,
            "active", "true",
            "reason", reason,
            "backoff_level", backoff_level,
            "until_ts", until_ts,
            "updated", now
        }
    )
    nauthilus_util.if_error_raise(err)

    -- Maintain a set of accounts currently in protection mode for fast metrics
    local _, err2 = nauthilus_redis.redis_run_script(
        client,
        "",
        "SAddMultiExpire",
        {"ntc:acct:protection_active"},
        {ttl, username}
    )
    nauthilus_util.if_error_raise(err2)
end

local function set_stepup_required(client, username, reason, ttl)
    local now = os.time()
    local until_ts = now + ttl
    local _, err = nauthilus_redis.redis_run_script(
        client,
        "",
        "HSetMultiExpire",
        {"ntc:acct:" .. username .. ":stepup"},
        {
            ttl,
            "required", "true",
            "reason", reason,
            "until_ts", until_ts,
            "updated", now
        }
    )
    nauthilus_util.if_error_raise(err)

    -- Increment Prometheus counter for Step-Up hints
    nauthilus_prometheus.increment_counter("security_stepup_challenges_issued_total", { })
end

function nauthilus_call_filter(request)
    if request.no_auth then
        return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
    end

    local username = request.username or request.account
    local ip = request.client_ip
    local now = os.time()

    if not username or username == "" then
        return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
    end

    local client = get_redis_client()

    -- Evaluate protection state
    local under, m = compute_under_protection(client, username)

    local backoff_level = 0
    local applied_ms = 0

    if under then
        -- Compute/upgrade backoff level from existing state if present
        local prot_key = "ntc:acct:" .. username .. ":protection"
        backoff_level = tonumber(nauthilus_redis.redis_hget(client, prot_key, "backoff_level") or "0") or 0
        backoff_level = clamp(backoff_level + 1, 1, BACKOFF_MAX_LEVEL)

        -- Calculate delay (progressive)
        local base = BACKOFF_MIN_MS * math.pow(2, backoff_level - 1)
        local jitter = math.random(0, math.floor(BACKOFF_MIN_MS / 2))
        applied_ms = clamp(math.floor(base + jitter), BACKOFF_MIN_MS, BACKOFF_MAX_MS)

        -- Sleep to add backoff
        time.sleep(applied_ms / 1000.0)

        -- Record protection mode
        record_protection_state(client, username, table.concat(m.hits, ","), backoff_level, MODE_TTL)

        -- Count a slow-attack suspicion
        nauthilus_prometheus.increment_counter("security_slow_attack_suspicions_total", { })

        -- For HTTP/OIDC flows: we cannot detect protocol reliably here; set step-up hint flag
        set_stepup_required(client, username, "protection:" .. table.concat(m.hits, ","), MODE_TTL)

        -- Expose a response header so frontends (e.g., Keycloak) can enforce a CAPTCHA/Step-Up
        -- Header indicates that protection is required for this account
        pcall(function()
            nauthilus_http_response.set_http_response_header("X-Nauthilus-Protection", "stepup")
            nauthilus_http_response.set_http_response_header("X-Nauthilus-Protection-Reason", table.concat(m.hits, ","))
        end)

        -- Logging
        local logs = {
            caller = N .. ".lua",
            level = "warning",
            message = "Protection mode active",
            username = username,
            client_ip = ip,
            uniq_ips_24h = m.uniq24,
            uniq_ips_7d = m.uniq7d,
            fails_24h = m.fail24,
            fails_7d = m.fail7d,
            attacked = m.attacked,
            hits = m.hits,
            backoff_level = backoff_level,
            applied_delay_ms = applied_ms,
            ts = now,
        }
        nauthilus_util.print_result({ log_format = "json" }, logs)

        -- Enrich rt so downstream actions (e.g., telegram) can include protection info
        do
            local rt = nauthilus_context.context_get("rt") or {}
            if type(rt) == "table" then
                rt.account_protection = {
                    active = true,
                    reason = table.concat(m.hits, ","),
                    backoff_level = backoff_level,
                    delay_ms = applied_ms,
                    ts = now,
                }
                rt.filter_account_protection_mode = true
                nauthilus_context.context_set("rt", rt)
            end
        end

        -- Decide filter result: If authentication failed, we either reject (enforcement) or allow (dry-run)
        if not request.authenticated then
            if protect_enforce_reject() then
                nauthilus_builtin.status_message_set("Temporary protection active")
                return nauthilus_builtin.FILTER_REJECT, nauthilus_builtin.FILTER_RESULT_OK
            else
                -- Dry-run mode: expose header for frontends and do not block here
                pcall(function()
                    nauthilus_http_response.set_http_response_header("X-Nauthilus-Protection-Mode", "dry-run")
                end)
                return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
            end
        end
    end

    -- Default accept
    return nauthilus_builtin.FILTER_ACCEPT, nauthilus_builtin.FILTER_RESULT_OK
end
