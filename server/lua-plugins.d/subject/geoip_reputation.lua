-- Copyright (C) 2026 Christian Rößner
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

-- Redis-backed GeoIP reputation learner.
--
-- The source records successful and failed authentication outcomes per IP, ASN,
-- country, and ASN country, then emits bounded reputation scores for policy use.

local N = "geoip_reputation"

local nauthilus_util = require("nauthilus_util")
local nauthilus_redis = require("nauthilus_redis")
local nauthilus_context = require("nauthilus_context")
local policy_facts = require("nauthilus_policy_facts")
local geoip_bridge = require("nauthilus_geoip_bridge")

local CUSTOM_REDIS_POOL = nauthilus_util.getenv("CUSTOM_REDIS_POOL_NAME", "default")

local function getenv_num(name, default_value)
    local value = tonumber(nauthilus_util.getenv(name, "") or "")
    if value == nil then
        return default_value
    end

    return value
end

local ALPHA = getenv_num("GEOIP_REPUTATION_ALPHA", 2)
local SATURATION = getenv_num("GEOIP_REPUTATION_SATURATION", 20)
local TEMPERATURE = getenv_num("GEOIP_REPUTATION_TEMPERATURE", 1.5)
local TTL_SECONDS = getenv_num("GEOIP_REPUTATION_TTL_SEC", 2592000)
local SUSPICIOUS_THRESHOLD = getenv_num("GEOIP_REPUTATION_SUSPICIOUS_THRESHOLD", 0.65)
local TRUSTED_THRESHOLD = getenv_num("GEOIP_REPUTATION_TRUSTED_THRESHOLD", 0.65)

local ENTITY_WEIGHTS = {
    ip = 4,
    asn = 2,
    country = 1,
    asn_country = 1.5,
}

local function safe_tanh(value)
    if math.tanh ~= nil then
        return math.tanh(value)
    end

    if value > 20 then
        return 1
    end
    if value < -20 then
        return -1
    end

    local exp_value = math.exp(2 * value)

    return (exp_value - 1) / (exp_value + 1)
end

local function clamp_score(value)
    if value ~= value then
        return 0
    end
    if value > 1 then
        return 1
    end
    if value < -1 then
        return -1
    end

    return value
end

local function score_from_counts(successes, failures)
    local success_count = tonumber(successes or 0) or 0
    local failure_count = tonumber(failures or 0) or 0
    local total = success_count + failure_count

    if total <= 0 or SATURATION <= 0 or TEMPERATURE <= 0 then
        return 0, 0
    end

    local log_odds = math.log((failure_count + ALPHA) / (success_count + ALPHA))
    local confidence = 1 - math.exp(-total / SATURATION)

    return clamp_score(safe_tanh(log_odds / TEMPERATURE) * confidence), total
end

local function normalize_non_empty(value)
    if value == nil then
        return nil
    end

    local text = tostring(value)
    if text == "" then
        return nil
    end

    return text
end

local function add_entity(entities, seen, request, kind, value)
    local entity_value = normalize_non_empty(value)
    if entity_value == nil then
        return
    end

    local identity = kind .. ":" .. entity_value
    if seen[identity] then
        return
    end

    seen[identity] = true
    table.insert(entities, {
        kind = kind,
        value = entity_value,
        key = nauthilus_util.get_redis_key(request, "geoip:reputation:" .. identity),
    })
end

local function collect_entities(request, geoip_info)
    local entities = {}
    local seen = {}

    add_entity(entities, seen, request, "ip", request.client_ip)

    if type(geoip_info) == "table" then
        add_entity(entities, seen, request, "asn", geoip_info.asn)
        add_entity(entities, seen, request, "country", geoip_info.current_country_code or geoip_info.native_country_iso)
        add_entity(entities, seen, request, "asn_country", geoip_info.asn_country_iso)
    end

    return entities
end

local function resolve_redis_pool()
    if CUSTOM_REDIS_POOL == "default" then
        return "default"
    end

    local pool, err = nauthilus_redis.get_redis_connection(CUSTOM_REDIS_POOL)
    nauthilus_util.if_error_raise(err)

    return pool
end

local function update_entity_counts(pool, entities, outcome)
    local commands = {}

    for _, entity in ipairs(entities) do
        table.insert(commands, { "hincrby", entity.key, outcome, 1 })
        table.insert(commands, { "expire", entity.key, TTL_SECONDS })
    end

    if #commands == 0 then
        return
    end

    local _, err = nauthilus_redis.redis_pipeline(pool, "write", commands)
    nauthilus_util.if_error_raise(err)
end

local function read_entity_counts(pool, entities)
    local commands = {}

    for _, entity in ipairs(entities) do
        table.insert(commands, { "hgetall", entity.key })
    end

    if #commands == 0 then
        return {}
    end

    local results, err = nauthilus_redis.redis_pipeline(pool, "read", commands)
    nauthilus_util.if_error_raise(err)

    return results or {}
end

local function hash_result_value(results, index)
    local item = results[index]
    if type(item) ~= "table" or item.ok == false or type(item.value) ~= "table" then
        return {}
    end

    return item.value
end

local function compute_entity_scores(entities, results)
    local scores = {}
    local samples = {}
    local positive_score = 0
    local negative_score = 0
    local weighted_total = 0
    local weight_sum = 0
    local max_samples = 0

    for index, entity in ipairs(entities) do
        local counts = hash_result_value(results, index)
        local score, total = score_from_counts(counts.success, counts.failure)

        scores[entity.kind] = score
        samples[entity.kind] = total

        if score > positive_score then
            positive_score = score
        end
        if -score > negative_score then
            negative_score = -score
        end
        if total > max_samples then
            max_samples = total
        end

        local weight = ENTITY_WEIGHTS[entity.kind] or 1
        weighted_total = weighted_total + (score * weight)
        weight_sum = weight_sum + weight
    end

    local aggregate_score = 0
    if weight_sum > 0 then
        aggregate_score = clamp_score(weighted_total / weight_sum)
    end

    return scores, samples, aggregate_score, positive_score, negative_score, max_samples
end

local function decision_from_scores(positive_score, negative_score)
    if positive_score >= SUSPICIOUS_THRESHOLD then
        return "suspicious"
    end
    if negative_score >= TRUSTED_THRESHOLD and positive_score < SUSPICIOUS_THRESHOLD then
        return "trusted"
    end

    return "neutral"
end

local function emit_reputation(scores, aggregate_score, positive_score, negative_score, max_samples, decision)
    policy_facts.emit_many(N, {
        score = aggregate_score,
        positive_score = positive_score,
        negative_score = negative_score,
        ip_score = scores.ip or 0,
        asn_score = scores.asn or 0,
        country_score = scores.country or 0,
        asn_country_score = scores.asn_country or 0,
        samples = max_samples,
        decision = decision,
    })
end

local function store_runtime_reputation(scores, aggregate_score, positive_score, negative_score, max_samples, decision)
    local rt = nauthilus_context.context_get("rt") or {}
    if type(rt) ~= "table" then
        rt = {}
    end

    rt.geoip_reputation = {
        source = "redis",
        score = aggregate_score,
        positive_score = positive_score,
        negative_score = negative_score,
        ip_score = scores.ip or 0,
        asn_score = scores.asn or 0,
        country_score = scores.country or 0,
        asn_country_score = scores.asn_country or 0,
        samples = max_samples,
        decision = decision,
    }

    nauthilus_context.context_set("rt", rt)
end

function nauthilus_call_subject(request)
    if request.no_auth then
        return nauthilus_builtin.SUBJECT_ACCEPT, nauthilus_builtin.SUBJECT_RESULT_OK
    end

    local geoip_info = geoip_bridge.attach()
    local entities = collect_entities(request, geoip_info)

    if #entities == 0 then
        return nauthilus_builtin.SUBJECT_ACCEPT, nauthilus_builtin.SUBJECT_RESULT_OK
    end

    local outcome = "failure"
    if request.authenticated == true then
        outcome = "success"
    end

    local pool = resolve_redis_pool()
    update_entity_counts(pool, entities, outcome)

    local results = read_entity_counts(pool, entities)
    local scores, _, aggregate_score, positive_score, negative_score, max_samples = compute_entity_scores(entities, results)
    local decision = decision_from_scores(positive_score, negative_score)

    emit_reputation(scores, aggregate_score, positive_score, negative_score, max_samples, decision)
    store_runtime_reputation(scores, aggregate_score, positive_score, negative_score, max_samples, decision)

    nauthilus_util.log_info(request, {
        caller = N .. ".lua",
        message = "GeoIP reputation updated",
        outcome = outcome,
        score = aggregate_score,
        positive_score = positive_score,
        negative_score = negative_score,
        decision = decision,
        samples = max_samples,
    })

    return nauthilus_builtin.SUBJECT_ACCEPT, nauthilus_builtin.SUBJECT_RESULT_OK
end
