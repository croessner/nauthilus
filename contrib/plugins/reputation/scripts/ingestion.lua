-- Validate the complete bounded state before mutating one subject/model and its same-slot seen set.
local request = decode(ARGV[1], 32768)
if not request or #KEYS ~= 2 then return {'invalid_state'} end
local now = clock()
if not bounded(request.manifest_expiry, now, now + 31536000) or request.manifest_expiry <= now then return {'event_time'} end
if not bounded(request.retention, 1, 31536000) or not bounded(request.seen_ttl, 1, request.retention) or
   not bounded(request.weight, 0, 1000) or not bounded(request.maximum_seen, 1, 100000) or
   not bounded(request.observed_at, 0, now + 3600) or not text(request.seen_tag, 128) then return {'invalid_state'} end
if request.direction ~= 'risk' and request.direction ~= 'trust' then return {'invalid_state'} end
if type(request.profiles) ~= 'table' or #request.profiles ~= 3 or type(request.classes) ~= 'table' or
   #request.classes < 1 or #request.classes > 8 or type(request.eligible_profiles) ~= 'table' then return {'invalid_state'} end
local state = hash(KEYS[1], 96)
local seen_type = kind(KEYS[2])
if not state or (seen_type ~= 'none' and seen_type ~= 'zset') then return {'invalid_state'} end
if redis.call('ZCARD', KEYS[2]) > request.maximum_seen then return {'invalid_state'} end
local existing = next(state) ~= nil
if existing and (state.schema_version ~= state_schema or state.model_fingerprint ~= request.fingerprint or state.kind ~= request.kind) then
    return {'model_mismatch'}
end
local values = decay_state(request, state, now)
if not values or not valid_subject_lifetime(state, KEYS[1], KEYS[2], now, request.retention) then return {'invalid_state'} end
local eligible = {}
for _, profile in ipairs(request.eligible_profiles) do eligible[profile] = true end
local source_exists = false
for _, class in ipairs(request.classes) do
    if class.name == request.source_class then source_exists = true end
end
if not source_exists then return {'invalid_state'} end
for _, profile in ipairs(request.profiles) do
    local evidence_decay = math.pow(2, -math.max(0, now - request.observed_at) / profile.half_life)
    for _, class in ipairs(request.classes) do
        for _, measure in ipairs({'risk','trust','samples'}) do
            local field = profile.name .. '_' .. class.name .. '_' .. measure
            local increment = 0
            if eligible[profile.name] and class.name == request.source_class then
                if measure == request.direction then increment = request.weight end
                if measure == 'samples' and request.weight > 0 then increment = 1 end
            end
            values[field] = math.min(class[measure], values[field] + increment * evidence_decay)
            if not finite(values[field]) then return {'invalid_state'} end
        end
    end
end
local seen_expiry = tonumber(redis.call('ZSCORE', KEYS[2], request.seen_tag))
if seen_expiry and seen_expiry > now then return {'duplicate'} end
if redis.call('ZCOUNT', KEYS[2], now, '+inf') >= request.maximum_seen then return {'quota_exceeded'} end
if request.weight > 0 then
    local field = 'last_independent_' .. request.direction .. '_at'
    values[field] = math.max(values[field], math.min(now, request.observed_at))
    if request.authoritative and request.direction == 'risk' then
        values.last_authoritative_risk_at = math.max(values.last_authoritative_risk_at, math.min(now, request.observed_at))
    end
end
local seen_until = math.max(now + request.seen_ttl, request.manifest_expiry, tonumber(state.seen_until) or 0)
if seen_until > now + request.retention then return {'invalid_state'} end
values.schema_version = state_schema
values.model_fingerprint = request.fingerprint
values.kind = request.kind
values.expires_at = now + request.retention
values.seen_until = seen_until
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now)
for field, value in pairs(values) do redis.call('HSET', KEYS[1], field, value) end
redis.call('ZADD', KEYS[2], request.manifest_expiry, request.seen_tag)
redis.call('PEXPIRE', KEYS[1], math.ceil(request.retention * 1000))
redis.call('PEXPIRE', KEYS[2], math.ceil((seen_until - now) * 1000))
return {'applied'}
