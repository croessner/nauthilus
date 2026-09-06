-- Atomically create or compare one complete plan and reserve bounded same-shard source quotas.
local request = decode(ARGV[1], 131072)
if not request or #KEYS ~= 4 or type(request.candidates) ~= 'table' or #request.candidates < 1 or #request.candidates > 2 then
    return {'invalid_state'}
end
local control = hash(KEYS[2], 8)
if not control or not closed(control, {'schema','identity','mode'}) or control.schema ~= manifest_schema or control.mode ~= 'active' or control.identity ~= request.allocation_identity then return {'allocation_mismatch'} end
local now = clock()
local existing_type = kind(KEYS[1])
if existing_type ~= 'none' then
    if existing_type ~= 'string' then return {'invalid_state'} end
    local existing = decode(redis.call('GET', KEYS[1]), 65536)
    local ttl = redis.call('PTTL', KEYS[1])
    if not existing or not closed(existing, {'schema','payload','fingerprint','created','expires','retention'}) or
       existing.schema ~= manifest_schema or not opaque_tag(existing.fingerprint) or
       not bounded(existing.created, 0, now) or not bounded(existing.expires, now, now + 31536000) or
       not bounded(existing.retention, 1, 31536000) or
       math.abs(existing.expires - existing.created - existing.retention) > 0.002 or
       ttl <= 0 or math.abs(ttl / 1000 - (existing.expires - now)) > 0.02 or
       not valid_manifest_payload(decode(existing.payload, 61440)) then return {'invalid_state'} end
    local match = 0
    for index, candidate in ipairs(request.candidates) do
        if candidate.payload == existing.payload and candidate.fingerprint == existing.fingerprint then
            if match ~= 0 then return {'invalid_state'} end
            match = index
        end
    end
    if match == 0 then return {'event_conflict'} end
    return {'admitted', match, tostring(existing.expires)}
end

if not bounded(request.observed_at, 0, now + request.future_skew) or
   now - request.observed_at > request.lateness then return {'event_time'} end
if not bounded(request.retention, 1, 31536000) then return {'invalid_state'} end
local candidate = request.candidates[1]
local payload = decode(candidate.payload, 61440)
if not valid_manifest_payload(payload) or not opaque_tag(candidate.fingerprint) then return {'invalid_state'} end
local subjects = {}
for _, model in ipairs(payload.models) do
    if type(model.subjects) ~= 'table' or #model.subjects < 1 or #model.subjects > 24 then return {'invalid_state'} end
    for _, subject in ipairs(model.subjects) do
        if not text(subject.tag, 128) then return {'invalid_state'} end
        subjects[subject.tag] = true
    end
end
local quota_type, events_type = kind(KEYS[3]), kind(KEYS[4])
if (quota_type ~= 'none' and quota_type ~= 'zset') or (events_type ~= 'none' and events_type ~= 'zset') then return {'invalid_state'} end
if redis.call('ZCARD', KEYS[3]) > request.maximum_new_subjects or redis.call('ZCARD', KEYS[4]) > request.maximum_events then return {'invalid_state'} end
local active_subjects = redis.call('ZCOUNT', KEYS[3], now, '+inf')
local new_subjects = 0
for tag in pairs(subjects) do
    local expiry = tonumber(redis.call('ZSCORE', KEYS[3], tag))
    if not expiry or expiry <= now then new_subjects = new_subjects + 1 end
end
if active_subjects + new_subjects > request.maximum_new_subjects or
   redis.call('ZCOUNT', KEYS[4], now, '+inf') >= request.maximum_events then return {'quota_exceeded'} end

local expiry = now + request.retention
local manifest = cjson.encode({schema=manifest_schema, payload=candidate.payload,
    fingerprint=candidate.fingerprint, created=now, expires=expiry, retention=request.retention})
if #manifest > 65536 then return {'invalid_state'} end
redis.call('ZREMRANGEBYSCORE', KEYS[3], '-inf', now)
redis.call('ZREMRANGEBYSCORE', KEYS[4], '-inf', now)
for tag in pairs(subjects) do redis.call('ZADD', KEYS[3], now + 3600, tag) end
redis.call('ZADD', KEYS[4], expiry, request.allocation_tag)
redis.call('PEXPIRE', KEYS[3], 3600000)
redis.call('PEXPIRE', KEYS[4], math.ceil(request.retention * 1000))
redis.call('SET', KEYS[1], manifest, 'PX', math.ceil(request.retention * 1000))
return {'admitted', 1, tostring(expiry)}
