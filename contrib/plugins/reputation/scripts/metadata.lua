-- Bind model and allocation identities before publishing any writer readiness.
local request = decode(ARGV[1], 16384)
if not request or #KEYS ~= 2 then return {'invalid_state'} end
local metadata = hash(KEYS[1], 16)
local models = hash(KEYS[2], 64)
if not metadata or not models then return {'invalid_state'} end
local now = clock()
local generation = stored_number(metadata, 'generation', 0, 1000000, 0)
if not generation then return {'invalid_state'} end
if (next(metadata) == nil) ~= (next(models) == nil) then return {'invalid_state'} end
if next(metadata) ~= nil then
    local allowed = {schema=true,identity=true,shards=true,generation=true,mode=true,retention=true,
        drain_generation=true,drained_at=true,previous_identity=true}
    for field in pairs(metadata) do if not allowed[field] then return {'invalid_state'} end end
    if not text(metadata.schema, 64) or not text(metadata.identity, 128) or
       not number(metadata.retention, 1, 31536000) or not number(metadata.shards, 1, 256) or
       (metadata.mode ~= 'active' and metadata.mode ~= 'draining') or
       redis.call('PTTL', KEYS[1]) ~= -1 or redis.call('PTTL', KEYS[2]) ~= -1 then return {'invalid_state'} end
    if metadata.mode == 'draining' and (tonumber(metadata.drain_generation) ~= generation + 1 or
       not number(metadata.drained_at, 0, now)) then return {'invalid_state'} end
end
if metadata.schema and (metadata.schema ~= request.schema or tonumber(metadata.shards) ~= request.shards) then
    return {'allocation_mismatch'}
end

if request.operation == 'begin_drain' or request.operation == 'finish_drain' then
    if metadata.identity ~= request.identity or generation ~= request.generation then return {'allocation_mismatch'} end
    if request.operation == 'begin_drain' then
        if metadata.mode ~= 'active' and metadata.mode ~= 'draining' then return {'invalid_state'} end
        if metadata.mode == 'active' then
            redis.call('HSET', KEYS[1], 'mode', 'draining', 'drain_generation', generation + 1, 'drained_at', 0)
        end
        return {'draining', generation + 1}
    end
    if metadata.mode ~= 'draining' then return {'allocation_mismatch'} end
    if tonumber(metadata.drained_at) == 0 then redis.call('HSET', KEYS[1], 'drained_at', now) end
    return {'draining', generation + 1}
end

if request.operation ~= 'activate' or not bounded(request.retention, 1, 31536000) or
   not bounded(request.generation, 0, 1000000) or type(request.models) ~= 'table' then return {'invalid_state'} end
local previous = metadata.previous_identity or ''
if metadata.identity then
    if metadata.identity == request.identity then
        if metadata.mode ~= 'active' or request.generation ~= generation then return {'allocation_draining'} end
    else
        local completed = number(metadata.drained_at, 1, now)
        local retained = number(metadata.retention, 1, 31536000)
        if metadata.mode ~= 'draining' or not completed or not retained or now < completed + retained or
           request.generation ~= tonumber(metadata.drain_generation) then return {'allocation_mismatch'} end
        previous = metadata.identity
    end
elseif request.generation ~= 0 then return {'allocation_mismatch'} end

local count = 0
for _ in pairs(models) do count = count + 1 end
for id, fingerprint in pairs(request.models) do
    if not text(id, 64) or not text(fingerprint, 64) then return {'invalid_state'} end
    if models[id] and models[id] ~= fingerprint then return {'model_mismatch'} end
    if not models[id] then count = count + 1 end
end
if count > 64 then return {'quota_exceeded'} end
local retained = math.max(tonumber(metadata.retention) or 0, request.retention)
redis.call('HSET', KEYS[1], 'schema', request.schema, 'identity', request.identity, 'shards', request.shards,
    'generation', request.generation, 'mode', 'active', 'retention', retained, 'previous_identity', previous)
for id, fingerprint in pairs(request.models) do redis.call('HSET', KEYS[2], id, fingerprint) end
return {'active', previous}
