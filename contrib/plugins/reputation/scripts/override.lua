-- Apply one audited compare-and-set operator change using the primary clock.
local request = decode(ARGV[1], 4096)
if not request or #KEYS ~= 1 then return {'invalid_state'} end
local now = clock()
local previous = read_override(KEYS[1], request.tag, request.kind, now)
if not previous then return {'invalid_state'} end
if request.operation == 'get' then
    if previous.band == 'none' then return {'override_missing'} end
    previous.created_at = tonumber(previous.created_at)
    previous.expires_at = tonumber(previous.expires_at)
    return {'override_read',cjson.encode(previous)}
end
local audit = previous.audit_id or '' 
if audit ~= request.previous_audit then return {'override_conflict'} end
if request.operation == 'delete' then
    redis.call('DEL', KEYS[1])
    return {'override_deleted'}
end
if request.operation ~= 'put' or not bounded(request.ttl, 0, 31536000) or not opaque_tag(request.tag) or
   not identifier(request.kind) or (request.band ~= 'blocked' and request.band ~= 'trusted' and request.band ~= 'neutral') or
   not identifier(request.reason) or not audit_text(request.creator) or not audit_text(request.audit_id) or
   not identifier(request.origin) then return {'invalid_state'} end
local value = {schema=override_schema,tag=request.tag,kind=request.kind,band=request.band,
    reason=request.reason,creator=request.creator,created_at=now,expires_at=0,audit_id=request.audit_id,origin=request.origin}
if request.ttl > 0 then value.expires_at = now + request.ttl end
for field, content in pairs(value) do redis.call('HSET', KEYS[1], field, content) end
if request.ttl > 0 then redis.call('PEXPIRE', KEYS[1], math.ceil(request.ttl * 1000))
else redis.call('PERSIST', KEYS[1]) end
return {'override_written',cjson.encode(value)}
