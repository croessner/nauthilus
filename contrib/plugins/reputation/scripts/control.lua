-- Publish or quiesce one fixed manifest shard without allowing old writers to reopen it.
local request = decode(ARGV[1], 4096)
if not request or #KEYS ~= 1 then return {'invalid_state'} end
local current = hash(KEYS[1], 8)
if not current or not closed(current, {'schema','identity','mode'}) then return {'invalid_state'} end
if current.schema and current.schema ~= request.schema then return {'allocation_mismatch'} end
if request.operation == 'drain' then
    if current.identity and current.identity ~= request.identity then return {'allocation_mismatch'} end
    redis.call('HSET', KEYS[1], 'schema', request.schema, 'identity', request.identity, 'mode', 'draining')
    return {'draining'}
end
if request.operation ~= 'activate' then return {'invalid_state'} end
if current.identity then
    if current.identity == request.identity then
        if current.mode ~= 'active' then return {'allocation_draining'} end
        return {'active'}
    end
    if current.mode ~= 'draining' or current.identity ~= request.previous then return {'allocation_mismatch'} end
end
redis.call('HSET', KEYS[1], 'schema', request.schema, 'identity', request.identity, 'mode', 'active')
return {'active'}
