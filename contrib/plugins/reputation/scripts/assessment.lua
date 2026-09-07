-- Obtain one primary, server-time snapshot without writing state, seen sets or expirations.
local request = decode(ARGV[1], 16384)
if not request or #KEYS ~= (request.details and 4 or 3) or not bounded(request.retention, 1, 31536000) or
   not bounded(request.diversity_floor, 0.000000001, 1000000) then return {'invalid_state'} end
local now = clock()
local state = hash(KEYS[1], 96)
local values = decay_state(request, state, now)
if not values or not valid_subject_lifetime(state, KEYS[1], KEYS[2], now, request.retention) then return {'invalid_state'} end
local override = read_override(KEYS[3], request.tag, request.kind, now)
if not override then return {'invalid_state'} end
local result = {state='not_found',now=now,override=override.band}
if request.details then
    local audit = read_management_audit(KEYS[4], request.tag, request.kind, now)
    if not audit then return {'invalid_state'} end
    if next(audit) ~= nil then result.audit = audit end
    if override.band ~= 'none' then
        override.created_at, override.expires_at = tonumber(override.created_at), tonumber(override.expires_at)
        result.operator_override = override
    end
    result.sources = {}
end
if next(state) == nil then return {'snapshot',cjson.encode(result)} end
result.state = 'fresh'
result.updated_at = tonumber(state.expires_at) - request.retention
result.risk_at = values.last_independent_risk_at
result.trust_at = values.last_independent_trust_at
result.authoritative_at = values.last_authoritative_risk_at
result.profiles = {}
for _, profile in ipairs(request.profiles) do
    local total = {name=profile.name,risk=0,trust=0,samples=0,diversity=0,risk_diversity=0}
    if request.details then result.sources[profile.name] = {} end
    for _, class in ipairs(request.classes) do
        local prefix = profile.name .. '_' .. class.name .. '_'
        local risk, trust = values[prefix .. 'risk'], values[prefix .. 'trust']
        total.risk = total.risk + risk
        total.trust = total.trust + trust
        total.samples = total.samples + values[prefix .. 'samples']
        if risk + trust >= request.diversity_floor then total.diversity = total.diversity + 1 end
        if request.details and risk + trust >= request.diversity_floor then result.sources[profile.name][class.name] = true end
        if risk >= request.diversity_floor then total.risk_diversity = total.risk_diversity + 1 end
    end
    table.insert(result.profiles,total)
end
return {'snapshot',cjson.encode(result)}
