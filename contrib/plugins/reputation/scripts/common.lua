-- Shared finite-value, decoding and Redis-time boundaries for reputation scripts.
local function finite(value)
    return type(value) == 'number' and value == value and value > -math.huge and value < math.huge
end

local function bounded(value, low, high)
    return finite(value) and value >= low and value <= high
end

local function clock()
    local value = redis.call('TIME')
    return tonumber(value[1]) + tonumber(value[2]) / 1000000
end

local function decode(value, maximum)
    if type(value) ~= 'string' or #value == 0 or #value > maximum then return nil end
    local ok, decoded = pcall(cjson.decode, value)
    if not ok or type(decoded) ~= 'table' then return nil end
    return decoded
end

local function kind(key)
    return redis.call('TYPE', key).ok
end

local function hash(key, maximum)
    if kind(key) == 'none' then return {} end
    if kind(key) ~= 'hash' or redis.call('HLEN', key) > maximum then return nil end
    local values = redis.call('HGETALL', key)
    local result = {}
    for index = 1, #values, 2 do result[values[index]] = values[index + 1] end
    return result
end

local function text(value, maximum)
    return type(value) == 'string' and #value > 0 and #value <= maximum
end

local function number(value, low, high)
    local parsed = tonumber(value)
    if not bounded(parsed, low, high) then return nil end
    return parsed
end

-- Missing or malformed fields in an existing hash must never acquire initialization defaults.
local function stored_number(state, field, low, high, initial)
    if next(state) == nil then return initial end
    return number(state[field], low, high)
end

local function closed(value, fields)
    if type(value) ~= 'table' then return false end
    local allowed = {}
    for _, field in ipairs(fields) do allowed[field] = true end
    for field in pairs(value) do if not allowed[field] then return false end end
    return true
end

local function identifier(value)
    return text(value, 64) and string.match(value, '^[a-z][a-z0-9_.%-]*$') ~= nil
end

local function opaque_tag(value)
    if not text(value, 128) then return false end
    local version, digest = string.match(value, '^hmac%-sha256%-v1:([a-z0-9_.%-]+):([A-Za-z0-9_%-]+)$')
    return version ~= nil and #version <= 32 and #digest == 43
end

local function valid_model_dimensions(model)
    if type(model.profiles) ~= 'table' or #model.profiles ~= 3 or type(model.classes) ~= 'table' or
       #model.classes < 1 or #model.classes > 8 or type(model.eligible_profiles) ~= 'table' or
       #model.eligible_profiles < 1 or #model.eligible_profiles > 3 then return false end
    local profiles, classes, eligible = {}, {}, {}
    for _, profile in ipairs(model.profiles) do
        if not closed(profile, {'name','half_life'}) or
           (profile.name ~= 'fast' and profile.name ~= 'operational' and profile.name ~= 'baseline') or
           profiles[profile.name] or not bounded(profile.half_life, 0, 31536000) or profile.half_life == 0 then return false end
        profiles[profile.name] = true
    end
    for _, class in ipairs(model.classes) do
        if not closed(class, {'name','risk','trust','samples'}) or not identifier(class.name) or classes[class.name] or
           not bounded(class.risk, 0, 1000000) or not bounded(class.trust, 0, 1000000) or
           not bounded(class.samples, 0, 1000000) or class.samples == 0 then return false end
        classes[class.name] = true
    end
    for _, name in ipairs(model.eligible_profiles) do
        if not profiles[name] or eligible[name] then return false end
        eligible[name] = true
    end
    return true
end

local function valid_manifest_model(model)
    if not closed(model, {'subjects','profiles','classes','eligible_profiles','id','fingerprint','direction','authoritative'}) or
       not identifier(model.id) or not text(model.fingerprint, 64) or #model.fingerprint ~= 64 or
       not string.match(model.fingerprint, '^[a-f0-9]+$') or type(model.authoritative) ~= 'boolean' or
       (model.direction ~= 'trust' and model.direction ~= 'risk') or not valid_model_dimensions(model) or
       type(model.subjects) ~= 'table' or #model.subjects < 1 or #model.subjects > 24 then return false end
    local kinds = {ip=true,network=true,asn=true,dns_domain=true,account=true,service=true}
    local previous = ''
    for _, subject in ipairs(model.subjects) do
        if not closed(subject, {'role','kind','tag','weight'}) or not identifier(subject.role) or
           not kinds[subject.kind] or not opaque_tag(subject.tag) or not bounded(subject.weight, 0, 1000) then return false end
        local identity = subject.kind .. subject.tag
        if identity <= previous then return false end
        previous = identity
    end
    return true
end

local function valid_manifest_payload(payload)
    if not closed(payload, {'models','magnitude','schema','seen_tag','tag_version','signal','source_class','origin','observed_at','observed_time'}) or
       payload.schema ~= manifest_schema or not opaque_tag(payload.seen_tag) or
       not text(payload.tag_version, 32) or not identifier(payload.signal) or not identifier(payload.source_class) or
       not bounded(payload.observed_at, 0, 100000000000) or not text(payload.observed_time, 40) or
       (payload.magnitude ~= cjson.null and not bounded(payload.magnitude, 0, 1)) or
       (payload.origin ~= 'external_pre_policy' and payload.origin ~= 'host_backend_outcome' and payload.origin ~= 'authoritative_external') or
       type(payload.models) ~= 'table' or #payload.models < 1 or #payload.models > 2 then return false end
    local models = {}
    for _, model in ipairs(payload.models) do
        if not valid_manifest_model(model) or models[model.id] then return false end
        models[model.id] = true
    end
    return true
end
