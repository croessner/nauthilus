-- Validate and decay one complete model snapshot; both ingestion and assessment use this boundary.
local function decay_state(request, state, now)
    if not state or type(request.profiles) ~= 'table' or #request.profiles ~= 3 or
       type(request.classes) ~= 'table' or #request.classes < 1 or #request.classes > 8 then return nil end
    local existing = next(state) ~= nil
    if existing and (state.schema_version ~= state_schema or state.model_fingerprint ~= request.fingerprint or
       state.kind ~= request.kind) then return nil end
    local allowed = {schema_version=true,model_fingerprint=true,kind=true,expires_at=true,seen_until=true,
        last_independent_risk_at=true,last_independent_trust_at=true,last_authoritative_risk_at=true}
    local values, profiles, classes = {}, {}, {}
    for _, class in ipairs(request.classes) do
        if not identifier(class.name) or classes[class.name] or not bounded(class.risk, 0, 1000000) or
           not bounded(class.trust, 0, 1000000) or not bounded(class.samples, 0, 1000000) or class.samples == 0 then return nil end
        classes[class.name] = true
    end
    for _, profile in ipairs(request.profiles) do
        if not identifier(profile.name) or profiles[profile.name] or
           not bounded(profile.half_life, 0, 31536000) or profile.half_life == 0 then return nil end
        profiles[profile.name] = true
        local field = profile.name .. '_updated_at'
        allowed[field] = true
        local updated = stored_number(state, field, 0, now, now)
        if not updated then return nil end
        local decay = math.pow(2, -(now - updated) / profile.half_life)
        values[field] = now
        for _, class in ipairs(request.classes) do
            for _, measure in ipairs({'risk','trust','samples'}) do
                field = profile.name .. '_' .. class.name .. '_' .. measure
                allowed[field] = true
                local previous = stored_number(state, field, 0, class[measure], 0)
                if not previous then return nil end
                values[field] = previous * decay
            end
        end
    end
    for field in pairs(state) do if not allowed[field] then return nil end end
    for _, field in ipairs({'last_independent_risk_at','last_independent_trust_at','last_authoritative_risk_at'}) do
        values[field] = stored_number(state, field, 0, now, 0)
        if not values[field] then return nil end
    end
    return values
end

-- Validate persistent expiry metadata without refreshing or repairing either subject key.
local function valid_subject_lifetime(state, state_key, seen_key, now, retention)
    local seen_type = kind(seen_key)
    if seen_type ~= 'none' and seen_type ~= 'zset' then return false end
    if next(state) == nil then return seen_type == 'none' end
    local expiry = number(state.expires_at, now, now + retention)
    local seen_until = number(state.seen_until, 0, now + retention)
    if not expiry or not seen_until or redis.call('PTTL', state_key) <= 0 then return false end
    if seen_type == 'none' and seen_until > now then return false end
    return true
end
