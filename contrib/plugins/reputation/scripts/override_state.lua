-- Validate operator audit metadata separately from learned state and without TTL mutation.
local function read_override(key, tag, subject_kind, now)
    local value = hash(key, 16)
    if not value then return nil end
    if next(value) == nil then return {band='none'} end
    if not closed(value, {'schema','tag','kind','band','reason','creator','created_at','expires_at','audit_id','origin'}) or
       value.schema ~= override_schema or value.tag ~= tag or value.kind ~= subject_kind or
       (value.band ~= 'blocked' and value.band ~= 'trusted' and value.band ~= 'neutral') or
       not identifier(value.reason) or not audit_text(value.creator) or not audit_text(value.audit_id) or
       not identifier(value.origin) or not number(value.created_at, 0, now) then return nil end
    local expiry = number(value.expires_at, 0, 100000000000)
    if not expiry or (expiry > 0 and expiry <= tonumber(value.created_at)) then return nil end
    if expiry > 0 and expiry <= now then return {band='none'} end
    return value
end

-- read_management_audit validates the one bounded receipt without granting override authority.
local function read_management_audit(key, tag, subject_kind, now)
    local value = hash(key, 16)
    if not value then return nil end
    if next(value) == nil then return {} end
    if not closed(value, {'schema','tag','kind','operation','reason','creator','audit_id','previous_audit','origin','created_at'}) or
       value.schema ~= audit_schema or value.tag ~= tag or value.kind ~= subject_kind or
       (value.operation ~= 'override_put' and value.operation ~= 'override_delete') or
       not identifier(value.reason) or not identifier(value.origin) or not audit_text(value.creator) or
       not audit_text(value.audit_id) or (value.previous_audit ~= '' and not audit_text(value.previous_audit)) or
       not number(value.created_at, 0, now) then return nil end
    value.created_at = tonumber(value.created_at)
    return value
end
