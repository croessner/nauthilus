-- Copyright (C) 2026 Christian Rößner
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.

-- This fixture selects one closed-result violation through the redacted client ID.
_G["policy.facts.collect"] = function(request)
    local mode = request.caller.client_id
    local value = { kind = "string", value = "accepted" }

    if mode == "success" then
        return { facts = { { name = "risk.label", value = value } } }
    end

    if mode == "wrong_type" then
        return {
            facts = {
                { name = "risk.label", value = { kind = "integer", value = "7" } },
            },
        }
    end

    if mode == "undeclared" then
        return { facts = { { name = "risk.undeclared", value = value } } }
    end

    if mode == "local_authority_prefix" then
        return { facts = { { name = "lua.risk.risk.label", value = value } } }
    end

    if mode == "foreign_authority" then
        return { facts = { { name = "lua.foreign.risk.label", value = value } } }
    end

    if mode == "forbidden_source" then
        return {
            facts = {
                { name = "risk.label", value = value, source = "caller" },
            },
        }
    end

    if mode == "forbidden_namespace" then
        return {
            facts = {
                { name = "risk.label", value = value, namespace = "foreign" },
            },
        }
    end

    if mode == "duplicate" then
        return {
            facts = {
                { name = "risk.label", value = value },
                { name = "risk.label", value = value },
            },
        }
    end

    error("behavior-matrix-fact-secret")
end
