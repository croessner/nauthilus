-- Copyright (C) 2026 Christian Rößner
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.

-- This fixture exposes deterministic selected-effect outcomes without host work.
_G["policy.effects.execute"] = function(request)
    local mode = request.parameters[1].value.value

    if mode == "unknown" then
        return { state = "outcome_unknown", error_class = "unavailable" }
    end

    if mode == "post" then
        return { state = "succeeded" }
    end

    error("behavior-matrix-effect-secret")
end
