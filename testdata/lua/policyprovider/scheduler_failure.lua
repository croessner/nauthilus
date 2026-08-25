-- Copyright (C) 2026 Christian Rößner
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.

-- This fixture returns one bounded provider failure for shared-scheduler tests.
_G["policy.facts.collect"] = function(_)
    return { error_class = "unavailable" }
end
