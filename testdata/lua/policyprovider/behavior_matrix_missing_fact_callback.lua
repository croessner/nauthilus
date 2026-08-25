-- Copyright (C) 2026 Christian Rößner
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.

-- Only the effect callback is registered, so fact registration must fail closed.
_G["policy.effects.execute"] = function(_)
    return { state = "succeeded" }
end
