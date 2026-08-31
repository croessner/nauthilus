// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package registry

import "github.com/croessner/nauthilus/v4/server/policy/internal/identifier"

// validEffectID preserves the general namespace/action grammar plus one authn-only native extension form.
func validEffectID(value string) bool {
	return identifier.Qualified(value) || identifier.AuthnPluginEffect(value)
}
