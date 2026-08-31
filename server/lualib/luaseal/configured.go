// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package luaseal

import (
	"fmt"

	"github.com/croessner/nauthilus/v4/server/config"
)

// CaptureConfigured compiles the canonical module search order from one candidate-bound artifact snapshot.
func CaptureConfigured(configured config.File) (*Modules, error) {
	if configured == nil {
		return nil, fmt.Errorf("capture configured Lua modules: config is nil")
	}

	snapshot, err := config.ArtifactSnapshotFor(configured)
	if err != nil {
		return nil, fmt.Errorf("capture configured Lua modules: %w", err)
	}

	return CaptureSnapshot(config.EffectiveLuaPackagePatterns(configured), snapshot)
}
