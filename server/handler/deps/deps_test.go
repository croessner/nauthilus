// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package deps

import (
	"testing"

	"github.com/croessner/nauthilus/v3/server/app/configfx"
	"github.com/croessner/nauthilus/v3/server/config"
)

type mutableConfigProvider struct {
	snapshot configfx.Snapshot
}

func (p *mutableConfigProvider) Current() configfx.Snapshot {
	return p.snapshot
}

func TestAuthUsesCurrentConfigSnapshotAtRequestBoundary(t *testing.T) {
	startup := &config.FileSettings{}
	current := &config.FileSettings{}
	provider := &mutableConfigProvider{snapshot: configfx.Snapshot{File: current, Version: 2}}
	dependencies := &Deps{Cfg: startup, CfgProvider: provider}

	if got := dependencies.Auth().Cfg; got != current {
		t.Fatalf("Auth().Cfg = %p, want current snapshot %p", got, current)
	}
}
