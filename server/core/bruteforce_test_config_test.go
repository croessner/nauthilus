// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package core

import (
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
)

const hardCutBruteForceRuleName = "loopback_block"

// hardCutBruteForceConfig builds one explicit request-owned brute-force fixture.
func hardCutBruteForceConfig(t *testing.T) *config.FileSettings {
	t.Helper()

	cfg := newCurrentBehaviorConfig(t, definitions.ControlBruteForce)
	cfg.BruteForce = &config.BruteForceSection{
		AllowedUniqueWrongPWHashes: 1,
		RWPWindow:                  time.Minute,
		Buckets: []config.BruteForceRule{
			{
				Name:           hardCutBruteForceRuleName,
				Period:         time.Hour,
				CIDR:           32,
				IPv4:           true,
				FailedRequests: 5,
			},
		},
	}
	cfg.Server.BruteForceProtocols = []*config.Protocol{config.NewProtocol(definitions.ProtoIMAP)}

	return cfg
}
