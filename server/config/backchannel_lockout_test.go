// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package config

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
)

const backchannelLockoutPath = "auth.backchannel.failure_lockout."

// loadBackchannelLockoutConfig loads a configuration that only sets the backchannel lockout.
func loadBackchannelLockoutConfig(t *testing.T, lockout map[string]any) (*FileSettings, error) {
	t.Helper()

	viper.Reset()
	t.Cleanup(viper.Reset)

	viper.Set("auth", map[string]any{
		"backchannel": map[string]any{
			"failure_lockout": lockout,
		},
	})

	cfg := &FileSettings{}

	return cfg, cfg.HandleFile()
}

// TestBackchannelLockoutDefaultsMatchHistoricalLimits pins that an unconfigured lockout keeps the limits
// that were hard-wired before the settings became configurable.
func TestBackchannelLockoutDefaultsMatchHistoricalLimits(t *testing.T) {
	for name, lockout := range map[string]*BackchannelLockout{
		"nil section":   nil,
		"empty section": {},
	} {
		t.Run(name, func(t *testing.T) {
			if got := lockout.GetThreshold(); got != 5 {
				t.Fatalf("GetThreshold() = %d, want 5", got)
			}

			if got := lockout.GetWindow(); got != time.Minute {
				t.Fatalf("GetWindow() = %s, want 1m", got)
			}

			if got := lockout.GetBlockTime(); got != 2*time.Minute {
				t.Fatalf("GetBlockTime() = %s, want 2m", got)
			}

			if got := lockout.GetSleepOnFail(); got != 300*time.Millisecond {
				t.Fatalf("GetSleepOnFail() = %s, want 300ms", got)
			}

			if got := lockout.GetExemptThreshold(); got != 50 {
				t.Fatalf("GetExemptThreshold() = %d, want 50", got)
			}

			if got := lockout.GetExemptNetworks(); !slices.Equal(got, []string{"127.0.0.0/8", "::1"}) {
				t.Fatalf("GetExemptNetworks() = %v, want loopback only", got)
			}

			if got := lockout.GetTrustedMTLSIdentities(); len(got) != 0 {
				t.Fatalf("GetTrustedMTLSIdentities() = %v, want none", got)
			}
		})
	}
}

// TestBackchannelLockoutLoadsConfiguredValues pins the public key names and their materialization into the
// runtime server section.
func TestBackchannelLockoutLoadsConfiguredValues(t *testing.T) {
	cfg, err := loadBackchannelLockoutConfig(t, map[string]any{
		"threshold":               20,
		"window":                  "30s",
		"block_time":              "10m",
		"sleep_on_fail":           "50ms",
		"exempt_threshold":        200,
		"exempt_networks":         []any{"127.0.0.1", "127.0.0.6"},
		"trusted_mtls_identities": []any{"spiffe://cluster.local/ns/mail/sa/doppelgaenger"},
	})
	if err != nil {
		t.Fatalf("HandleFile() error = %v", err)
	}

	lockout := cfg.GetServer().GetBackchannelLockout()

	if lockout.GetThreshold() != 20 || lockout.GetWindow() != 30*time.Second ||
		lockout.GetBlockTime() != 10*time.Minute || lockout.GetSleepOnFail() != 50*time.Millisecond ||
		lockout.GetExemptThreshold() != 200 {
		t.Fatalf("GetBackchannelLockout() = %+v, want configured values", *lockout)
	}

	if !slices.Equal(lockout.GetExemptNetworks(), []string{"127.0.0.1", "127.0.0.6"}) {
		t.Fatalf("GetExemptNetworks() = %v", lockout.GetExemptNetworks())
	}

	if !slices.Equal(lockout.GetTrustedMTLSIdentities(), []string{"spiffe://cluster.local/ns/mail/sa/doppelgaenger"}) {
		t.Fatalf("GetTrustedMTLSIdentities() = %v", lockout.GetTrustedMTLSIdentities())
	}
}

// TestBackchannelLockoutEmptyExemptNetworksDisableExemption pins that an explicit empty list is kept and
// does not fall back to loopback.
func TestBackchannelLockoutEmptyExemptNetworksDisableExemption(t *testing.T) {
	cfg, err := loadBackchannelLockoutConfig(t, map[string]any{"exempt_networks": []any{}})
	if err != nil {
		t.Fatalf("HandleFile() error = %v", err)
	}

	if got := cfg.GetServer().GetBackchannelLockout().GetExemptNetworks(); len(got) != 0 {
		t.Fatalf("GetExemptNetworks() = %v, want none", got)
	}
}

// TestBackchannelLockoutRejectsExemptThresholdBelowThreshold pins that exempt callers are never counted
// more strictly than untrusted ones.
func TestBackchannelLockoutRejectsExemptThresholdBelowThreshold(t *testing.T) {
	_, err := loadBackchannelLockoutConfig(t, map[string]any{"threshold": 10, "exempt_threshold": 5})
	if err == nil || !strings.Contains(err.Error(), backchannelLockoutPath+"exempt_threshold") {
		t.Fatalf("HandleFile() error = %v, want exempt_threshold relation error", err)
	}
}

// TestBackchannelLockoutRejectsInvalidValues pins positive values and upper bounds for every setting.
func TestBackchannelLockoutRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		value any
		key   string
	}{
		{key: "threshold", value: -1},
		{key: "threshold", value: 1001},
		{key: "window", value: "-1s"},
		{key: "window", value: "2h"},
		{key: "block_time", value: "-1m"},
		{key: "block_time", value: "25h"},
		{key: "sleep_on_fail", value: "-1ms"},
		{key: "sleep_on_fail", value: "6s"},
		{key: "exempt_threshold", value: 0 - 1},
		{key: "exempt_threshold", value: 100001},
		{key: "exempt_networks", value: []any{"not-a-network"}},
		{key: "trusted_mtls_identities", value: []any{""}},
	}

	for _, test := range tests {
		t.Run(test.key, func(t *testing.T) {
			_, err := loadBackchannelLockoutConfig(t, map[string]any{test.key: test.value})
			if err == nil {
				t.Fatalf("HandleFile() error = nil, want validation error for %s=%v", test.key, test.value)
			}

			if !strings.Contains(err.Error(), backchannelLockoutPath+test.key) {
				t.Fatalf("HandleFile() error = %q, want path %q", err, backchannelLockoutPath+test.key)
			}
		})
	}
}

// TestBackchannelLockoutDefaultsAppearInConfigDump pins that operators see the effective defaults.
func TestBackchannelLockoutDefaultsAppearInConfigDump(t *testing.T) {
	output, err := RenderDefaultConfigDump()
	if err != nil {
		t.Fatalf("RenderDefaultConfigDump() error = %v", err)
	}

	for _, expected := range []string{
		backchannelLockoutPath + "threshold = 5",
		backchannelLockoutPath + `window = "1m0s"`,
		backchannelLockoutPath + `block_time = "2m0s"`,
		backchannelLockoutPath + `sleep_on_fail = "300ms"`,
		backchannelLockoutPath + "exempt_threshold = 50",
		backchannelLockoutPath + `exempt_networks = ["127.0.0.0/8", "::1"]`,
		backchannelLockoutPath + "trusted_mtls_identities = []",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("RenderDefaultConfigDump() missing line %q", expected)
		}
	}
}

// TestBackchannelLockoutExemptThresholdFollowsRaisedThreshold pins that raising threshold alone stays valid
// and never counts exempt callers more strictly than untrusted ones.
func TestBackchannelLockoutExemptThresholdFollowsRaisedThreshold(t *testing.T) {
	cfg, err := loadBackchannelLockoutConfig(t, map[string]any{"threshold": 60})
	if err != nil {
		t.Fatalf("HandleFile() error = %v", err)
	}

	if got := cfg.GetServer().GetBackchannelLockout().GetExemptThreshold(); got != 60 {
		t.Fatalf("GetExemptThreshold() = %d, want 60", got)
	}
}

// TestBackchannelLockoutTrimsTrustedMTLSIdentities pins that allowlist entries are trimmed on load and that
// blank entries are rejected instead of silently never matching.
func TestBackchannelLockoutTrimsTrustedMTLSIdentities(t *testing.T) {
	cfg, err := loadBackchannelLockoutConfig(t, map[string]any{"trusted_mtls_identities": []any{"  doppelgaenger  "}})
	if err != nil {
		t.Fatalf("HandleFile() error = %v", err)
	}

	if got := cfg.GetServer().GetBackchannelLockout().GetTrustedMTLSIdentities(); !slices.Equal(got, []string{"doppelgaenger"}) {
		t.Fatalf("GetTrustedMTLSIdentities() = %q, want trimmed entry", got)
	}

	if _, err := loadBackchannelLockoutConfig(t, map[string]any{"trusted_mtls_identities": []any{"   "}}); err == nil ||
		!strings.Contains(err.Error(), backchannelLockoutPath+"trusted_mtls_identities") {
		t.Fatalf("HandleFile() error = %v, want blank identity rejection", err)
	}
}
