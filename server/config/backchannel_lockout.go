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
	"fmt"
	"strings"
	"time"
)

const (
	// DefaultBackchannelLockoutThreshold is the number of rejected caller authentications that lock out a source.
	DefaultBackchannelLockoutThreshold = 5
	// DefaultBackchannelLockoutWindow is the period in which rejected caller authentications are counted.
	DefaultBackchannelLockoutWindow = time.Minute
	// DefaultBackchannelLockoutBlockTime is how long a locked-out source stays blocked.
	DefaultBackchannelLockoutBlockTime = 2 * time.Minute
	// DefaultBackchannelLockoutSleepOnFail is the delay applied to every rejected caller authentication.
	DefaultBackchannelLockoutSleepOnFail = 300 * time.Millisecond
	// DefaultBackchannelLockoutExemptThreshold is the number of rejections within the window that block one
	// presented identity of an exempt caller.
	DefaultBackchannelLockoutExemptThreshold = 50
)

const (
	backchannelLockoutIPv4Loopback = "127.0.0.0/8"
	backchannelLockoutIPv6Loopback = "::1"
)

// defaultBackchannelLockoutExemptNetworks exempts only callers on the same host, such as sidecars.
var defaultBackchannelLockoutExemptNetworks = []string{backchannelLockoutIPv4Loopback, backchannelLockoutIPv6Loopback}

// BackchannelLockout configures the process-local lockout of backchannel callers after repeated
// rejected authentications. Zero values select the defaults; configured values must be positive and bounded.
//
// Exempt callers, identified by their direct transport peer address or by an allow-listed mTLS identity,
// are never blocked per address. They are counted per presented credential identity instead, with the
// higher exempt_threshold, so a shared sidecar address stays usable while a single guesser is still stopped.
type BackchannelLockout struct {
	ExemptNetworks        []string      `mapstructure:"exempt_networks" validate:"omitempty,dive,ip|cidr"`
	TrustedMTLSIdentities []string      `mapstructure:"trusted_mtls_identities" validate:"omitempty,dive,min=1,max=255,printascii"`
	Window                time.Duration `mapstructure:"window" validate:"omitempty,gt=0,max=1h"`
	BlockTime             time.Duration `mapstructure:"block_time" validate:"omitempty,gt=0,max=24h"`
	SleepOnFail           time.Duration `mapstructure:"sleep_on_fail" validate:"omitempty,gt=0,max=5s"`
	Threshold             int           `mapstructure:"threshold" validate:"omitempty,gte=1,lte=1000"`
	ExemptThreshold       int           `mapstructure:"exempt_threshold" validate:"omitempty,gte=1,lte=100000"`
}

// GetExemptNetworks returns the peer networks exempt from address lockout; unset means loopback only.
func (l *BackchannelLockout) GetExemptNetworks() []string {
	if l == nil || l.ExemptNetworks == nil {
		return defaultBackchannelLockoutExemptNetworks
	}

	return l.ExemptNetworks
}

// GetTrustedMTLSIdentities returns the client-certificate identities exempt from address lockout.
// An empty list disables the mTLS exemption.
func (l *BackchannelLockout) GetTrustedMTLSIdentities() []string {
	if l == nil {
		return nil
	}

	return l.TrustedMTLSIdentities
}

// GetExemptThreshold returns the number of rejections that block one presented identity of an exempt caller.
// Unset, it is the default but never lower than threshold, so raising threshold alone stays valid.
func (l *BackchannelLockout) GetExemptThreshold() int {
	if l == nil || l.ExemptThreshold <= 0 {
		return max(DefaultBackchannelLockoutExemptThreshold, l.GetThreshold())
	}

	return l.ExemptThreshold
}

// Validate normalizes the mTLS identity allowlist and checks relations between settings that struct tags
// cannot express. The exempt threshold is compared with threshold only when it is set explicitly.
func (l *BackchannelLockout) Validate() error {
	if l == nil {
		return nil
	}

	for index, identity := range l.TrustedMTLSIdentities {
		trimmed := strings.TrimSpace(identity)
		if trimmed == "" {
			return fmt.Errorf("auth.backchannel.failure_lockout.trusted_mtls_identities[%d] must not be empty", index)
		}

		l.TrustedMTLSIdentities[index] = trimmed
	}

	if l.ExemptThreshold > 0 && l.ExemptThreshold < l.GetThreshold() {
		return fmt.Errorf("auth.backchannel.failure_lockout.exempt_threshold (%d) must not be lower than threshold (%d)",
			l.ExemptThreshold, l.GetThreshold())
	}

	return nil
}

// GetThreshold returns the number of rejections within the window that lock out a source.
func (l *BackchannelLockout) GetThreshold() int {
	if l == nil || l.Threshold <= 0 {
		return DefaultBackchannelLockoutThreshold
	}

	return l.Threshold
}

// GetWindow returns the period in which rejections are counted.
func (l *BackchannelLockout) GetWindow() time.Duration {
	return positiveDurationOrDefault(l, func(lockout *BackchannelLockout) time.Duration {
		return lockout.Window
	}, DefaultBackchannelLockoutWindow)
}

// GetBlockTime returns how long a locked-out source stays blocked.
func (l *BackchannelLockout) GetBlockTime() time.Duration {
	return positiveDurationOrDefault(l, func(lockout *BackchannelLockout) time.Duration {
		return lockout.BlockTime
	}, DefaultBackchannelLockoutBlockTime)
}

// GetSleepOnFail returns the delay applied to every rejected caller authentication.
func (l *BackchannelLockout) GetSleepOnFail() time.Duration {
	return positiveDurationOrDefault(l, func(lockout *BackchannelLockout) time.Duration {
		return lockout.SleepOnFail
	}, DefaultBackchannelLockoutSleepOnFail)
}

// positiveDurationOrDefault reads one lockout duration and falls back to its default when unset.
func positiveDurationOrDefault(
	lockout *BackchannelLockout,
	read func(*BackchannelLockout) time.Duration,
	fallback time.Duration,
) time.Duration {
	if lockout == nil {
		return fallback
	}

	if value := read(lockout); value > 0 {
		return value
	}

	return fallback
}

// GetBackchannelLockout returns the backchannel caller lockout settings.
func (s *ServerSection) GetBackchannelLockout() *BackchannelLockout {
	if s == nil {
		return &BackchannelLockout{}
	}

	return &s.BackchannelLockout
}
