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

// Package dnsclient provides the shared outbound DNS client with overlapping
// retries and an optional pool of reusable UDP sockets.
package dnsclient

import (
	"time"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
)

// Settings is the comparable transport configuration of one Client.
type Settings struct {
	// Resolver is an optional host:port that replaces the system resolvers.
	Resolver string

	// Timeout is the total budget of one lookup, including all attempts.
	Timeout time.Duration

	// RetryInterval is the delay before another attempt is started while
	// earlier attempts keep running. Zero spreads the attempts evenly over Timeout.
	RetryInterval time.Duration

	// Attempts is the maximum number of queries sent for one lookup.
	Attempts int

	// PoolSize is the number of idle UDP sockets kept per resolver. Zero disables pooling.
	PoolSize int

	// PoolMaxUses is the number of queries after which a pooled socket is replaced.
	PoolMaxUses int
}

// SettingsFromConfig projects the DNS client configuration into Settings.
func SettingsFromConfig(cfg config.File) Settings {
	if cfg == nil {
		return Settings{}.normalized()
	}

	dns := cfg.GetServer().GetDNS()

	return Settings{
		Resolver:      dns.GetResolver(),
		Timeout:       dns.GetTimeout(),
		RetryInterval: dns.GetRetryInterval(),
		Attempts:      dns.GetAttempts(),
		PoolSize:      dns.GetPoolSize(),
		PoolMaxUses:   dns.GetPoolMaxUses(),
	}.normalized()
}

// normalized returns the settings with defaults applied to unset values.
func (s Settings) normalized() Settings {
	if s.Timeout <= 0 {
		s.Timeout = definitions.DNSResolveTimeout * time.Second
	}

	if s.Attempts <= 0 {
		s.Attempts = definitions.DNSLookupAttempts
	}

	if s.RetryInterval <= 0 {
		s.RetryInterval = s.Timeout / time.Duration(s.Attempts)
	}

	if s.PoolSize < 0 {
		s.PoolSize = 0
	}

	if s.PoolMaxUses <= 0 {
		s.PoolMaxUses = definitions.DNSPoolMaxUses
	}

	return s
}
