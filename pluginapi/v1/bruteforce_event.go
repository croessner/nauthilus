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

package pluginapi

import (
	"context"
	"time"
)

// BruteForceEventVersion is the current BruteForceEvent contract version.
const BruteForceEventVersion uint16 = 1

// BruteForceEventKind names one observed brute-force counting or ban lifecycle transition.
type BruteForceEventKind string

const (
	// BruteForceCounted is one increment the bucket counter really applied.
	BruteForceCounted BruteForceEventKind = "counted"
	// BruteForceThresholdTolerated is an over-limit bucket whose ban was suppressed by toleration.
	BruteForceThresholdTolerated BruteForceEventKind = "threshold_tolerated"
	// BruteForceBanHit is a request rejected by an already existing ban.
	BruteForceBanHit BruteForceEventKind = "ban_hit"
	// BruteForceBanActivated is a new ban instance written by this host.
	BruteForceBanActivated BruteForceEventKind = "ban_activated"
	// BruteForceBanActivationUnconfirmed is a ban that exists although this host could not confirm writing it.
	BruteForceBanActivationUnconfirmed BruteForceEventKind = "ban_activation_unconfirmed"
	// BruteForceBanReleased is a ban removed by an administrative flush.
	BruteForceBanReleased BruteForceEventKind = "ban_released"
	// BruteForceCountersReset is an administrative removal of bucket counters.
	BruteForceCountersReset BruteForceEventKind = "counters_reset"
)

// Lifecycle reports whether the kind is a rare ban lifecycle transition that must not compete with volume events.
func (k BruteForceEventKind) Lifecycle() bool {
	switch k {
	case BruteForceBanActivated, BruteForceBanActivationUnconfirmed, BruteForceBanReleased, BruteForceCountersReset:
		return true
	default:
		return false
	}
}

// Brute-force ban hit sources.
const (
	// BruteForceHitRedis marks a ban found in Redis.
	BruteForceHitRedis = "redis"
	// BruteForceHitL1 marks a ban found in the short-lived in-process decision cache.
	BruteForceHitL1 = "l1"
	// BruteForceHitActivationRace marks a request that lost the ban-creation race to a concurrent request.
	BruteForceHitActivationRace = "activation_race"
)

// Brute-force ban release sources.
const (
	// BruteForceReleaseAdminFlush marks the IP/rule brute-force flush endpoint.
	BruteForceReleaseAdminFlush = "admin_flush"
	// BruteForceReleaseUserFlush marks the user cache flush, which removes the bans of the user's IP history.
	BruteForceReleaseUserFlush = "user_flush"
)

// BruteForceEvent is one bounded, secret-free brute-force transition observed by the host where the counter or ban
// decision happened. Pointer fields are nil when the value was not known at that point. It never contains passwords,
// password hashes, or repeated-wrong-password state. ClaimedUsername is the login name as entered; it is a claim, not
// an identity, and is only set on volume kinds.
type BruteForceEvent struct {
	ObservedAt         time.Time
	ExpiresAt          *time.Time
	WindowIndex        *int64
	Weight             *float64
	Current            *int64
	Previous           *int64
	Total              *float64
	Limit              *float64
	Crossed            *bool
	BanActive          *bool
	AccountKnown       *bool
	KeysRemoved        *int64
	EventID            string
	RequestID          string
	ClientIP           string
	Network            string
	Rule               string
	RuleFingerprint    string
	BucketID           string
	BucketProtocol     string
	BucketOIDCClient   string
	CountSource        string
	ClaimedUsername    string
	Account            string
	Protocol           string
	OIDCClientID       string
	HitSource          string
	StoredRule         string
	ReleaseSource      string
	OperatorClientID   string
	OperatorAuthMethod string
	Kind               BruteForceEventKind
	PeriodSeconds      int64
	BanTimeSeconds     int64
	FailedRequests     int64
	CIDR               uint8
	IPFamily           uint8
	Version            uint16
}

// BruteForceEventSink receives host brute-force events on a dedicated host lane goroutine, never on a request.
// ObserveBruteForceEvent must return within the deadline of its context; a sink may flush a full batch inline as long
// as it honours that deadline.
type BruteForceEventSink interface {
	Name() string
	ObserveBruteForceEvent(context.Context, BruteForceEvent) error
}

// BruteForceEventRegistrar is an optional additive registrar for brute-force event sinks.
type BruteForceEventRegistrar interface {
	RegisterBruteForceEventSink(BruteForceEventSink) error
}
