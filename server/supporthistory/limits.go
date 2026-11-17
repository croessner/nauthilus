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

package supporthistory

import "time"

// Shared limits. They live in the service so every transport gets exactly the same bounds.
const (
	// MaxWindow is the largest accepted time window of one request.
	MaxWindow = 31 * 24 * time.Hour

	// DefaultPageLimit is the attempt or ban page size when the caller sends none.
	DefaultPageLimit = 20

	// MaxAttemptPageLimit bounds the attempts of one search page.
	MaxAttemptPageLimit = 50

	// DefaultBanPageLimit is the ban page size when the caller sends none.
	DefaultBanPageLimit = 10

	// MaxBanPageLimit bounds the bans of one page.
	MaxBanPageLimit = 20

	// MaxEventsPerAttempt bounds the events returned for one attempt.
	MaxEventsPerAttempt = 200

	// MaxContributions bounds the listed counted contributions of one ban.
	MaxContributions = 500

	// MaxClaimants bounds the named hit claimants of one ban in the detail projection.
	MaxClaimants = 50

	// MaxLifecycleRows bounds the lifecycle rows read for the candidate networks of one ban search.
	MaxLifecycleRows = 2000

	// maxSubjectLength bounds subject values.
	maxSubjectLength = 256

	// maxCandidatePrefixes bounds the prefix lengths considered for one IP.
	maxCandidatePrefixes = 64

	// sliceSpan is the initial newest-first scan slice of attempt searches.
	sliceSpan = 24 * time.Hour

	// minSliceSpan is the smallest slice tried before a search is rejected as too broad.
	minSliceSpan = time.Hour

	// initialAttemptMargin is the first read margin around attempt anchors.
	initialAttemptMargin = 30 * time.Minute

	// widenedAttemptMargin is the read margin used when rows touch the initial margin boundary.
	widenedAttemptMargin = 2 * time.Hour

	// flowSilenceBound is the longest silence between two events of one IdP flow that the IdP permits: the
	// step-up re-save TTL (server/handler/frontend/idp require_mfa.go). Rows closer than this to a read boundary
	// can have siblings beyond it.
	flowSilenceBound = 15 * time.Minute

	// hitAttributionGrace tolerates L1 cache lag and clock skew when attributing hits to a ban instance.
	hitAttributionGrace = time.Second

	// lateEventHorizon covers the export delays (login flush 60 s, event flush 10 s) plus skew; windows that end
	// inside it can still receive rows.
	lateEventHorizon = 5 * time.Minute

	// maxConcurrentOperations bounds history operations of the whole process.
	maxConcurrentOperations = 4

	// maxConcurrentPerCaller bounds history operations of one caller identity.
	maxConcurrentPerCaller = 2

	// gateWait is how long a call may wait for a free gate slot.
	gateWait = 250 * time.Millisecond
)

// Retention of the recorded sources (contract §7.5, §13.3, schema TTLs).
const (
	loginRetention     = 7 * 24 * time.Hour
	eventRetention     = 7 * 24 * time.Hour
	rawBanRetention    = 14 * 24 * time.Hour
	lifecycleRetention = 400 * 24 * time.Hour
)
