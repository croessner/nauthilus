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

import (
	"context"
	"time"
)

// Brute-force event kinds (contract §13.2).
const (
	kindCounted       = "counted"
	kindTolerated     = "threshold_tolerated"
	kindHit           = "ban_hit"
	kindActivated     = "ban_activated"
	kindUnconfirmed   = "ban_activation_unconfirmed"
	kindReleased      = "ban_released"
	kindCountersReset = "counters_reset"
)

// Prefix is one IP family and prefix length a brute-force rule bans by.
type Prefix struct {
	Family int
	Bits   int
}

// PrefixSource returns the prefixes of the configured brute-force rules.
type PrefixSource func() []Prefix

// LifecycleRecord is one stored bruteforce_lifecycle row.
type LifecycleRecord struct {
	At                 time.Time
	ExpiresAt          *time.Time
	WindowIndex        *int64
	WindowCurrent      *int64
	WindowPrevious     *int64
	Total              *float64
	EffectiveLimit     *float64
	KeysRemoved        *int64
	EventID            string
	Kind               string
	Instance           string
	RequestID          string
	Network            string
	Rule               string
	RuleFingerprint    string
	StoredRule         string
	BucketID           string
	ReleaseSource      string
	OperatorClientID   string
	OperatorAuthMethod string
	PeriodSeconds      int64
	BanTimeSeconds     int64
	FailedRequests     int64
}

// CountedRecord is one stored counted contribution of bruteforce_attempts.
type CountedRecord struct {
	At              time.Time
	WindowIndex     *int64
	WindowCurrent   *int64
	Crossed         *bool
	AccountKnown    *bool
	BanActive       *bool
	EventID         string
	RequestID       string
	ClientIP        string
	CountSource     string
	ClaimedUsername string
	Account         string
	Protocol        string
}

// WindowSummary is the hourly aggregate of one bucket window folded over its hours.
type WindowSummary struct {
	MinCurrent   *int64
	MaxCurrent   *int64
	Events       int64
	ClaimedNames int64
	WindowIndex  int64
}

// NetworkInterval is a half-open time interval of one network.
type NetworkInterval struct {
	From    time.Time
	Until   time.Time
	Network string
}

// LifecycleQuery selects the newest lifecycle rows of candidate networks, at most PerNetwork per network.
type LifecycleQuery struct {
	From       time.Time
	Until      time.Time
	Networks   []string
	PerNetwork int
}

// ContributionQuery selects the counted rows of one activation per contract §13.4.
type ContributionQuery struct {
	From        time.Time
	Until       time.Time
	ResetAfter  *time.Time
	ResetBefore *time.Time
	Network     string
	BucketID    string
	WindowIndex int64
	Current     int64
	Previous    int64
	Limit       int
}

// SummaryQuery selects the hourly aggregates of bucket windows.
type SummaryQuery struct {
	Network       string
	BucketID      string
	Kind          string
	WindowIndexes []int64
}

// KindQuery aggregates volume-lane rows of one kind over networks and a range, minus excluded intervals.
type KindQuery struct {
	From      time.Time
	Until     time.Time
	Subject   *SubjectMatch
	Kind      string
	Networks  []string
	Exclude   []NetworkInterval
	Claimants int
	Summary   bool
}

// KindAggregate is the deduplicated count of one kind; Summary counts are upper bounds under replay.
type KindAggregate struct {
	BySource      map[string]int64
	DistinctNames *int64
	SubjectHits   *int64
	Claimants     []ClaimantRecord
	Total         int64
}

// RequestHitQuery selects the recorded ban hits of known requests on candidate networks. Networks keep the read on
// the primary key; RequestIDs are the request ids (logins.session) of the requests to link.
type RequestHitQuery struct {
	From       time.Time
	Until      time.Time
	Networks   []string
	RequestIDs []string
	Limit      int
}

// HitRecord is one recorded ban_hit row of bruteforce_attempts: the ban key network a request was rejected by.
type HitRecord struct {
	At        time.Time
	EventID   string
	RequestID string
	Network   string
	Rule      string
	BucketID  string
	HitSource string
}

// ClaimantRecord is one claimed name and account with its hit count.
type ClaimantRecord struct {
	ClaimedUsername string
	Account         string
	Hits            int64
}

// BanStore is the narrow read surface of recorded brute-force evidence.
type BanStore interface {
	// Prefixes returns the distinct prefixes recorded in lifecycle and summary rows of the deployment; with an error
	// the returned prefixes can still be a usable partial set.
	Prefixes(ctx context.Context) ([]Prefix, error)

	// Lifecycle returns the deduplicated, newest lifecycle rows of the networks, at most PerNetwork per network.
	Lifecycle(ctx context.Context, query LifecycleQuery) ([]LifecycleRecord, error)

	// Contributions returns the deduplicated counted rows of one activation.
	Contributions(ctx context.Context, query ContributionQuery) ([]CountedRecord, error)

	// WindowSummaries returns the aggregates of the requested bucket windows.
	WindowSummaries(ctx context.Context, query SummaryQuery) ([]WindowSummary, error)

	// KindCounts aggregates one kind from raw rows or, with Summary, from the hourly aggregate.
	KindCounts(ctx context.Context, query KindQuery) (KindAggregate, error)

	// RequestHits returns the deduplicated ban_hit rows of the requests on the networks, oldest first.
	RequestHits(ctx context.Context, query RequestHitQuery) ([]HitRecord, error)

	// Presence reports whether a source holds rows of the deployment within its retention.
	Presence(ctx context.Context, source Source) SourcePresence
}
