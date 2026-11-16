// Copyright (C) 2026 Christian Roessner
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

package main

import (
	"context"
	"encoding/json"
	"fmt"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

// componentBruteForceSink is the local name of the brute-force event sink component.
const componentBruteForceSink = "bruteforce_events"

var _ pluginapi.BruteForceEventSink = bruteForceEventTarget{}

// bruteForceEventTarget writes lifecycle events into nauthilus.bruteforce_lifecycle and volume events into
// nauthilus.bruteforce_attempts, each kind through its own bounded stream.
type bruteForceEventTarget struct {
	plugin *Plugin
}

// bruteForceEventRow holds the columns shared by both brute-force tables.
type bruteForceEventRow struct {
	WindowIndex     *int64   `json:"window_index"`
	Current         *int64   `json:"window_current"`
	Previous        *int64   `json:"window_previous"`
	Total           *float64 `json:"total"`
	Limit           *float64 `json:"effective_limit"`
	TS              string   `json:"ts"`
	EventID         string   `json:"event_id"`
	Kind            string   `json:"kind"`
	Deployment      string   `json:"deployment"`
	Instance        string   `json:"instance"`
	RequestID       string   `json:"request_id"`
	Network         string   `json:"network"`
	Rule            string   `json:"rule"`
	RuleFingerprint string   `json:"rule_fingerprint"`
	BucketID        string   `json:"bucket_id"`
	PeriodSeconds   int64    `json:"period_seconds"`
	BanTimeSeconds  int64    `json:"ban_time_seconds"`
	FailedRequests  int64    `json:"failed_requests"`
	EventVersion    uint16   `json:"event_version"`
	CIDR            uint8    `json:"cidr"`
	IPFamily        uint8    `json:"ip_family"`
}

// bruteForceLifecycleRow is one nauthilus.bruteforce_lifecycle row; it never carries claimed login names or the client
// address, because the activating request can be an uninvolved user behind the banned network.
type bruteForceLifecycleRow struct {
	bruteForceEventRow
	ExpiresAt          *string `json:"expires_at"`
	KeysRemoved        *int64  `json:"keys_removed"`
	StoredRule         string  `json:"stored_rule"`
	ReleaseSource      string  `json:"release_source"`
	OperatorClientID   string  `json:"operator_client_id"`
	OperatorAuthMethod string  `json:"operator_auth_method"`
}

// bruteForceAttemptRow is one nauthilus.bruteforce_attempts row of a counted, tolerated, or hit event.
type bruteForceAttemptRow struct {
	bruteForceEventRow
	Weight           *float64 `json:"weight"`
	Crossed          *bool    `json:"crossed"`
	BanActive        *bool    `json:"ban_active"`
	AccountKnown     *bool    `json:"account_known"`
	ClientIP         string   `json:"client_ip"`
	BucketProtocol   string   `json:"bucket_protocol"`
	BucketOIDCClient string   `json:"bucket_oidc_client"`
	CountSource      string   `json:"count_source"`
	ClaimedUsername  string   `json:"claimed_username"`
	Account          string   `json:"account"`
	Protocol         string   `json:"protocol"`
	OIDCClientID     string   `json:"oidc_client_id"`
	HitSource        string   `json:"hit_source"`
}

// Name returns the component identity.
func (bruteForceEventTarget) Name() string {
	return componentBruteForceSink
}

// ObserveBruteForceEvent admits one event into its stream. Volume streams flush inline from the host lane goroutine
// when their batch is full; that goroutine is never an authentication request. The inline flush stays inside the host
// delivery deadline, keeps failed rows in the stream for the ticker worker, and never turns an admitted event into a
// delivery failure.
func (t bruteForceEventTarget) ObserveBruteForceEvent(ctx context.Context, event pluginapi.BruteForceEvent) error {
	if t.plugin == nil {
		return fmt.Errorf("clickhouse brute-force sink has no plugin")
	}

	stream := t.plugin.bruteForceStreamFor(event.Kind)
	state := t.plugin.snapshotFor(stream)

	if state.insertURL == "" || state.cache == nil {
		state.metrics.recordQueueResult(ctx, resultSkipped)

		return nil
	}

	encoded, err := encodeBruteForceRow(event, state.config)
	if err != nil {
		state.metrics.recordQueueResult(ctx, resultEncodeError)

		return err
	}

	length := state.queue.pushRows(ctx, string(encoded))
	if length < 0 {
		return nil
	}

	state.metrics.recordQueueResult(ctx, resultQueued)

	if event.Kind.Lifecycle() || length < min(state.config.BatchSize, state.config.MaxBufferRows) {
		return nil
	}

	flushCtx, cancel := context.WithTimeout(ctx, state.config.Timeout)
	defer cancel()

	_ = flushBatch(flushCtx, state)

	return nil
}

// bruteForceStreamFor selects the stream of one event kind.
func (p *Plugin) bruteForceStreamFor(kind pluginapi.BruteForceEventKind) *rowStream {
	switch {
	case kind.Lifecycle():
		return &p.bfLifecycle
	case kind == pluginapi.BruteForceBanHit:
		return &p.bfHits
	default:
		return &p.bfCounted
	}
}

// encodeBruteForceRow maps one event onto its table row.
func encodeBruteForceRow(event pluginapi.BruteForceEvent, cfg moduleConfig) ([]byte, error) {
	shared := bruteForceEventRow{
		WindowIndex: event.WindowIndex, Current: event.Current, Previous: event.Previous, Total: event.Total,
		Limit: event.Limit, TS: event.ObservedAt.UTC().Format(clickHouseTimestampLayout), EventID: event.EventID,
		Kind: string(event.Kind), Deployment: cfg.Deployment, Instance: cfg.Instance, RequestID: event.RequestID,
		Network: event.Network, Rule: event.Rule, RuleFingerprint: event.RuleFingerprint,
		BucketID: event.BucketID, PeriodSeconds: event.PeriodSeconds, BanTimeSeconds: event.BanTimeSeconds,
		FailedRequests: event.FailedRequests, EventVersion: event.Version, CIDR: event.CIDR, IPFamily: event.IPFamily,
	}

	if event.Kind.Lifecycle() {
		row := bruteForceLifecycleRow{
			bruteForceEventRow: shared, KeysRemoved: event.KeysRemoved, StoredRule: event.StoredRule,
			ReleaseSource: event.ReleaseSource, OperatorClientID: event.OperatorClientID,
			OperatorAuthMethod: event.OperatorAuthMethod,
		}

		if event.ExpiresAt != nil {
			expiresAt := event.ExpiresAt.UTC().Format(clickHouseTimestampLayout)
			row.ExpiresAt = &expiresAt
		}

		return json.Marshal(row)
	}

	return json.Marshal(bruteForceAttemptRow{
		bruteForceEventRow: shared, Weight: event.Weight, Crossed: event.Crossed, BanActive: event.BanActive,
		AccountKnown: event.AccountKnown, ClientIP: event.ClientIP, BucketProtocol: event.BucketProtocol, BucketOIDCClient: event.BucketOIDCClient,
		CountSource: event.CountSource, ClaimedUsername: event.ClaimedUsername, Account: event.Account,
		Protocol: event.Protocol, OIDCClientID: event.OIDCClientID, HitSource: event.HitSource,
	})
}
