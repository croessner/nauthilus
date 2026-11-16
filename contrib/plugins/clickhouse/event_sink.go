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

// componentEventSink is the local name of the step-event sink component.
const componentEventSink = "auth_events"

var _ pluginapi.AuthEventSink = authEventTarget{}

// authEventTarget enqueues host step events into the nauthilus.auth_events stream.
type authEventTarget struct {
	plugin *Plugin
}

// authEventRow mirrors the nauthilus.auth_events JSONEachRow columns of event contract version 1.
type authEventRow struct {
	TS           string `json:"ts"`
	EventID      string `json:"event_id"`
	EventType    string `json:"event_type"`
	Deployment   string `json:"deployment"`
	Instance     string `json:"instance"`
	RequestID    string `json:"request_id"`
	FlowRef      string `json:"flow_ref"`
	Protocol     string `json:"protocol"`
	ClientID     string `json:"client_id"`
	SAMLEntityID string `json:"saml_entity_id"`
	Account      string `json:"account"`
	ClientIP     string `json:"client_ip"`
	FactorRole   string `json:"factor_role"`
	Method       string `json:"method"`
	Result       string `json:"result"`
	Reason       string `json:"reason"`
	FlowEffect   string `json:"flow_effect"`
	EventVersion uint16 `json:"event_version"`
	FailLatched  bool   `json:"fail_latched"`
}

// Name returns the component identity.
func (authEventTarget) Name() string {
	return componentEventSink
}

// ObserveAuthEvent encodes one event and admits it into the bounded event stream without inserting inline.
func (t authEventTarget) ObserveAuthEvent(ctx context.Context, event pluginapi.AuthEvent) error {
	if t.plugin == nil {
		return fmt.Errorf("clickhouse event sink has no plugin")
	}

	state := t.plugin.snapshotFor(&t.plugin.events)
	if state.insertURL == "" || state.cache == nil {
		state.metrics.recordQueueResult(ctx, resultSkipped)

		return nil
	}

	encoded, err := json.Marshal(newAuthEventRow(event, state.config))
	if err != nil {
		state.metrics.recordQueueResult(ctx, resultEncodeError)

		return err
	}

	if state.queue.pushRows(ctx, string(encoded)) < 0 {
		return nil
	}

	state.metrics.recordQueueResult(ctx, resultQueued)

	return nil
}

// newAuthEventRow maps one host event onto the auth_events row.
func newAuthEventRow(event pluginapi.AuthEvent, cfg moduleConfig) authEventRow {
	return authEventRow{
		TS: event.ObservedAt.UTC().Format(clickHouseTimestampLayout), EventID: event.EventID,
		EventType: string(event.Type), Deployment: cfg.Deployment, Instance: cfg.Instance, RequestID: event.RequestID,
		FlowRef: event.FlowRef, Protocol: event.Protocol, ClientID: event.ClientID, SAMLEntityID: event.SAMLEntityID,
		Account: event.Account, ClientIP: event.ClientIP, FactorRole: event.FactorRole, Method: event.Method,
		Result: string(event.Result), Reason: event.Reason, FlowEffect: string(event.FlowEffect),
		EventVersion: event.Version, FailLatched: event.FailLatched,
	}
}
