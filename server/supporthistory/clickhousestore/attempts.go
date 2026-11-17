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

package clickhousestore

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/croessner/nauthilus/v4/server/supporthistory"
)

const (
	operationFilter = "operation IN ('authenticate', '')"
	// stepEventFilter selects the step events the history interprets: second factors and OIDC completion.
	stepEventFilter = "event_type IN ('mfa.verification', 'oidc.code_issuance', 'oidc.code_redemption')"
	attemptKeyLogin = "if(flow_ref != '', flow_ref, session)"
	attemptKeyEvent = "if(flow_ref != '', flow_ref, request_id)"
	keyKindExpr     = "if(flow_ref != '', 'flow', 'request')"
)

// loginColumns are the only logins columns the reader selects (no password hash, port, user agent, host, HIBP).
const loginColumns = "toUnixTimestamp64Milli(ts) AS ts_ms, event_id, session, instance, service, proto, method, " +
	"username, account, client_ip, client_net, oidc_cid, saml_entity_id, grant_type, flow_ref, operation, outcome, " +
	"outcome_stage, outcome_marker, response_marker, policy_rule, tempfail_reason, tempfail_checkpoint, policy_status, " +
	"fsm_state, transport, transport_status, user_found, brute_force_bucket, brute_force_tolerated, decision_sources, " +
	"contract_version, reputation_assessments, reputation_truncated, http_status, status_msg"

// eventColumns are the selected auth_events columns.
const eventColumns = "toUnixTimestamp64Milli(ts) AS ts_ms, event_id, event_type, event_version, request_id, flow_ref, " +
	"instance, protocol, client_id, saml_entity_id, account, client_ip, factor_role, method, result, reason, " +
	"flow_effect, fail_latched"

// subjectCondition renders the identity predicate of logins rows.
func subjectCondition(stmt *statement, match supporthistory.SubjectMatch) string {
	var logins, accounts string

	if len(match.Logins) > 0 {
		logins = "username IN " + stmt.texts(match.Logins)
	}

	if len(match.Accounts) > 0 {
		accounts = "(account != '' AND account IN " + stmt.texts(match.Accounts) + ")"
	}

	return anyOf(logins, accounts)
}

// Anchors returns attempt anchors (latest subject-matching activity) newest first.
func (s *Store) Anchors(ctx context.Context, query supporthistory.AnchorQuery) ([]supporthistory.AttemptAnchor, error) {
	stmt := newStatement(s.deployment)
	stmt.timeRange("ts", query.From, query.Until)
	stmt.where(operationFilter)
	stmt.where(subjectCondition(stmt, query.Subject))
	stmt.equalsIfSet("client_ip", query.Filter.ClientIP)
	stmt.equalsIfSet("proto", query.Filter.Protocol)
	stmt.equalsIfSet("oidc_cid", query.Filter.OIDCClientID)
	stmt.equalsIfSet("saml_entity_id", query.Filter.SAMLEntityID)

	inner := "SELECT " + keyKindExpr + " AS key_kind, " + attemptKeyLogin + " AS key_value, ts FROM " +
		s.client.table("logins") + stmt.whereClause()

	if len(query.Subject.Accounts) > 0 {
		events := stmt.sibling(s.deployment)
		events.where(stepEventFilter)
		events.timeRange("ts", query.From, query.Until)
		events.where("account != '' AND account IN " + events.texts(query.Subject.Accounts))
		events.equalsIfSet("client_ip", query.Filter.ClientIP)
		events.equalsIfSet("protocol", query.Filter.Protocol)
		events.equalsIfSet("client_id", query.Filter.OIDCClientID)
		events.equalsIfSet("saml_entity_id", query.Filter.SAMLEntityID)
		inner += " UNION ALL SELECT " + keyKindExpr + ", " + attemptKeyEvent + ", ts FROM " +
			s.client.table("auth_events") + events.whereClause()
	}

	sql := "SELECT key_kind, key_value, toUnixTimestamp64Milli(max(ts)) AS anchor_ms FROM (" + inner +
		") GROUP BY key_kind, key_value"

	if query.Before != nil {
		sql += " HAVING (anchor_ms, key_value) < (" + stmt.integer(query.Before.At.UnixMilli()) + ", " +
			stmt.text(query.Before.Key) + ")"
	}

	sql += " ORDER BY anchor_ms DESC, key_value DESC LIMIT " + strconv.Itoa(max(1, query.Limit))

	var anchors []supporthistory.AttemptAnchor

	err := s.client.query(ctx, sql, stmt.params(), func(raw json.RawMessage) error {
		var row struct {
			Kind   string `json:"key_kind"`
			Value  string `json:"key_value"`
			Anchor optInt `json:"anchor_ms"`
		}

		if err := json.Unmarshal(raw, &row); err != nil {
			return err
		}

		anchors = append(anchors, supporthistory.AttemptAnchor{At: millis(row.Anchor),
			Key: supporthistory.AttemptKey{Kind: supporthistory.AttemptKind(row.Kind), Value: row.Value}})

		return nil
	})

	return anchors, err
}

// RecordedAccounts returns distinct accounts recorded on rows of the literal logins.
func (s *Store) RecordedAccounts(ctx context.Context, query supporthistory.AccountQuery) ([]string, error) {
	if len(query.Logins) == 0 {
		return nil, nil
	}

	stmt := newStatement(s.deployment)
	stmt.timeRange("ts", query.From, query.Until)
	stmt.where(operationFilter)
	stmt.where("username IN " + stmt.texts(query.Logins))
	stmt.where("account != ''")

	sql := "SELECT DISTINCT account FROM " + s.client.table("logins") + stmt.whereClause() +
		" ORDER BY account LIMIT " + strconv.Itoa(max(1, query.Limit))

	var accounts []string

	err := s.client.query(ctx, sql, stmt.params(), func(raw json.RawMessage) error {
		var row struct {
			Account string `json:"account"`
		}

		if err := json.Unmarshal(raw, &row); err != nil {
			return err
		}

		accounts = append(accounts, row.Account)

		return nil
	})

	return accounts, err
}

// groupCondition selects the rows of the requested flows and requests; request rows can be narrowed by subject.
func groupCondition(stmt *statement, query supporthistory.RowQuery, requestColumn string, subject string) string {
	var flows, requests string

	if len(query.Flows) > 0 {
		flows = "flow_ref IN " + stmt.texts(query.Flows)
	}

	if len(query.Requests) > 0 {
		requests = "(flow_ref = '' AND " + requestColumn + " IN " + stmt.texts(query.Requests)
		if subject != "" {
			requests += " AND " + subject
		}

		requests += ")"
	}

	return anyOf(flows, requests)
}

// groupLimit renders the per-attempt and total bounds of a row query.
func groupLimit(query supporthistory.RowQuery, key string) string {
	perGroup := max(1, query.LimitPerGroup)
	total := perGroup * max(1, len(query.Flows)+len(query.Requests))

	return " LIMIT " + strconv.Itoa(perGroup) + " BY " + key + " LIMIT " + strconv.Itoa(total)
}

// LoginRows returns the authenticate and legacy rows of the attempts.
func (s *Store) LoginRows(ctx context.Context, query supporthistory.RowQuery) ([]supporthistory.LoginRecord, error) {
	if len(query.Flows)+len(query.Requests) == 0 {
		return nil, nil
	}

	stmt := newStatement(s.deployment)
	stmt.timeRange("ts", query.From, query.Until)
	stmt.where(operationFilter)

	subject := ""
	if query.Subject != nil {
		subject = subjectCondition(stmt, *query.Subject)
	}

	stmt.where(groupCondition(stmt, query, "session", subject))

	sql := "SELECT " + loginColumns + " FROM " + s.client.table("logins") + stmt.whereClause() +
		" ORDER BY ts, event_id" + groupLimit(query, attemptKeyLogin)

	var records []supporthistory.LoginRecord

	err := s.client.query(ctx, sql, stmt.params(), func(raw json.RawMessage) error {
		var row loginRow
		if err := json.Unmarshal(raw, &row); err != nil {
			return err
		}

		records = append(records, row.record())

		return nil
	})

	return records, err
}

// AuthEvents returns the second-factor and OIDC completion events of the attempts.
func (s *Store) AuthEvents(ctx context.Context, query supporthistory.RowQuery) ([]supporthistory.AuthEventRecord, error) {
	if len(query.Flows)+len(query.Requests) == 0 {
		return nil, nil
	}

	stmt := newStatement(s.deployment)
	stmt.where(stepEventFilter)
	stmt.timeRange("ts", query.From, query.Until)

	subject := ""
	if query.Subject != nil && len(query.Subject.Accounts) > 0 {
		subject = "account IN " + stmt.texts(query.Subject.Accounts)
	}

	stmt.where(groupCondition(stmt, query, "request_id", subject))

	sql := "SELECT " + eventColumns + " FROM " + s.client.table("auth_events") + stmt.whereClause() +
		" ORDER BY ts, event_id" + groupLimit(query, attemptKeyEvent)

	var records []supporthistory.AuthEventRecord

	err := s.client.query(ctx, sql, stmt.params(), func(raw json.RawMessage) error {
		var row eventRow
		if err := json.Unmarshal(raw, &row); err != nil {
			return err
		}

		records = append(records, row.record())

		return nil
	})

	return records, err
}

// loginRow is the JSON shape of one selected logins row.
type loginRow struct {
	Reputation          []reputationTuple `json:"reputation_assessments"`
	TS                  optInt            `json:"ts_ms"`
	TransportStatus     optInt            `json:"transport_status"`
	AnsweredStatusCode  optInt            `json:"http_status"`
	ContractVersion     optInt            `json:"contract_version"`
	UserFound           optBool           `json:"user_found"`
	BruteForceTolerated optBool           `json:"brute_force_tolerated"`
	ReputationTruncated optBool           `json:"reputation_truncated"`
	EventID             string            `json:"event_id"`
	Session             string            `json:"session"`
	Instance            string            `json:"instance"`
	Service             string            `json:"service"`
	Protocol            string            `json:"proto"`
	Method              string            `json:"method"`
	Username            string            `json:"username"`
	Account             string            `json:"account"`
	ClientIP            string            `json:"client_ip"`
	ClientNet           string            `json:"client_net"`
	OIDCClientID        string            `json:"oidc_cid"`
	SAMLEntityID        string            `json:"saml_entity_id"`
	GrantType           string            `json:"grant_type"`
	FlowRef             string            `json:"flow_ref"`
	Operation           string            `json:"operation"`
	Outcome             string            `json:"outcome"`
	OutcomeStage        string            `json:"outcome_stage"`
	OutcomeMarker       string            `json:"outcome_marker"`
	ResponseMarker      string            `json:"response_marker"`
	PolicyRule          string            `json:"policy_rule"`
	TempFailReason      string            `json:"tempfail_reason"`
	TempFailCheckpoint  string            `json:"tempfail_checkpoint"`
	PolicyStatus        string            `json:"policy_status"`
	FSMState            string            `json:"fsm_state"`
	Transport           string            `json:"transport"`
	BruteForceBucket    string            `json:"brute_force_bucket"`
	DecisionSources     string            `json:"decision_sources"`
	StatusMessage       string            `json:"status_msg"`
}

// reputationTuple is one named reputation_assessments tuple.
type reputationTuple struct {
	RiskScore       optFloat `json:"risk_score"`
	TrustScore      optFloat `json:"trust_score"`
	Confidence      optFloat `json:"confidence"`
	Samples         optFloat `json:"samples"`
	SourceDiversity optInt   `json:"source_diversity"`
	AgeSeconds      optInt   `json:"age_seconds"`
	Fact            string   `json:"fact"`
	Role            string   `json:"role"`
	Kind            string   `json:"kind"`
	State           string   `json:"state"`
	Profile         string   `json:"profile"`
	Band            string   `json:"band"`
	Override        string   `json:"override"`
}

// record converts the decoded row.
func (r loginRow) record() supporthistory.LoginRecord {
	record := supporthistory.LoginRecord{At: millis(r.TS), UserFound: r.UserFound.value,
		BruteForceTolerated: r.BruteForceTolerated.value, EventID: r.EventID, Session: r.Session, Instance: r.Instance,
		Service: r.Service, Protocol: r.Protocol, Method: r.Method, Username: r.Username, Account: r.Account,
		ClientIP: r.ClientIP, ClientNet: r.ClientNet, OIDCClientID: r.OIDCClientID, SAMLEntityID: r.SAMLEntityID,
		GrantType: r.GrantType, FlowRef: r.FlowRef, Operation: r.Operation, Outcome: r.Outcome,
		OutcomeStage: r.OutcomeStage, OutcomeMarker: r.OutcomeMarker, ResponseMarker: r.ResponseMarker,
		PolicyRule: r.PolicyRule, TempFailReason: r.TempFailReason, TempFailCheckpoint: r.TempFailCheckpoint,
		PolicyStatus: r.PolicyStatus, FSMState: r.FSMState, Transport: r.Transport,
		BruteForceBucket: r.BruteForceBucket, ContractVersion: int(r.ContractVersion.int()),
		AnsweredStatusCode: int(r.AnsweredStatusCode.int()), AnsweredStatusMessage: r.StatusMessage,
		ReputationTruncated: r.ReputationTruncated.bool(), DecisionSources: splitSources(r.DecisionSources)}

	if r.TransportStatus.value != nil {
		status := int(*r.TransportStatus.value)
		record.TransportStatus = &status
	}

	for _, tuple := range r.Reputation {
		record.Reputation = append(record.Reputation, supporthistory.ReputationAssessment{
			RiskScore: tuple.RiskScore.value, TrustScore: tuple.TrustScore.value, Confidence: tuple.Confidence.value,
			Samples: tuple.Samples.value, SourceDiversity: tuple.SourceDiversity.value, AgeSeconds: tuple.AgeSeconds.value,
			Fact: tuple.Fact, Role: tuple.Role, Kind: tuple.Kind, State: tuple.State, Profile: tuple.Profile,
			Band: tuple.Band, Override: tuple.Override})
	}

	return record
}

// splitSources splits the comma list of fired decision sources.
func splitSources(value string) []string {
	if strings.TrimSpace(value) == "" {
		return []string{}
	}

	parts := strings.Split(value, ",")
	for index := range parts {
		parts[index] = strings.TrimSpace(parts[index])
	}

	return parts
}

// eventRow is the JSON shape of one selected auth_events row.
type eventRow struct {
	TS           optInt  `json:"ts_ms"`
	EventVersion optInt  `json:"event_version"`
	FailLatched  optBool `json:"fail_latched"`
	EventID      string  `json:"event_id"`
	EventType    string  `json:"event_type"`
	RequestID    string  `json:"request_id"`
	FlowRef      string  `json:"flow_ref"`
	Instance     string  `json:"instance"`
	Protocol     string  `json:"protocol"`
	ClientID     string  `json:"client_id"`
	SAMLEntityID string  `json:"saml_entity_id"`
	Account      string  `json:"account"`
	ClientIP     string  `json:"client_ip"`
	FactorRole   string  `json:"factor_role"`
	Method       string  `json:"method"`
	Result       string  `json:"result"`
	Reason       string  `json:"reason"`
	FlowEffect   string  `json:"flow_effect"`
}

// record converts the decoded row.
func (r eventRow) record() supporthistory.AuthEventRecord {
	return supporthistory.AuthEventRecord{At: millis(r.TS), EventID: r.EventID, EventType: r.EventType,
		RequestID: r.RequestID, FlowRef: r.FlowRef, Instance: r.Instance, Protocol: r.Protocol, ClientID: r.ClientID,
		SAMLEntityID: r.SAMLEntityID, Account: r.Account, ClientIP: r.ClientIP, FactorRole: r.FactorRole,
		Method: r.Method, Result: r.Result, Reason: r.Reason, FlowEffect: r.FlowEffect,
		EventVersion: int(r.EventVersion.int()), FailLatched: r.FailLatched.bool()}
}
