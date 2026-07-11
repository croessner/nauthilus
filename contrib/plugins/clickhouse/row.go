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
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/pluginapi/v1/exchange"
)

const (
	sourceNativeGeoIP            = "native_geoip"
	sourcePolicyFacts            = "policy_facts"
	geoIPFieldASN                = "asn"
	geoIPFieldASNAllocated       = "asn_allocated"
	geoIPFieldASNCountryISO      = "asn_country_iso"
	geoIPFieldASNOrg             = "asn_org"
	geoIPFieldASNPrefix          = "asn_prefix"
	geoIPFieldASNRegistry        = "asn_registry"
	geoIPFieldASNStatus          = "asn_status"
	geoIPFieldCityName           = "city_name"
	geoIPFieldCountryISO         = "country_iso"
	geoIPFieldCountryName        = "country_name"
	geoIPFieldCurrentCountryCode = "current_country_code"
	geoIPFieldMatched            = "matched"
	geoIPStatusMatched           = "matched"
	geoIPStatusMiss              = "miss"
)

// clickHouseRow mirrors the Lua clickhouse.lua JSONEachRow field names.
type clickHouseRow struct {
	mappingDiagnostics            []string `json:"-"`
	GeoIPPrivacyClasses           []string `json:"geoip_privacy_classes"`
	GeoIPPrivacySourceAuthorities []string `json:"geoip_privacy_source_authorities"`
	TS                            string   `json:"ts"`
	Session                       string   `json:"session"`
	Service                       string   `json:"service"`
	Deployment                    string   `json:"deployment"`
	Instance                      string   `json:"instance"`
	DecisionSources               string   `json:"decision_sources"`
	ClientIP                      string   `json:"client_ip"`
	ClientPort                    string   `json:"client_port"`
	ClientNet                     string   `json:"client_net"`
	ClientID                      string   `json:"client_id"`
	Hostname                      string   `json:"hostname"`
	Proto                         string   `json:"proto"`
	Method                        string   `json:"method"`
	UserAgent                     string   `json:"user_agent"`
	LocalIP                       string   `json:"local_ip"`
	LocalPort                     string   `json:"local_port"`
	DisplayName                   string   `json:"display_name"`
	Account                       string   `json:"account"`
	Username                      string   `json:"username"`
	PasswordHash                  string   `json:"password_hash"`
	PwndInfo                      string   `json:"pwnd_info"`
	BruteForceBucket              string   `json:"brute_force_bucket"`
	BruteForceCounter             *uint64  `json:"brute_force_counter"`
	OIDCCID                       string   `json:"oidc_cid"`
	SAMLEntityID                  string   `json:"saml_entity_id"`
	GrantType                     string   `json:"grant_type"`
	MFAMethod                     string   `json:"mfa_method"`
	FailedLoginCount              *uint64  `json:"failed_login_count"`
	FailedLoginRank               *uint64  `json:"failed_login_rank"`
	FailedLoginRecognized         *bool    `json:"failed_login_recognized"`
	GeoIPGUID                     string   `json:"geoip_guid"`
	GeoIPCountry                  string   `json:"geoip_country"`
	GeoIPISOCodes                 string   `json:"geoip_iso_codes"`
	GeoIPStatus                   string   `json:"geoip_status"`
	GeoIPSource                   string   `json:"geoip_source"`
	GeoIPMatched                  *bool    `json:"geoip_matched"`
	GeoIPCountryName              string   `json:"geoip_country_name"`
	GeoIPCityName                 string   `json:"geoip_city_name"`
	GeoIPASN                      *uint64  `json:"geoip_asn"`
	GeoIPASNOrg                   string   `json:"geoip_asn_org"`
	GeoIPASNPrefix                string   `json:"geoip_asn_prefix"`
	GeoIPASNRegistry              string   `json:"geoip_asn_registry"`
	GeoIPASNCountry               string   `json:"geoip_asn_country"`
	GeoIPASNAllocated             string   `json:"geoip_asn_allocated"`
	GeoIPASNStatus                string   `json:"geoip_asn_status"`
	GeoIPPrivacyLookupState       string   `json:"geoip_privacy_lookup_state"`
	GeoIPPrivacyPrimaryClass      string   `json:"geoip_privacy_primary_class"`
	GeoIPPrivacyDetected          *bool    `json:"geoip_privacy_detected"`
	GeoIPPrivacyConfidence        *float64 `json:"geoip_privacy_confidence"`
	GeoIPPrivacyDataStale         *bool    `json:"geoip_privacy_data_stale"`
	GeoIPPrivacyDataAgeSeconds    *uint64  `json:"geoip_privacy_data_age_seconds"`
	GeoIPIsTorExitNode            *bool    `json:"geoip_is_tor_exit_node"`
	GeoIPIsKnownVPNExit           *bool    `json:"geoip_is_known_vpn_exit"`
	GeoIPIsCommunityVPNExit       *bool    `json:"geoip_is_community_vpn_exit"`
	GeoIPIsPublicProxy            *bool    `json:"geoip_is_public_proxy"`
	GeoIPIsPrivacyRelay           *bool    `json:"geoip_is_privacy_relay"`
	GeoIPIsHostingNetwork         *bool    `json:"geoip_is_hosting_network"`
	ReputationScore               *float64 `json:"reputation_score"`
	ReputationPositiveScore       *float64 `json:"reputation_positive_score"`
	ReputationNegativeScore       *float64 `json:"reputation_negative_score"`
	ReputationIPScore             *float64 `json:"reputation_ip_score"`
	ReputationASNScore            *float64 `json:"reputation_asn_score"`
	ReputationCountryScore        *float64 `json:"reputation_country_score"`
	ReputationASNCountryScore     *float64 `json:"reputation_asn_country_score"`
	ReputationSamples             *uint64  `json:"reputation_samples"`
	ReputationSource              string   `json:"reputation_source"`
	ReputationDecision            string   `json:"reputation_decision"`
	GPAttempts                    *uint64  `json:"gp_attempts"`
	GPUniqueIPs                   *uint64  `json:"gp_unique_ips"`
	GPUniqueUsers                 *uint64  `json:"gp_unique_users"`
	GPIPsPerUser                  *float64 `json:"gp_ips_per_user"`
	ProtectionActive              *bool    `json:"prot_active"`
	ProtectionReason              string   `json:"prot_reason"`
	ProtectionBackoff             *uint64  `json:"prot_backoff"`
	ProtectionDelayMillis         *uint64  `json:"prot_delay_ms"`
	DynamicThreat                 *uint64  `json:"dyn_threat"`
	DynamicResponse               string   `json:"dyn_response"`
	XSSLProtocol                  string   `json:"xssl_protocol"`
	XSSLCipher                    string   `json:"xssl_cipher"`
	SSLFingerprint                string   `json:"ssl_fingerprint"`
	StatusMessage                 string   `json:"status_msg"`
	Repeating                     bool     `json:"repeating"`
	RWP                           bool     `json:"rwp"`
	UserFound                     bool     `json:"user_found"`
	Authenticated                 bool     `json:"authenticated"`
	Latency                       uint64   `json:"latency"`
	HTTPStatus                    uint64   `json:"http_status"`
}

// buildRow maps one post-action request into the Lua-compatible ClickHouse row.
func buildRow(request pluginapi.PostActionRequest, cfg moduleConfig) (clickHouseRow, error) {
	exchangeSnapshot := exchange.NewSnapshot(request.Runtime, request.Facts)
	geoIPAnalytics := exchangeSnapshot.GeoIPAnalytics()

	row := clickHouseRow{
		TS:                utcNowMillis(),
		Session:           request.Snapshot.Session,
		Service:           request.Snapshot.Service,
		DecisionSources:   exchangeSnapshot.DecisionSourcesString(),
		Deployment:        cfg.Deployment,
		Instance:          cfg.Instance,
		ClientIP:          request.Snapshot.ClientIP,
		ClientPort:        request.Snapshot.ClientPort,
		ClientNet:         request.Snapshot.ClientNet,
		ClientID:          request.Snapshot.ClientID,
		Hostname:          request.Snapshot.ClientHost,
		Proto:             request.Snapshot.Protocol,
		Method:            request.Snapshot.Method,
		UserAgent:         request.Snapshot.UserAgent,
		LocalIP:           request.Snapshot.LocalIP,
		LocalPort:         request.Snapshot.LocalPort,
		DisplayName:       request.Snapshot.DisplayName,
		Account:           request.Snapshot.Account,
		Username:          request.Snapshot.Username,
		PasswordHash:      request.PasswordHash,
		PwndInfo:          exchangeSnapshot.HIBPHashInfo(),
		BruteForceBucket:  request.Snapshot.Diagnostics.BruteForceName,
		BruteForceCounter: uintPointer(uint64(request.Snapshot.Diagnostics.BruteForceCounter)),
		OIDCCID:           request.Snapshot.OIDCCID,
		SAMLEntityID:      request.Snapshot.SAMLEntityID,
		GrantType:         request.Snapshot.IDP.GrantType,
		MFAMethod:         request.Snapshot.IDP.MFAMethod,
		Repeating:         request.Snapshot.Runtime.Repeating,
		RWP:               request.Snapshot.Runtime.RWP,
		UserFound:         request.Snapshot.Runtime.UserFound,
		Authenticated:     request.Snapshot.Runtime.Authenticated,
		XSSLProtocol:      request.Snapshot.TLS.Legacy.Protocol,
		XSSLCipher:        request.Snapshot.TLS.Legacy.CipherSuite,
		SSLFingerprint:    request.Snapshot.TLS.Legacy.Fingerprint,
		Latency:           uint64(nonNegativeInt64(request.Snapshot.Diagnostics.LatencyMillis)),
		HTTPStatus:        uint64(nonNegativeInt(request.Snapshot.Diagnostics.HTTPStatus)),
		StatusMessage:     request.Snapshot.Diagnostics.StatusMessage,
	}

	applyFailedLoginInfo(&row, exchangeSnapshot.Map(exchange.KeyFailedLoginHotspot))
	applyGeoIPInfo(&row, geoIPInfo(geoIPAnalytics.Fields))
	applyGeoIPPrivacyInfo(&row, geoIPAnalytics)
	applyReputationInfo(&row, reputationInfo(exchangeSnapshot))
	applyGlobalPatternInfo(&row, exchangeSnapshot.Map(exchange.KeyGlobalPattern))
	applyAccountProtectionInfo(&row, exchangeSnapshot.Map(exchange.KeyAccountProtection))
	applyDynamicResponseInfo(&row, exchangeSnapshot.Map(exchange.KeyDynamicResponse))

	return row, nil
}

// applyGeoIPPrivacyInfo copies typed privacy analytics and bounded diagnostics.
func applyGeoIPPrivacyInfo(row *clickHouseRow, info exchange.GeoIPAnalytics) {
	privacy := info.Privacy
	row.mappingDiagnostics = append([]string(nil), info.MalformedFields...)
	row.GeoIPPrivacyClasses = append([]string{}, privacy.Classes...)
	row.GeoIPPrivacySourceAuthorities = append([]string{}, privacy.SourceAuthorities...)
	row.GeoIPPrivacyLookupState = privacy.LookupState
	row.GeoIPPrivacyPrimaryClass = privacy.PrimaryClass
	row.GeoIPPrivacyDetected = privacy.Detected
	row.GeoIPPrivacyConfidence = privacy.Confidence
	row.GeoIPPrivacyDataStale = privacy.DataStale
	row.GeoIPPrivacyDataAgeSeconds = privacy.DataAgeSeconds
	row.GeoIPIsTorExitNode = privacy.IsTorExitNode
	row.GeoIPIsKnownVPNExit = privacy.IsKnownVPNExit
	row.GeoIPIsCommunityVPNExit = privacy.IsCommunityVPNExit
	row.GeoIPIsPublicProxy = privacy.IsPublicProxy
	row.GeoIPIsPrivacyRelay = privacy.IsPrivacyRelay
	row.GeoIPIsHostingNetwork = privacy.IsHostingNetwork
}

// applyFailedLoginInfo copies standard failed-login hotspot details.
func applyFailedLoginInfo(row *clickHouseRow, info map[string]any) {
	if len(info) == 0 {
		return
	}

	row.FailedLoginCount = firstUintFromAny(info["count"], info["new_count"])
	row.FailedLoginRank = uintFromAny(info["rank"])

	if value, ok := boolFromAny(info["recognized_account"]); ok {
		row.FailedLoginRecognized = &value
	}
}

// applyGeoIPInfo copies standard GeoIP exchange fields.
func applyGeoIPInfo(row *clickHouseRow, info map[string]any) {
	if len(info) == 0 {
		return
	}

	row.GeoIPGUID = stringValue(info["guid"])
	row.GeoIPCountry = firstStringValue(info[geoIPFieldCountryISO], info[geoIPFieldCurrentCountryCode])
	row.GeoIPISOCodes = isoCodesValue(info["iso_codes_seen"], row.GeoIPCountry)
	row.GeoIPStatus = geoIPStatus(info)
	row.GeoIPSource = firstStringValue(info["source"], sourceNativeGeoIP)

	if value, ok := boolFromAny(info["matched"]); ok {
		row.GeoIPMatched = &value
	}

	row.GeoIPCountryName = stringValue(info["country_name"])
	row.GeoIPCityName = stringValue(info["city_name"])
	row.GeoIPASN = uintFromAny(info["asn"])
	row.GeoIPASNOrg = stringValue(info["asn_org"])
	row.GeoIPASNPrefix = stringValue(info["asn_prefix"])
	row.GeoIPASNRegistry = stringValue(info["asn_registry"])
	row.GeoIPASNCountry = stringValue(info["asn_country_iso"])
	row.GeoIPASNAllocated = stringValue(info["asn_allocated"])
	row.GeoIPASNStatus = stringValue(info["asn_status"])
}

// applyReputationInfo copies GeoIP reputation details from runtime or facts.
func applyReputationInfo(row *clickHouseRow, info reputationDetails) {
	values := info.values
	if len(values) == 0 {
		return
	}

	row.ReputationScore = floatFromAny(values["score"])
	row.ReputationPositiveScore = floatFromAny(values["positive_score"])
	row.ReputationNegativeScore = floatFromAny(values["negative_score"])
	row.ReputationIPScore = floatFromAny(values["ip_score"])
	row.ReputationASNScore = floatFromAny(values["asn_score"])
	row.ReputationCountryScore = floatFromAny(values["country_score"])
	row.ReputationASNCountryScore = floatFromAny(values["asn_country_score"])
	row.ReputationSamples = uintFromAny(values["samples"])
	row.ReputationSource = info.source

	if source := stringValue(values["source"]); source != "" {
		row.ReputationSource = source
	}

	row.ReputationDecision = stringValue(values["decision"])
}

// applyGlobalPatternInfo copies global pattern counters from runtime state.
func applyGlobalPatternInfo(row *clickHouseRow, info map[string]any) {
	if len(info) == 0 {
		return
	}

	row.GPAttempts = uintFromAny(info["attempts"])
	row.GPUniqueIPs = uintFromAny(info["unique_ips"])
	row.GPUniqueUsers = uintFromAny(info["unique_users"])
	row.GPIPsPerUser = floatFromAny(info["ips_per_user"])
}

// applyAccountProtectionInfo copies account protection details from runtime state.
func applyAccountProtectionInfo(row *clickHouseRow, info map[string]any) {
	if len(info) == 0 {
		return
	}

	if value, ok := boolFromAny(info["active"]); ok {
		row.ProtectionActive = &value
	}

	row.ProtectionReason = stringValue(info["reason"])
	row.ProtectionBackoff = uintFromAny(info["backoff_level"])
	row.ProtectionDelayMillis = uintFromAny(info["delay_ms"])
}

// applyDynamicResponseInfo copies dynamic response details from runtime state.
func applyDynamicResponseInfo(row *clickHouseRow, info map[string]any) {
	if len(info) == 0 {
		return
	}

	row.DynamicThreat = uintFromAny(info["threat_level"])
	row.DynamicResponse = stringValue(info["response"])
}

// geoIPInfo normalizes standard GeoIP exchange fields for row mapping.
func geoIPInfo(values map[string]any) map[string]any {
	if len(values) == 0 {
		return nil
	}

	normalized := make(map[string]any, len(values)+2)
	for key, value := range values {
		normalized[key] = value
	}

	country := isoCode(firstStringValue(values[geoIPFieldCountryISO], values[geoIPFieldCurrentCountryCode]))
	if country != "" {
		normalized[geoIPFieldCountryISO] = country
		normalized["iso_codes_seen"] = isoCodesList(country, values["iso_codes_seen"])
	}

	if asnCountry := isoCode(stringValue(values[geoIPFieldASNCountryISO])); asnCountry != "" {
		normalized[geoIPFieldASNCountryISO] = asnCountry
	}

	return normalized
}

// geoIPStatus returns the standard row status for GeoIP exchange data.
func geoIPStatus(info map[string]any) string {
	if status := strings.TrimSpace(stringValue(info["status"])); status != "" {
		return status
	}

	if matched, ok := boolFromAny(info[geoIPFieldMatched]); ok && matched {
		return geoIPStatusMatched
	}

	return geoIPStatusMiss
}

type reputationDetails struct {
	values map[string]any
	source string
}

// reputationInfo returns standard reputation details with policy facts as fallback.
func reputationInfo(snapshot exchange.Snapshot) reputationDetails {
	if values := snapshot.Map(exchange.KeyGeoIPReputation); len(values) > 0 {
		return reputationDetails{values: values, source: stringValue(values["source"])}
	}

	values := snapshot.GeoIPReputation()
	if len(values) == 0 {
		return reputationDetails{}
	}

	return reputationDetails{values: values, source: sourcePolicyFacts}
}

// utcNowMillis returns the ClickHouse DateTime64(3, UTC) timestamp format used by Lua.
func utcNowMillis() string {
	return time.Now().UTC().Format("2006-01-02 15:04:05.000")
}

// stringValue mirrors Lua tostring defaults for string-like optional values.
func stringValue(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	default:
		return fmt.Sprint(typed)
	}
}

// firstStringValue returns the first non-empty string rendering.
func firstStringValue(values ...any) string {
	for _, value := range values {
		if text := strings.TrimSpace(stringValue(value)); text != "" {
			return text
		}
	}

	return ""
}

// uintFromAny converts non-negative numeric values to UInt64-compatible pointers.
//
//nolint:gocyclo // Type-switch breadth keeps runtime conversion explicit and allocation-free.
func uintFromAny(value any) *uint64 {
	switch typed := value.(type) {
	case nil:
		return nil
	case *uint64:
		return typed
	case uint64:
		return uintPointer(typed)
	case uint:
		return uintPointer(uint64(typed))
	case uint32:
		return uintPointer(uint64(typed))
	case uint16:
		return uintPointer(uint64(typed))
	case uint8:
		return uintPointer(uint64(typed))
	case int:
		if typed < 0 {
			return nil
		}

		return uintPointer(uint64(typed))
	case int64:
		if typed < 0 {
			return nil
		}

		return uintPointer(uint64(typed))
	case int32:
		if typed < 0 {
			return nil
		}

		return uintPointer(uint64(typed))
	case float64:
		if typed < 0 || math.IsNaN(typed) || math.IsInf(typed, 0) {
			return nil
		}

		return uintPointer(uint64(math.Floor(typed)))
	case float32:
		return uintFromAny(float64(typed))
	case string:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(typed), 64)
		if err != nil {
			return nil
		}

		return uintFromAny(parsed)
	default:
		return nil
	}
}

// firstUintFromAny returns the first value that can be represented as UInt64.
func firstUintFromAny(values ...any) *uint64 {
	for _, value := range values {
		if converted := uintFromAny(value); converted != nil {
			return converted
		}
	}

	return nil
}

// uintPointer returns a pointer to value.
func uintPointer(value uint64) *uint64 {
	return &value
}

// floatFromAny converts finite numeric values to Float64-compatible pointers.
//
//nolint:gocyclo // Type-switch breadth keeps runtime conversion explicit and allocation-free.
func floatFromAny(value any) *float64 {
	switch typed := value.(type) {
	case nil:
		return nil
	case *float64:
		return typed
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) {
			return nil
		}

		return &typed
	case float32:
		return floatFromAny(float64(typed))
	case int:
		value := float64(typed)

		return &value
	case int64:
		value := float64(typed)

		return &value
	case uint:
		value := float64(typed)

		return &value
	case uint64:
		value := float64(typed)

		return &value
	case string:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(typed), 64)
		if err != nil {
			return nil
		}

		return floatFromAny(parsed)
	default:
		return nil
	}
}

// boolFromAny converts bool-like runtime values.
func boolFromAny(value any) (bool, bool) {
	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		parsed, err := strconv.ParseBool(strings.TrimSpace(typed))
		if err != nil {
			return false, false
		}

		return parsed, true
	default:
		return false, false
	}
}

// isoCodesValue formats ISO country codes like the Lua ClickHouse action.
func isoCodesValue(value any, fallback string) string {
	parts := isoCodesList(fallback, value)
	if len(parts) == 0 {
		return ""
	}

	return strings.Join(parts, ",")
}

// isoCodesList collects unique two-letter ISO codes with stable order.
func isoCodesList(countryCode string, existing any) []string {
	var codes []string

	seen := make(map[string]struct{})
	add := func(value string) {
		code := isoCode(value)
		if code == "" {
			return
		}

		if _, ok := seen[code]; ok {
			return
		}

		seen[code] = struct{}{}
		codes = append(codes, code)
	}

	for _, value := range exchange.StringList(existing) {
		add(value)
	}

	add(countryCode)

	return codes
}

// isoCode normalizes ISO-3166 alpha-2 values.
func isoCode(value string) string {
	code := strings.ToUpper(strings.TrimSpace(value))
	if len(code) != 2 {
		return ""
	}

	for _, char := range code {
		if char < 'A' || char > 'Z' {
			return ""
		}
	}

	return code
}

// nonNegativeInt maps negative ints to zero.
func nonNegativeInt(value int) int {
	if value < 0 {
		return 0
	}

	return value
}

// nonNegativeInt64 maps negative int64 values to zero.
func nonNegativeInt64(value int64) int64 {
	if value < 0 {
		return 0
	}

	return value
}
