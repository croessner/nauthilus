// Copyright (C) 2024 Christian Rößner
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
	"net"
	"time"
)

type BruteForceSection struct {
	SoftWhitelist      `mapstructure:"soft_whitelist"`
	IPWhitelist        []string         `mapstructure:"ip_whitelist" validate:"omitempty,dive,ip_addr|cidr"`
	Buckets            []BruteForceRule `mapstructure:"buckets" validate:"required,dive"`
	Learning           []*Feature       `mapstructure:"learning" validate:"omitempty,dive"`
	ToleratePercent    uint8            `mapstructure:"tolerate_percent" validate:"omitempty,min=0,max=100"`
	CustomTolerations  []Tolerate       `mapstructure:"custom_tolerations" validate:"omitempty,dive"`
	TolerateTTL        time.Duration    `mapstructure:"tolerate_ttl" validate:"omitempty,gt=0,max=8760h"`
	AdaptiveToleration bool             `mapstructure:"adaptive_toleration"`
	MinToleratePercent uint8            `mapstructure:"min_tolerate_percent" validate:"omitempty,min=0,max=100"`
	MaxToleratePercent uint8            `mapstructure:"max_tolerate_percent" validate:"omitempty,min=0,max=100"`
	ScaleFactor        float64          `mapstructure:"scale_factor" validate:"omitempty,min=0.1,max=10"`

	// Reduce PW_HIST write amplification while an IP/net is already blocked:
	// If true, account-scoped PW_HIST entries are only written for known accounts (no fallback to username)
	// when the request is served from an already-triggered (cached) brute-force block.
	LogHistoryForKnownAccounts bool `mapstructure:"pw_history_for_known_accounts"`

	// IPv6 scoping options for features that use password-history (PW_HIST), e.g., repeating-wrong-password.
	// If set to >0, IPv6 addresses will be considered on the given CIDR instead of /128 for the respective context.
	IPScoping IPScoping `mapstructure:"ip_scoping"`

	// Cold-start grace: one-time grace for known accounts without negative PW history.
	ColdStartGraceEnabled bool          `mapstructure:"cold_start_grace_enabled"`
	ColdStartGraceTTL     time.Duration `mapstructure:"cold_start_grace_ttl" validate:"omitempty,gt=0,max=8760h"`

	// RWP allowance: tolerate up to N unique wrong password hashes in a time window
	AllowedUniqueWrongPWHashes uint          `mapstructure:"rwp_allowed_unique_hashes" validate:"omitempty,min=1,max=100"`
	RWPWindow                  time.Duration `mapstructure:"rwp_window" validate:"omitempty,gt=0,max=8760h"`
}

// IPScoping configures how client IPs are normalized/scoped for different contexts.
// This is intentionally generic to allow reuse by tolerations in the future.
type IPScoping struct {
	// RepeatingWrongPasswordIPv6CIDR defines the IPv6 CIDR to use when evaluating/storing
	// password-history for repeating-wrong-password detection. 0 disables special handling (default /128).
	RepeatingWrongPasswordIPv6CIDR uint `mapstructure:"rwp_ipv6_cidr" validate:"omitempty,min=1,max=128"`

	// TolerationsIPv6CIDR defines the IPv6 CIDR to use for tolerations buckets. 0 disables (default /128).
	TolerationsIPv6CIDR uint `mapstructure:"tolerations_ipv6_cidr" validate:"omitempty,min=1,max=128"`
}

func (b *BruteForceSection) String() string {
	if b == nil {
		return "<nil>"
	}

	return fmt.Sprintf("Buckets: %+v, IP-Whitelist: %+v", b.Buckets, b.IPWhitelist)
}

// LearnFromFeature checks if the given feature is present in the Learning slice of the BruteForceSection.
// It returns true if the feature is found, otherwise false.
func (b *BruteForceSection) LearnFromFeature(input string) bool {
	if b == nil {
		return false
	}

	if b.Learning == nil {
		return false
	}

	if len(b.Learning) == 0 {
		return false
	}

	for _, feature := range b.Learning {
		if input == feature.Get() {
			return true
		}
	}

	return false
}

// GetToleratePercent retrieves the ToleratePercent value from the BruteForceSection instance. Returns 0 if the receiver is nil.
func (b *BruteForceSection) GetToleratePercent() uint8 {
	if b == nil {
		return 0
	}

	return b.ToleratePercent
}

// GetTolerateTTL retrieves the TolerateTTL value from the BruteForceSection instance. Returns 0 if the receiver is nil.
func (b *BruteForceSection) GetTolerateTTL() time.Duration {
	if b == nil {
		return 0
	}

	return b.TolerateTTL
}

// GetCustomTolerations returns the CustomTolerations slice from the BruteForceSection. Returns an empty slice if the receiver is nil.
func (b *BruteForceSection) GetCustomTolerations() []Tolerate {
	if b == nil {
		return []Tolerate{}
	}

	return b.CustomTolerations
}

// GetAdaptiveToleration retrieves the AdaptiveToleration value from the BruteForceSection instance.
// Returns false if the receiver is nil.
func (b *BruteForceSection) GetAdaptiveToleration() bool {
	if b == nil {
		return false
	}

	return b.AdaptiveToleration
}

// GetMinToleratePercent retrieves the MinToleratePercent value from the BruteForceSection instance.
// Returns 10 as default if not set or if the receiver is nil.
func (b *BruteForceSection) GetMinToleratePercent() uint8 {
	if b == nil {
		return 10
	}

	if b.MinToleratePercent == 0 {
		return 10 // Default value
	}

	return b.MinToleratePercent
}

// GetMaxToleratePercent retrieves the MaxToleratePercent value from the BruteForceSection instance.
// Returns 50 as default if not set or if the receiver is nil.
func (b *BruteForceSection) GetMaxToleratePercent() uint8 {
	if b == nil {
		return 50
	}

	if b.MaxToleratePercent == 0 {
		return 50 // Default value
	}

	return b.MaxToleratePercent
}

// GetScaleFactor retrieves the ScaleFactor value from the BruteForceSection instance.
// Returns 1.0 as default if not set or if the receiver is nil.
func (b *BruteForceSection) GetScaleFactor() float64 {
	if b == nil {
		return 1.0
	}

	if b.ScaleFactor == 0 {
		return 1.0 // Default value
	}

	return b.ScaleFactor
}

// GetSoftWhitelist retrieves the SoftWhitelist from the BruteForceSection.
// Returns an empty map if the BruteForceSection is nil.
func (b *BruteForceSection) GetSoftWhitelist() SoftWhitelist {
	if b == nil {
		return map[string][]string{}
	}

	return b.SoftWhitelist
}

// GetIPWhitelist retrieves the IP whitelist from the BruteForceSection.
// Returns an empty slice if the BruteForceSection is nil.
func (b *BruteForceSection) GetIPWhitelist() []string {
	if b == nil {
		return []string{}
	}

	return b.IPWhitelist
}

// GetBuckets retrieves the list of brute force rules from the BruteForceSection.
// Returns an empty slice if the BruteForceSection is nil.
func (b *BruteForceSection) GetBuckets() []BruteForceRule {
	if b == nil {
		return []BruteForceRule{}
	}

	return b.Buckets
}

// GetIPScoping returns the IPScoping settings or a zero-value if not present.
func (b *BruteForceSection) GetIPScoping() IPScoping {
	if b == nil {
		return IPScoping{}
	}

	return b.IPScoping
}

// GetPWHistKnownAccountsOnlyOnAlreadyTriggered returns whether per-account PW_HIST should be limited
// to known accounts (no username fallback) when a request is already cached-blocked.
// Supports both the new short key (pw_hist_known_cached) and the legacy long key
// (pw_hist_known_accounts_only_on_already_triggered) for backward compatibility.
func (b *BruteForceSection) GetPWHistKnownAccountsOnlyOnAlreadyTriggered() bool {
	if b == nil {
		return false
	}

	return b.LogHistoryForKnownAccounts
}

// GetRWPIPv6CIDR returns the CIDR to use for IPv6 in the repeating-wrong-password context (0 disables).
func (b *BruteForceSection) GetRWPIPv6CIDR() uint {
	if b == nil {
		return 0
	}

	return b.IPScoping.RepeatingWrongPasswordIPv6CIDR
}

// GetTolerationsIPv6CIDR returns the CIDR to use for IPv6 in the tolerations context (0 disables).
func (b *BruteForceSection) GetTolerationsIPv6CIDR() uint {
	if b == nil {
		return 0
	}

	return b.IPScoping.TolerationsIPv6CIDR
}

// GetColdStartGraceEnabled tells whether the one-time cold-start grace is enabled.
func (b *BruteForceSection) GetColdStartGraceEnabled() bool {
	if b == nil {
		return false
	}

	return b.ColdStartGraceEnabled
}

// GetColdStartGraceTTL returns the TTL for the cold-start grace.
// Defaults to 120s if not set or invalid.
func (b *BruteForceSection) GetColdStartGraceTTL() time.Duration {
	if b == nil {
		return 120 * time.Second
	}

	if b.ColdStartGraceTTL <= 0 {
		return 120 * time.Second
	}

	return b.ColdStartGraceTTL
}

// GetRWPAllowedUniqueHashes returns how many distinct wrong password hashes are tolerated within the window.
// Defaults to 3 if not set or if the receiver is nil.
func (b *BruteForceSection) GetRWPAllowedUniqueHashes() uint {
	if b == nil {
		return 3
	}

	if b.AllowedUniqueWrongPWHashes == 0 {
		return 3
	}

	return b.AllowedUniqueWrongPWHashes
}

// GetRWPWindow returns the time window for tracking tolerated unique wrong password hashes.
// Defaults to 15 minutes if not set or invalid.
func (b *BruteForceSection) GetRWPWindow() time.Duration {
	if b == nil {
		return 15 * time.Minute
	}

	if b.RWPWindow <= 0 {
		return 15 * time.Minute
	}

	return b.RWPWindow
}

// Tolerate represents a configuration item for toleration settings based on IP, percentage, and Time-to-Live (TTL).
type Tolerate struct {
	IPAddress          string        `mapstructure:"ip_address" validate:"required,ip_addr|cidr"`
	ToleratePercent    uint8         `mapstructure:"tolerate_percent" validate:"required,min=0,max=100"`
	TolerateTTL        time.Duration `mapstructure:"tolerate_ttl" validate:"required,gt=0,max=8760h"`
	AdaptiveToleration bool          `mapstructure:"adaptive_toleration"`
	MinToleratePercent uint8         `mapstructure:"min_tolerate_percent" validate:"omitempty,min=0,max=100"`
	MaxToleratePercent uint8         `mapstructure:"max_tolerate_percent" validate:"omitempty,min=0,max=100"`
	ScaleFactor        float64       `mapstructure:"scale_factor" validate:"omitempty,min=0.1,max=10"`
}

// GetIPAddress retrieves the IP address from the Tolerate configuration.
// Returns an empty string if the Tolerate is nil.
func (t *Tolerate) GetIPAddress() string {
	if t == nil {
		return ""
	}

	return t.IPAddress
}

// GetToleratePercent retrieves the tolerate percent value from the Tolerate configuration.
// Returns 0 if the Tolerate is nil.
func (t *Tolerate) GetToleratePercent() uint8 {
	if t == nil {
		return 0
	}

	return t.ToleratePercent
}

// GetTolerateTTL retrieves the tolerate TTL duration from the Tolerate configuration.
// Returns 0 if the Tolerate is nil.
func (t *Tolerate) GetTolerateTTL() time.Duration {
	if t == nil {
		return 0
	}

	return t.TolerateTTL
}

// GetAdaptiveToleration checks if adaptive toleration is enabled in the Tolerate configuration.
// Returns false if the Tolerate is nil.
func (t *Tolerate) GetAdaptiveToleration() bool {
	if t == nil {
		return false
	}

	return t.AdaptiveToleration
}

// GetMinToleratePercent retrieves the minimum tolerate percent value from the Tolerate configuration.
// Returns 10 as default if not set or if the Tolerate is nil.
func (t *Tolerate) GetMinToleratePercent() uint8 {
	if t == nil {
		return 10
	}

	if t.MinToleratePercent == 0 {
		return 10 // Default value
	}

	return t.MinToleratePercent
}

// GetMaxToleratePercent retrieves the maximum tolerate percent value from the Tolerate configuration.
// Returns 50 as default if not set or if the Tolerate is nil.
func (t *Tolerate) GetMaxToleratePercent() uint8 {
	if t == nil {
		return 50
	}

	if t.MaxToleratePercent == 0 {
		return 50 // Default value
	}

	return t.MaxToleratePercent
}

// GetScaleFactor retrieves the scale factor value from the Tolerate configuration.
// Returns 1.0 as default if not set or if the Tolerate is nil.
func (t *Tolerate) GetScaleFactor() float64 {
	if t == nil {
		return 1.0
	}

	if t.ScaleFactor == 0 {
		return 1.0 // Default value
	}

	return t.ScaleFactor
}

// BruteForceRule is the definition of a brute force rule as defined in the configuration file. See the markdown
// documentation for a description of the field names.
type BruteForceRule struct {
	Name             string        `mapstructure:"name" validate:"required"`
	Period           time.Duration `mapstructure:"period" validate:"required,gt=0,max=8760h"`
	CIDR             uint          `mapstructure:"cidr" validate:"required,min=1,max=128"`
	IPv4             bool
	IPv6             bool
	FailedRequests   uint     `mapstructure:"failed_requests" validate:"required,min=1"`
	FilterByProtocol []string `mapstructure:"filter_by_protocol" validate:"omitempty"`
	FilterByOIDCCID  []string `mapstructure:"filter_by_oidc_cid" validate:"omitempty"`
}

func (b *BruteForceRule) String() string {
	if b == nil {
		return "<nil>"
	}

	return fmt.Sprintf("Name: %s, Period: %s, CIDR: %d, IPv4: %t, IPv6: %t, FailedRequests: %d", b.Name, b.Period, b.CIDR, b.IPv4, b.IPv6, b.FailedRequests)
}

// GetName retrieves the name of the brute force rule.
// Returns an empty string if the BruteForceRule is nil.
func (b *BruteForceRule) GetName() string {
	if b == nil {
		return ""
	}

	return b.Name
}

// GetPeriod retrieves the period duration for the brute force rule.
// Returns 0 if the BruteForceRule is nil.
func (b *BruteForceRule) GetPeriod() time.Duration {
	if b == nil {
		return 0
	}

	return b.Period
}

// GetCIDR retrieves the CIDR value for the brute force rule.
// Returns 0 if the BruteForceRule is nil.
func (b *BruteForceRule) GetCIDR() uint {
	if b == nil {
		return 0
	}

	return b.CIDR
}

// IsIPv4 checks if the brute force rule is configured for IPv4.
// Returns false if the BruteForceRule is nil.
func (b *BruteForceRule) IsIPv4() bool {
	if b == nil {
		return false
	}

	return b.IPv4
}

// IsIPv6 checks if the brute force rule is configured for IPv6.
// Returns false if the BruteForceRule is nil.
func (b *BruteForceRule) IsIPv6() bool {
	if b == nil {
		return false
	}

	return b.IPv6
}

// GetFailedRequests retrieves the number of failed requests threshold for the brute force rule.
// Returns 0 if the BruteForceRule is nil.
func (b *BruteForceRule) GetFailedRequests() uint {
	if b == nil {
		return 0
	}

	return b.FailedRequests
}

// GetFilterByProtocol retrieves the list of protocols to filter by for the brute force rule.
// Returns an empty slice if the BruteForceRule is nil.
func (b *BruteForceRule) GetFilterByProtocol() []string {
	if b == nil {
		return []string{}
	}

	return b.FilterByProtocol
}

// GetFilterByOIDCCID retrieves the list of OIDC client IDs to filter by for the brute force rule.
// Returns an empty slice if the BruteForceRule is nil.
func (b *BruteForceRule) GetFilterByOIDCCID() []string {
	if b == nil {
		return []string{}
	}

	return b.FilterByOIDCCID
}

// MatchesContext returns true if the rule is applicable for the given request context.
// It applies protocol and OIDC CID filters (when present and the corresponding input is non-empty)
// and validates the IP family (IPv4/IPv6) against the rule.
func (b *BruteForceRule) MatchesContext(protocol string, oidcCID string, ip net.IP) bool {
	if b == nil {
		return false
	}

	if ip == nil {
		return false
	}

	// Protocol filter
	if len(b.FilterByProtocol) > 0 && protocol != "" {
		matched := false
		for _, p := range b.FilterByProtocol {
			if p == protocol {
				matched = true

				break
			}
		}

		if !matched {
			return false
		}
	}

	// OIDC filter
	if len(b.FilterByOIDCCID) > 0 && oidcCID != "" {
		matched := false
		for _, cid := range b.FilterByOIDCCID {
			if cid == oidcCID {
				matched = true

				break
			}
		}

		if !matched {
			return false
		}
	}

	// IP family
	if ip.To4() != nil {
		return b.IPv4
	}

	if ip.To16() != nil {
		return b.IPv6
	}

	return false
}
