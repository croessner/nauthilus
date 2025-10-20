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
	"reflect"
	"time"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/go-playground/validator/v10"
)

type LDAPSection struct {
	Config            *LDAPConf            `mapstructure:"config" validate:"required"`
	OptionalLDAPPools map[string]*LDAPConf `mapstructure:"optional_ldap_pools" validate:"omitempty,dive,validatDefaultBackendName"`
	Search            []LDAPSearchProtocol `mapstructure:"search" validate:"omitempty,dive"`
}

// validatDefaultBackendName ensures the backend name is not set to "default" or the predefined DefaultBackendName constant.
func validatDefaultBackendName(fl validator.FieldLevel) bool {
	conf, ok := fl.Parent().Interface().(LDAPSection)
	if !ok {
		return false
	}

	for backendName := range conf.OptionalLDAPPools {
		if backendName == "default" || backendName == definitions.DefaultBackendName {
			return false
		}
	}

	return true
}

func (l *LDAPSection) String() string {
	if l == nil {
		return "LDAPSection: <nil>"
	}

	return fmt.Sprintf("LDAPSection: {Config[%+v] Search[%+v]}", l.Config, l.Search)
}

// GetConfig retrieves the LDAP configuration from the receiver. Returns nil if the receiver is nil.
func (l *LDAPSection) GetConfig() any {
	if l == nil {
		return nil
	}

	return l.Config
}

// GetProtocols returns the search protocols of the LDAP configuration, or an empty slice if the receiver is nil.
func (l *LDAPSection) GetProtocols() any {
	if l == nil {
		return []LDAPSearchProtocol{}
	}

	if l.Search == nil {
		return []LDAPSearchProtocol{}
	}

	return l.Search
}

var _ GetterHandler = (*LDAPSection)(nil)

// GetOptionalLDAPPools returns a map of LDAP pool configurations if available, or an empty map if the receiver is nil.
func (l *LDAPSection) GetOptionalLDAPPools() map[string]*LDAPConf {
	if l == nil {
		return map[string]*LDAPConf{}
	}

	if l.OptionalLDAPPools == nil {
		return map[string]*LDAPConf{}
	}

	return l.OptionalLDAPPools
}

// GetSearch returns the LDAP search protocols if available, or an empty slice if the receiver is nil.
func (l *LDAPSection) GetSearch() []LDAPSearchProtocol {
	if l == nil {
		return []LDAPSearchProtocol{}
	}

	if l.Search == nil {
		return []LDAPSearchProtocol{}
	}

	return l.Search
}

type LDAPConf struct {
	PoolOnly      bool `mapstructure:"pool_only"`
	StartTLS      bool
	TLSSkipVerify bool `mapstructure:"tls_skip_verify"`
	SASLExternal  bool `mapstructure:"sasl_external"`

	NumberOfWorkers    int `mapstructure:"number_of_workers" validate:"omitempty,min=1,max=1000000"`
	LookupPoolSize     int `mapstructure:"lookup_pool_size" validate:"required,min=1"`
	LookupIdlePoolSize int `mapstructure:"lookup_idle_pool_size" validate:"omitempty,min=0"`
	AuthPoolSize       int `mapstructure:"auth_pool_size" validate:"validateAuthPoolRequired"`
	AuthIdlePoolSize   int `mapstructure:"auth_idle_pool_size" validate:"omitempty,min=0"`
	LookupQueueLength  int `mapstructure:"lookup_queue_length" validate:"omitempty,min=0"`
	AuthQueueLength    int `mapstructure:"auth_queue_length" validate:"omitempty,min=0"`

	BindDN        string `mapstructure:"bind_dn" validate:"omitempty,printascii"`
	BindPW        string `mapstructure:"bind_pw" validate:"omitempty"`
	TLSCAFile     string `mapstructure:"tls_ca_cert" validate:"omitempty,file"`
	TLSClientCert string `mapstructure:"tls_client_cert" validate:"omitempty,file"`
	TLSClientKey  string `mapstructure:"tls_client_key" validate:"omitempty,file"`

	ConnectAbortTimeout time.Duration `mapstructure:"connect_abort_timeout" validate:"omitempty,max=10m"`
	// Operation-specific timeouts (0 = library default)
	SearchTimeout time.Duration `mapstructure:"search_timeout" validate:"omitempty,max=10m"`
	BindTimeout   time.Duration `mapstructure:"bind_timeout" validate:"omitempty,max=10m"`
	ModifyTimeout time.Duration `mapstructure:"modify_timeout" validate:"omitempty,max=10m"`
	// Guardrails for search
	SearchSizeLimit int           `mapstructure:"search_size_limit" validate:"omitempty,min=0,max=100000"`
	SearchTimeLimit time.Duration `mapstructure:"search_time_limit" validate:"omitempty,max=10m"`
	// Retry/backoff configuration
	RetryMax        int           `mapstructure:"retry_max" validate:"omitempty,min=0,max=10"`
	RetryBase       time.Duration `mapstructure:"retry_base" validate:"omitempty,max=1m"`
	RetryMaxBackoff time.Duration `mapstructure:"retry_max_backoff" validate:"omitempty,max=5m"`
	// Circuit breaker configuration
	CBFailureThreshold int           `mapstructure:"cb_failure_threshold" validate:"omitempty,min=1,max=1000"`
	CBCooldown         time.Duration `mapstructure:"cb_cooldown" validate:"omitempty,max=10m"`
	CBHalfOpenMax      int           `mapstructure:"cb_half_open_max" validate:"omitempty,min=1,max=100"`

	// A8 cache options
	DNCacheTTL         time.Duration `mapstructure:"dn_cache_ttl" validate:"omitempty,max=10m"`
	MembershipCacheTTL time.Duration `mapstructure:"membership_cache_ttl" validate:"omitempty,max=10m"`
	NegativeCacheTTL   time.Duration `mapstructure:"negative_cache_ttl" validate:"omitempty,max=10m"`
	CacheMaxEntries    int           `mapstructure:"cache_max_entries" validate:"omitempty,min=0,max=10000000"`
	CacheImpl          string        `mapstructure:"cache_impl" validate:"omitempty,oneof=lru ttl"`
	IncludeRawResult   bool          `mapstructure:"include_raw_result"`

	// A9 optional auth rate limiting (per pool)
	AuthRateLimitPerSecond float64 `mapstructure:"auth_rate_limit_per_second" validate:"omitempty,min=0"`
	AuthRateLimitBurst     int     `mapstructure:"auth_rate_limit_burst" validate:"omitempty,min=0"`

	ServerURIs []string `mapstructure:"server_uri" validate:"required,dive,uri"`
	// Internal: set by pool to label metrics
	PoolName string `mapstructure:"-"`
}

// validateAuthPoolRequired validates the AuthPoolSize field in LDAPConf ensuring it's greater than 0 when PoolOnly is false.
func validateAuthPoolRequired(fl validator.FieldLevel) bool {
	conf, ok := fl.Parent().Interface().(LDAPConf)

	if !ok {
		return false
	}

	if !conf.PoolOnly && conf.AuthPoolSize <= 0 {
		return false
	}

	return true
}

func (l *LDAPConf) String() string {
	var result string

	if l == nil {
		return "<nil>"
	}

	value := reflect.ValueOf(*l)
	typeOfValue := value.Type()

	for index := 0; index < value.NumField(); index++ {
		switch typeOfValue.Field(index).Name {
		case "BindPW":
			if environment.GetDevMode() {
				result += fmt.Sprintf(" %s='%v'", typeOfValue.Field(index).Name, value.Field(index).Interface())
			} else {
				result += fmt.Sprintf(" %s='<hidden>'", typeOfValue.Field(index).Name)
			}
		case "LookupPoolSize", "LookupIdlePoolSize", "AuthPoolSize", "AuthIdlePoolSize":
			continue
		default:
			result += fmt.Sprintf(" %s='%v'", typeOfValue.Field(index).Name, value.Field(index).Interface())
		}
	}

	return result[1:]
}

// GetNumberOfWorkers returns the number of workers configured in the LDAPConf. Returns 0 if the LDAPConf is nil.
func (l *LDAPConf) GetNumberOfWorkers() int {
	if l == nil {
		return definitions.DefaultNumberOfWorkers
	}

	if l.NumberOfWorkers == 0 {
		return definitions.DefaultNumberOfWorkers
	}

	return l.NumberOfWorkers
}

// IsPoolOnly checks if the LDAPConf is configured for pool-only mode.
// Returns false if the LDAPConf is nil.
func (l *LDAPConf) IsPoolOnly() bool {
	if l == nil {
		return false
	}

	return l.PoolOnly
}

// IsStartTLS checks if StartTLS is enabled in the LDAPConf.
// Returns false if the LDAPConf is nil.
func (l *LDAPConf) IsStartTLS() bool {
	if l == nil {
		return false
	}

	return l.StartTLS
}

// IsTLSSkipVerify checks if TLS verification should be skipped in the LDAPConf.
// Returns false if the LDAPConf is nil.
func (l *LDAPConf) IsTLSSkipVerify() bool {
	if l == nil {
		return false
	}

	return l.TLSSkipVerify
}

// IsSASLExternal checks if SASL External authentication is enabled in the LDAPConf.
// Returns false if the LDAPConf is nil.
func (l *LDAPConf) IsSASLExternal() bool {
	if l == nil {
		return false
	}

	return l.SASLExternal
}

// GetLookupPoolSize retrieves the lookup pool size from the LDAPConf.
// Returns definitions.LDAPIdlePoolSize if the LDAPConf is nil.
func (l *LDAPConf) GetLookupPoolSize() int {
	if l == nil {
		return definitions.LDAPIdlePoolSize
	}

	return l.LookupPoolSize
}

// GetLookupIdlePoolSize retrieves the lookup idle pool size from the LDAPConf.
// Returns definitions.LDAPIdlePoolSize if the LDAPConf is nil.
func (l *LDAPConf) GetLookupIdlePoolSize() int {
	if l == nil {
		return definitions.LDAPIdlePoolSize
	}

	return l.LookupIdlePoolSize
}

// GetAuthPoolSize retrieves the authentication pool size from the LDAPConf.
// Returns definitions.LDAPIdlePoolSize if the LDAPConf is nil.
func (l *LDAPConf) GetAuthPoolSize() int {
	if l == nil {
		return definitions.LDAPIdlePoolSize
	}

	return l.AuthPoolSize
}

// GetAuthIdlePoolSize retrieves the authentication idle pool size from the LDAPConf.
// Returns definitions.LDAPIdlePoolSize if the LDAPConf is nil.
func (l *LDAPConf) GetAuthIdlePoolSize() int {
	if l == nil {
		return definitions.LDAPIdlePoolSize
	}

	return l.AuthIdlePoolSize
}

// GetBindDN retrieves the bind DN from the LDAPConf.
// Returns an empty string if the LDAPConf is nil.
func (l *LDAPConf) GetBindDN() string {
	if l == nil {
		return ""
	}

	return l.BindDN
}

// GetBindPW retrieves the bind password from the LDAPConf.
// Returns an empty string if the LDAPConf is nil.
func (l *LDAPConf) GetBindPW() string {
	if l == nil {
		return ""
	}

	return l.BindPW
}

// GetTLSCAFile retrieves the TLS CA certificate file path from the LDAPConf.
// Returns an empty string if the LDAPConf is nil.
func (l *LDAPConf) GetTLSCAFile() string {
	if l == nil {
		return ""
	}

	return l.TLSCAFile
}

// GetTLSClientCert retrieves the TLS client certificate file path from the LDAPConf.
// Returns an empty string if the LDAPConf is nil.
func (l *LDAPConf) GetTLSClientCert() string {
	if l == nil {
		return ""
	}

	return l.TLSClientCert
}

// GetTLSClientKey retrieves the TLS client key file path from the LDAPConf.
// Returns an empty string if the LDAPConf is nil.
func (l *LDAPConf) GetTLSClientKey() string {
	if l == nil {
		return ""
	}

	return l.TLSClientKey
}

// GetConnectAbortTimeout retrieves the connect abort timeout duration from the LDAPConf.
// Returns 0 if the LDAPConf is nil.
func (l *LDAPConf) GetConnectAbortTimeout() time.Duration {
	if l == nil {
		return 0
	}

	return l.ConnectAbortTimeout
}

// GetServerURIs retrieves the server URIs from the LDAPConf.
// Returns []string{"ldap://localhost"} slice if the LDAPConf is nil.
func (l *LDAPConf) GetServerURIs() []string {
	if l == nil {
		return []string{"ldap://localhost"}
	}

	return l.ServerURIs
}

type LDAPFilter struct {
	User                string `mapstructure:"user" validate:"omitempty"`
	ListAccounts        string `mapstructure:"list_accounts" validate:"omitempty"`
	WebAuthnCredentials string `mapstructure:"webauthn_credentials" validate:"omitempty"`
}

// GetWebAuthnCredentialsFilter returns an LDAP filter which is used to find WebAuthn credentials.
// Returns an empty string if the LDAPFilter is nil.
func (f *LDAPFilter) GetWebAuthnCredentialsFilter() string {
	if f == nil {
		return ""
	}

	return f.WebAuthnCredentials
}

type LDAPAttributeMapping struct {
	AccountField      string `mapstructure:"account_field" validate:"required"` // Webauthn is not implemented, yet.
	TOTPSecretField   string `mapstructure:"totp_secret_field" validate:"omitempty"`
	TOTPRecoveryField string `mapstructure:"totp_recovery_field" validate:"omitempty"`
	DisplayNameField  string `mapstructure:"display_name_field" validate:"omitempty"`
	CredentialObject  string `mapstructure:"credential_object" validate:"omitempty"`
	CredentialIDField string `mapstructure:"credential_id_field" validate:"omitempty"`
	PublicKeyField    string `mapstructure:"public_key_field" validate:"omitempty"`
	UniqueUserIDField string `mapstructure:"unique_user_id_field" validate:"omitempty"`
	AAGUIDField       string `mapstructure:"aaguid_field" validate:"omitempty"`
	SignCountField    string `mapstructure:"sign_count_field" validate:"omitempty"`
}

// GetTOTPSecretField retrieves the TOTP secret field name from the LDAPAttributeMapping.
// Returns an empty string if the LDAPAttributeMapping is nil.
func (m *LDAPAttributeMapping) GetTOTPSecretField() string {
	if m == nil {
		return ""
	}

	return m.TOTPSecretField
}

// GetTOTPRecoveryField retrieves the TOTP recovery field name from the LDAPAttributeMapping.
// Returns an empty string if the LDAPAttributeMapping is nil.
func (m *LDAPAttributeMapping) GetTOTPRecoveryField() string {
	if m == nil {
		return ""
	}

	return m.TOTPRecoveryField
}

// GetDisplayNameField retrieves the display name field from the LDAPAttributeMapping.
// Returns an empty string if the LDAPAttributeMapping is nil.
func (m *LDAPAttributeMapping) GetDisplayNameField() string {
	if m == nil {
		return ""
	}

	return m.DisplayNameField
}

// GetCredentialObject retrieves the credential object field name from the LDAPAttributeMapping.
// Returns an empty string if the LDAPAttributeMapping is nil.
func (m *LDAPAttributeMapping) GetCredentialObject() string {
	if m == nil {
		return ""
	}

	return m.CredentialObject
}

// GetCredentialIDField retrieves the credential ID field name from the LDAPAttributeMapping.
// Returns an empty string if the LDAPAttributeMapping is nil.
func (m *LDAPAttributeMapping) GetCredentialIDField() string {
	if m == nil {
		return ""
	}

	return m.CredentialIDField
}

// GetPublicKeyField retrieves the public key field name from the LDAPAttributeMapping.
// Returns an empty string if the LDAPAttributeMapping is nil.
func (m *LDAPAttributeMapping) GetPublicKeyField() string {
	if m == nil {
		return ""
	}

	return m.PublicKeyField
}

// GetUniqueUserIDField retrieves the unique user ID field name from the LDAPAttributeMapping.
// Returns an empty string if the LDAPAttributeMapping is nil.
func (m *LDAPAttributeMapping) GetUniqueUserIDField() string {
	if m == nil {
		return ""
	}

	return m.UniqueUserIDField
}

// GetAAGUIDField retrieves the AAGUID field name from the LDAPAttributeMapping.
// Returns an empty string if the LDAPAttributeMapping is nil.
func (m *LDAPAttributeMapping) GetAAGUIDField() string {
	if m == nil {
		return ""
	}

	return m.AAGUIDField
}

// GetSignCountField retrieves the sign count field name from the LDAPAttributeMapping.
// Returns an empty string if the LDAPAttributeMapping is nil.
func (m *LDAPAttributeMapping) GetSignCountField() string {
	if m == nil {
		return ""
	}

	return m.SignCountField
}

type LDAPSearchProtocol struct {
	Protocols []string `mapstructure:"protocol" validate:"required"`
	CacheName string   `mapstructure:"cache_name" validate:"required,printascii,excludesall= "`
	PoolName  string   `mapstructure:"pool_name" validate:"omitempty,printascii,excludesall= "`
	BaseDN    string   `mapstructure:"base_dn" validate:"required,printascii"`
	Scope     string   `mapstructure:"scope" validate:"omitempty,oneof=base one sub"`

	LDAPFilter           `mapstructure:"filter" validate:"required"`
	LDAPAttributeMapping `mapstructure:"mapping" validate:"required"`

	// LDAP result attributes
	Attributes []string `mapstructure:"attribute" validate:"required,dive,printascii,excludesall= "`
}

// GetAccountField returns the LDAP attribute for an account. It returns a DetailedError, if no value has
// been configured.
func (p *LDAPSearchProtocol) GetAccountField() (string, error) {
	if p == nil || p.AccountField == "" {
		return "", errors.ErrLDAPConfig.WithDetail(
			fmt.Sprintf("Missing LDAP account field; protocols=%v", p.Protocols))
	}

	return p.AccountField, nil
}

// GetAttributes returns a list of attributes that are requested from the LDAP server.  It returns a DetailedError, if
// no value has been configured.
func (p *LDAPSearchProtocol) GetAttributes() ([]string, error) {
	if p == nil || len(p.Attributes) == 0 {
		return nil, errors.ErrLDAPConfig.WithDetail(
			fmt.Sprintf("Missing LDAP result attribute; protocols=%v", p.Protocols))
	}

	return p.Attributes, nil
}

// GetUserFilter returns an LDAP search filter to find a user.  It returns a DetailedError, if no value has
// been configured.
func (p *LDAPSearchProtocol) GetUserFilter() (string, error) {
	if p == nil || p.User == "" {
		return "", errors.ErrLDAPConfig.WithDetail(
			fmt.Sprintf("Missing LDAP user filter; protocols=%v", p.Protocols))
	}

	return p.User, nil
}

// GetListAccountsFilter returns an LDAP filter which is used to find all user accounts.  It returns a DetailedError, if
// no value has been configured.
func (p *LDAPSearchProtocol) GetListAccountsFilter() (string, error) {
	if p == nil || p.ListAccounts == "" {
		return "", errors.ErrLDAPConfig.WithDetail(
			fmt.Sprintf("Missing LDAP list_accounts filter; protocols=%v", p.Protocols))
	}

	return p.ListAccounts, nil
}

// GetPoolName returns the configured pool name. If no pool name is configured, it defaults to DefaultBackendName.
func (p *LDAPSearchProtocol) GetPoolName() string {
	if p == nil || p.PoolName == "" {
		return definitions.DefaultBackendName
	}

	return p.PoolName
}

// GetBaseDN returns the base DN that is used for each specific protocol.  It returns a DetailedError, if no value has
// been configured.
func (p *LDAPSearchProtocol) GetBaseDN() (string, error) {
	if p == nil || p.BaseDN == "" {
		return "", errors.ErrLDAPConfig.WithDetail(
			fmt.Sprintf("Missing LDAP base DN; protocols=%v", p.Protocols))
	}

	return p.BaseDN, nil
}

// GetScope returns an LDAP search scope. If no scope was defined, it automatically sets the subtree scope. If a scope
// has been defined and is unknown, it returns a DetailedError.
func (p *LDAPSearchProtocol) GetScope() (*LDAPScope, error) {
	var err error

	scope := &LDAPScope{}
	if p == nil || p.Scope == "" {
		scope.Set("sub")
	} else {
		if err = scope.Set(p.Scope); err != nil {
			return nil, errors.ErrLDAPConfig.WithDetail(
				fmt.Sprintf("LDAP scope not detected: %s; protocols=%v", err, p.Protocols))
		}
	}

	return scope, nil
}

// GetCacheName returns the Redis cache domain. It returns a DetailedError, if no value has
// been configured.
func (p *LDAPSearchProtocol) GetCacheName() (string, error) {
	if p == nil || p.CacheName == "" {
		return "", errors.ErrLDAPConfig.WithDetail("No cache name setting")
	}

	return p.CacheName, nil
}

// GetProtocols retrieves the list of protocols from the LDAPSearchProtocol.
// Returns an empty slice if the LDAPSearchProtocol is nil or if the Protocols field is nil.
func (p *LDAPSearchProtocol) GetProtocols() []string {
	if p == nil {
		return []string{}
	}

	if p.Protocols == nil {
		return []string{}
	}

	return p.Protocols
}

// GetLookupQueueLength returns the maximum queue length for lookup requests. Zero means unlimited.
func (l *LDAPConf) GetLookupQueueLength() int {
	if l == nil {
		return 0
	}

	return l.LookupQueueLength
}

// GetAuthQueueLength returns the maximum queue length for auth requests. Zero means unlimited.
func (l *LDAPConf) GetAuthQueueLength() int {
	if l == nil {
		return 0
	}

	return l.AuthQueueLength
}

// GetSearchTimeout returns the search timeout duration.
func (l *LDAPConf) GetSearchTimeout() time.Duration {
	if l == nil {
		return 0
	}

	return l.SearchTimeout
}

// GetBindTimeout returns the bind timeout duration.
func (l *LDAPConf) GetBindTimeout() time.Duration {
	if l == nil {
		return 0
	}

	return l.BindTimeout
}

// GetModifyTimeout returns the modify timeout duration.
func (l *LDAPConf) GetModifyTimeout() time.Duration {
	if l == nil {
		return 0
	}

	return l.ModifyTimeout
}

// GetSearchSizeLimit returns LDAP size limit; 0 means server default (unlimited).
func (l *LDAPConf) GetSearchSizeLimit() int {
	if l == nil || l.SearchSizeLimit < 0 {
		return 0
	}

	return l.SearchSizeLimit
}

// GetSearchTimeLimit returns LDAP time limit as a duration; 0 means default.
func (l *LDAPConf) GetSearchTimeLimit() time.Duration {
	if l == nil || l.SearchTimeLimit < 0 {
		return 0
	}

	return l.SearchTimeLimit
}

// GetAuthRateLimitPerSecond returns tokens per second for auth limiter.
func (l *LDAPConf) GetAuthRateLimitPerSecond() float64 {
	if l == nil || l.AuthRateLimitPerSecond < 0 {
		return 0
	}

	return l.AuthRateLimitPerSecond
}

// GetAuthRateLimitBurst returns burst size for auth limiter.
func (l *LDAPConf) GetAuthRateLimitBurst() int {
	if l == nil || l.AuthRateLimitBurst < 0 {
		return 0
	}

	return l.AuthRateLimitBurst
}

// GetRetryMax returns the maximum number of retries for transient errors. Default 2 if unset.
func (l *LDAPConf) GetRetryMax() int {
	if l == nil || l.RetryMax == 0 {
		return 2
	}

	return l.RetryMax
}

// GetRetryBase returns the base backoff duration for retries. Default 200ms if unset.
func (l *LDAPConf) GetRetryBase() time.Duration {
	if l == nil || l.RetryBase == 0 {
		return 200 * time.Millisecond
	}

	return l.RetryBase
}

// GetRetryMaxBackoff returns the max backoff duration for retries. Default 2s if unset.
func (l *LDAPConf) GetRetryMaxBackoff() time.Duration {
	if l == nil || l.RetryMaxBackoff == 0 {
		return 2 * time.Second
	}

	return l.RetryMaxBackoff
}

// GetCBFailureThreshold returns the number of failures before opening the breaker. Default 5.
func (l *LDAPConf) GetCBFailureThreshold() int {
	if l == nil || l.CBFailureThreshold == 0 {
		return 5
	}

	return l.CBFailureThreshold
}

// GetCBCooldown returns the cooldown period for the breaker to remain open. Default 30s.
func (l *LDAPConf) GetCBCooldown() time.Duration {
	if l == nil || l.CBCooldown == 0 {
		return 30 * time.Second
	}

	return l.CBCooldown
}

// GetCBHalfOpenMax returns the number of half-open probes allowed before deciding state. Default 1.
func (l *LDAPConf) GetCBHalfOpenMax() int {
	if l == nil || l.CBHalfOpenMax == 0 {
		return 1
	}

	return l.CBHalfOpenMax
}

// GetNegativeCacheTTL returns TTL for negative cache entries. Default 20s.
func (l *LDAPConf) GetNegativeCacheTTL() time.Duration {
	if l == nil || l.NegativeCacheTTL == 0 {
		return 20 * time.Second
	}

	return l.NegativeCacheTTL
}

// GetCacheMaxEntries returns max entries for LRU caches. Default 5000.
func (l *LDAPConf) GetCacheMaxEntries() int {
	if l == nil || l.CacheMaxEntries == 0 {
		return 5000
	}

	return l.CacheMaxEntries
}

// GetCacheImpl returns selected cache implementation: "lru" or "ttl". Default "ttl".
func (l *LDAPConf) GetCacheImpl() string {
	if l == nil || l.CacheImpl == "" {
		return "ttl"
	}

	return l.CacheImpl
}

// GetIncludeRawResult returns whether raw LDAP search entries should be included in replies. Default false.
func (l *LDAPConf) GetIncludeRawResult() bool {
	if l == nil {
		return false
	}

	return l.IncludeRawResult
}

// GetPoolName returns the pool name label set internally.
func (l *LDAPConf) GetPoolName() string {
	if l == nil {
		return ""
	}

	return l.PoolName
}
