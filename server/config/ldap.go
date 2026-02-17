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
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/secret"
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
	// Deprecated: use lookup_pool_only
	PoolOnly       bool `mapstructure:"pool_only"`
	LookupPoolOnly bool `mapstructure:"lookup_pool_only"`
	StartTLS       bool
	TLSSkipVerify  bool `mapstructure:"tls_skip_verify"`
	SASLExternal   bool `mapstructure:"sasl_external"`

	NumberOfWorkers    int `mapstructure:"number_of_workers" validate:"omitempty,min=1,max=1000000"`
	LookupPoolSize     int `mapstructure:"lookup_pool_size" validate:"required,min=1"`
	LookupIdlePoolSize int `mapstructure:"lookup_idle_pool_size" validate:"omitempty,min=0"`
	AuthPoolSize       int `mapstructure:"auth_pool_size" validate:"validateAuthPoolRequired"`
	AuthIdlePoolSize   int `mapstructure:"auth_idle_pool_size" validate:"omitempty,min=0"`
	LookupQueueLength  int `mapstructure:"lookup_queue_length" validate:"omitempty,min=0"`
	AuthQueueLength    int `mapstructure:"auth_queue_length" validate:"omitempty,min=0"`

	BindDN           string       `mapstructure:"bind_dn" validate:"omitempty,printascii"`
	BindPW           secret.Value `mapstructure:"bind_pw" validate:"omitempty"`
	EncryptionSecret secret.Value `mapstructure:"encryption_secret" validate:"omitempty,secret_min=16,alphanumsymbol,secret_excludesall= "`
	TLSCAFile        string       `mapstructure:"tls_ca_cert" validate:"omitempty,file"`
	TLSClientCert    string       `mapstructure:"tls_client_cert" validate:"omitempty,file"`
	TLSClientKey     string       `mapstructure:"tls_client_key" validate:"omitempty,file"`

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

	// Health check configuration
	HealthCheckInterval time.Duration `mapstructure:"health_check_interval" validate:"omitempty,max=10m"`
	HealthCheckTimeout  time.Duration `mapstructure:"health_check_timeout" validate:"omitempty,max=1m"`

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

// validateAuthPoolRequired validates the AuthPoolSize field in LDAPConf ensuring it's greater than 0 when not in pool-only mode.
func validateAuthPoolRequired(fl validator.FieldLevel) bool {
	conf, ok := fl.Parent().Interface().(LDAPConf)

	if !ok {
		return false
	}

	if !conf.IsPoolOnly() && conf.AuthPoolSize <= 0 {
		return false
	}

	return true
}

func (l *LDAPConf) String() string {
	if l == nil {
		return "<nil>"
	}

	var result strings.Builder

	value := reflect.ValueOf(*l)
	typeOfValue := value.Type()

	for index := 0; index < value.NumField(); index++ {
		switch typeOfValue.Field(index).Name {
		case "BindPW":
			if environment.GetDevMode() {
				if secretValue, ok := value.Field(index).Interface().(secret.Value); ok {
					fmt.Fprintf(&result, " %s='%s'", typeOfValue.Field(index).Name, secretValue.String())
				} else {
					fmt.Fprintf(&result, " %s='%v'", typeOfValue.Field(index).Name, value.Field(index).Interface())
				}
			} else {
				fmt.Fprintf(&result, " %s='<hidden>'", typeOfValue.Field(index).Name)
			}
		case "EncryptionSecret":
			fmt.Fprintf(&result, " %s='<hidden>'", typeOfValue.Field(index).Name)
		case "LookupPoolSize", "LookupIdlePoolSize", "AuthPoolSize", "AuthIdlePoolSize":
			continue
		default:
			fmt.Fprintf(&result, " %s='%v'", typeOfValue.Field(index).Name, value.Field(index).Interface())
		}
	}

	if result.Len() == 0 {
		return ""
	}

	return result.String()[1:]
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

// IsPoolOnly determines the effective pool-only mode.
// Rule: If deprecated 'pool_only' is set, it wins. Otherwise use 'lookup_pool_only'.
func (l *LDAPConf) IsPoolOnly() bool {
	if l == nil {
		return false
	}

	if l.PoolOnly {
		return true
	}

	return l.LookupPoolOnly
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
func (l *LDAPConf) GetBindPW() secret.Value {
	if l == nil {
		return secret.Value{}
	}

	return l.BindPW
}

// GetEncryptionSecret retrieves the LDAP encryption secret from the LDAPConf.
// Returns an empty string if the LDAPConf is nil.
func (l *LDAPConf) GetEncryptionSecret() secret.Value {
	if l == nil {
		return secret.Value{}
	}

	return l.EncryptionSecret
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
	AccountField            string `mapstructure:"account_field" validate:"required"` // Webauthn is not implemented, yet.
	TOTPSecretField         string `mapstructure:"totp_secret_field" validate:"omitempty"`
	TOTPRecoveryField       string `mapstructure:"totp_recovery_field" validate:"omitempty"`
	TOTPObjectClass         string `mapstructure:"totp_object_class" validate:"omitempty"`
	TOTPRecoveryObjectClass string `mapstructure:"totp_recovery_object_class" validate:"omitempty"`
	DisplayNameField        string `mapstructure:"display_name_field" validate:"omitempty"`
	WebAuthnCredentialField string `mapstructure:"webauthn_credential_field" validate:"omitempty"`
	WebAuthnObjectClass     string `mapstructure:"webauthn_object_class" validate:"omitempty"`
	UniqueUserIDField       string `mapstructure:"unique_user_id_field" validate:"omitempty"`
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

// GetTOTPObjectClass returns the objectClass for TOTP usage.
func (m *LDAPAttributeMapping) GetTOTPObjectClass() string {
	if m == nil {
		return ""
	}

	return m.TOTPObjectClass
}

// GetTOTPRecoveryObjectClass returns the objectClass for TOTP recovery codes.
func (m *LDAPAttributeMapping) GetTOTPRecoveryObjectClass() string {
	if m == nil {
		return ""
	}

	return m.TOTPRecoveryObjectClass
}

// GetDisplayNameField retrieves the display name field from the LDAPAttributeMapping.
// Returns an empty string if the LDAPAttributeMapping is nil.
func (m *LDAPAttributeMapping) GetDisplayNameField() string {
	if m == nil {
		return ""
	}

	return m.DisplayNameField
}

// GetWebAuthnCredentialField retrieves the WebAuthn credential field name from the LDAPAttributeMapping.
// Returns an empty string if the LDAPAttributeMapping is nil.
func (m *LDAPAttributeMapping) GetWebAuthnCredentialField() string {
	if m == nil {
		return ""
	}

	return m.WebAuthnCredentialField
}

// GetWebAuthnObjectClass returns the objectClass for WebAuthn usage.
func (m *LDAPAttributeMapping) GetWebAuthnObjectClass() string {
	if m == nil {
		return ""
	}

	return m.WebAuthnObjectClass
}

// GetUniqueUserIDField retrieves the unique user ID field name from the LDAPAttributeMapping.
// Returns an empty string if the LDAPAttributeMapping is nil.
func (m *LDAPAttributeMapping) GetUniqueUserIDField() string {
	if m == nil {
		return ""
	}

	return m.UniqueUserIDField
}

// GetAllMappedFields returns all attribute names that are part of the mapping.
func (m *LDAPAttributeMapping) GetAllMappedFields() []string {
	if m == nil {
		return nil
	}

	fields := make([]string, 0, 6)

	if m.AccountField != "" {
		fields = append(fields, m.AccountField)
	}

	if m.TOTPSecretField != "" {
		fields = append(fields, m.TOTPSecretField)
	}

	if m.TOTPRecoveryField != "" {
		fields = append(fields, m.TOTPRecoveryField)
	}

	if m.DisplayNameField != "" {
		fields = append(fields, m.DisplayNameField)
	}

	if m.WebAuthnCredentialField != "" {
		fields = append(fields, m.WebAuthnCredentialField)
	}

	if m.UniqueUserIDField != "" {
		fields = append(fields, m.UniqueUserIDField)
	}

	return fields
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

// getProtocols retrieves a list of protocols from the provided LDAPSearchProtocol.
// Returns ["unknown"] if the input is nil.
func getProtocols(p *LDAPSearchProtocol) []string {
	if p == nil {
		return []string{"unknown"}
	}

	return p.Protocols
}

// GetAccountField returns the LDAP attribute for an account. It returns a DetailedError, if no value has
// been configured.
func (p *LDAPSearchProtocol) GetAccountField() (string, error) {
	if p == nil || p.AccountField == "" {
		return "", errors.ErrLDAPConfig.WithDetail(
			fmt.Sprintf("Missing LDAP account field; protocols=%v", getProtocols(p)))
	}

	return p.AccountField, nil
}

// GetAttributes returns a list of attributes that are requested from the LDAP server. It returns a DetailedError, if
// no value has been configured.
func (p *LDAPSearchProtocol) GetAttributes() ([]string, error) {
	if p == nil {
		return nil, errors.ErrLDAPConfig.WithDetail("LDAPSearchProtocol is nil")
	}

	uniqueAttributes := make(map[string]struct{})

	// Add configured attributes
	for _, attr := range p.Attributes {
		if attr != "" {
			uniqueAttributes[attr] = struct{}{}
		}
	}

	// Add mapped fields
	for _, field := range p.GetAllMappedFields() {
		if field != "" {
			uniqueAttributes[field] = struct{}{}
		}
	}

	if len(uniqueAttributes) == 0 {
		return nil, errors.ErrLDAPConfig.WithDetail(
			fmt.Sprintf("Missing LDAP result attribute; protocols=%v", getProtocols(p)))
	}

	result := make([]string, 0, len(uniqueAttributes))
	for attr := range uniqueAttributes {
		result = append(result, attr)
	}

	return result, nil
}

// GetUserFilter returns an LDAP search filter to find a user.  It returns a DetailedError, if no value has
// been configured.
func (p *LDAPSearchProtocol) GetUserFilter() (string, error) {
	if p == nil || p.User == "" {
		return "", errors.ErrLDAPConfig.WithDetail(
			fmt.Sprintf("Missing LDAP user filter; protocols=%v", getProtocols(p)))
	}

	return p.User, nil
}

// GetListAccountsFilter returns an LDAP filter which is used to find all user accounts.  It returns a DetailedError, if
// no value has been configured.
func (p *LDAPSearchProtocol) GetListAccountsFilter() (string, error) {
	if p == nil || p.ListAccounts == "" {
		return "", errors.ErrLDAPConfig.WithDetail(
			fmt.Sprintf("Missing LDAP list_accounts filter; protocols=%v", getProtocols(p)))
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
			fmt.Sprintf("Missing LDAP base DN; protocols=%v", getProtocols(p)))
	}

	return p.BaseDN, nil
}

// GetScope returns an LDAP search scope. If no scope was defined, it automatically sets the subtree scope. If a scope
// has been defined and is unknown, it returns a DetailedError.
func (p *LDAPSearchProtocol) GetScope() (*LDAPScope, error) {
	var err error

	scope := &LDAPScope{}
	if p == nil {
		scope.Set("sub")

		return scope, nil
	}

	if p.Scope == "" {
		scope.Set("sub")

		return scope, nil
	}

	if err = scope.Set(p.Scope); err != nil {
		return nil, errors.ErrLDAPConfig.WithDetail(
			fmt.Sprintf("LDAP scope not detected: %s; protocols=%v", err, getProtocols(p)))
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

// GetTotpSecretField returns the LDAP attribute for the TOTP secret.
func (p *LDAPSearchProtocol) GetTotpSecretField() string {
	return p.GetTOTPSecretField()
}

// GetTotpRecoveryField returns the LDAP attribute for the TOTP recovery codes.
func (p *LDAPSearchProtocol) GetTotpRecoveryField() string {
	return p.GetTOTPRecoveryField()
}

// GetTotpObjectClass returns the objectClass for TOTP usage.
func (p *LDAPSearchProtocol) GetTotpObjectClass() string {
	return p.GetTOTPObjectClass()
}

// GetTotpRecoveryObjectClass returns the objectClass for TOTP recovery codes.
func (p *LDAPSearchProtocol) GetTotpRecoveryObjectClass() string {
	return p.GetTOTPRecoveryObjectClass()
}

// GetWebAuthnCredentialField returns the LDAP attribute for the WebAuthn credentials.
func (p *LDAPSearchProtocol) GetWebAuthnCredentialField() string {
	return p.LDAPAttributeMapping.GetWebAuthnCredentialField()
}

// GetWebAuthnObjectClass returns the objectClass for WebAuthn usage.
func (p *LDAPSearchProtocol) GetWebAuthnObjectClass() string {
	return p.LDAPAttributeMapping.GetWebAuthnObjectClass()
}

// GetUniqueUserIDField returns the LDAP attribute for the unique user ID.
func (p *LDAPSearchProtocol) GetUniqueUserIDField() string {
	return p.LDAPAttributeMapping.GetUniqueUserIDField()
}

// GetDisplayNameField returns the LDAP attribute for the display name.
func (p *LDAPSearchProtocol) GetDisplayNameField() string {
	return p.LDAPAttributeMapping.GetDisplayNameField()
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

// GetHealthCheckInterval returns the interval for active LDAP health probes. Default 10s.
func (l *LDAPConf) GetHealthCheckInterval() time.Duration {
	if l == nil || l.HealthCheckInterval == 0 {
		return 10 * time.Second
	}

	return l.HealthCheckInterval
}

// GetHealthCheckTimeout returns the per-probe timeout for LDAP health checks. Default 1.5s.
func (l *LDAPConf) GetHealthCheckTimeout() time.Duration {
	if l == nil || l.HealthCheckTimeout == 0 {
		return 1500 * time.Millisecond
	}

	return l.HealthCheckTimeout
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
