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

// GetProtocols returns the search protocols of the LDAP configuration, or nil if the receiver is nil.
func (l *LDAPSection) GetProtocols() any {
	if l == nil {
		return nil
	}

	return l.Search
}

var _ GetterHandler = (*LDAPSection)(nil)

// GetOptionalLDAPPools returns a map of LDAP pool configurations if available, or nil if the receiver is nil.
func (l *LDAPSection) GetOptionalLDAPPools() map[string]*LDAPConf {
	if l == nil {
		return nil
	}

	return l.OptionalLDAPPools
}

type LDAPConf struct {
	PoolOnly      bool `mapstructure:"pool_only"`
	StartTLS      bool
	TLSSkipVerify bool `mapstructure:"tls_skip_verify"`
	SASLExternal  bool `mapstructure:"sasl_external"`

	LookupPoolSize     int `mapstructure:"lookup_pool_size" validate:"required,min=1"`
	LookupIdlePoolSize int `mapstructure:"lookup_idle_pool_size" validate:"omitempty,min=0"`
	AuthPoolSize       int `mapstructure:"auth_pool_size" validate:"validateAuthPoolRequired"`
	AuthIdlePoolSize   int `mapstructure:"auth_idle_pool_size" validate:"omitempty,min=0"`

	BindDN        string `mapstructure:"bind_dn" validate:"omitempty,printascii"`
	BindPW        string `mapstructure:"bind_pw" validate:"omitempty"`
	TLSCAFile     string `mapstructure:"tls_ca_cert" validate:"omitempty,file"`
	TLSClientCert string `mapstructure:"tls_client_cert" validate:"omitempty,file"`
	TLSClientKey  string `mapstructure:"tls_client_key" validate:"omitempty,file"`

	ConnectAbortTimeout time.Duration `mapstructure:"connect_abort_timeout" validate:"omitempty,max=10m"`
	ServerURIs          []string      `mapstructure:"server_uri" validate:"required,dive,uri"`
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

type LDAPFilter struct {
	User                string `mapstructure:"user" validate:"omitempty"`
	ListAccounts        string `mapstructure:"list_accounts" validate:"omitempty"`
	WebAuthnCredentials string `mapstructure:"webauthn_credentials" validate:"omitempty"`
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
	if p.PoolName == "" {
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
