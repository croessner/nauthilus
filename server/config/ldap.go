package config

import (
	"fmt"
	"reflect"

	"github.com/croessner/nauthilus/server/errors"
)

type LDAPSection struct {
	Config *LDAPConf
	Search []LDAPSearchProtocol
}

func (l *LDAPSection) String() string {
	return fmt.Sprintf("LDAPSection: {Config[%+v] Search[%+v]}", l.Config, l.Search)
}

func (l *LDAPSection) GetConfig() any {
	if l == nil {
		return nil
	}

	return l.Config
}

func (l *LDAPSection) GetProtocols() any {
	if l == nil {
		return nil
	}

	return l.Search
}

type LDAPConf struct {
	StartTLS      bool
	TLSSkipVerify bool `mapstructure:"tls_skip_verify"`
	SASLExternal  bool `mapstructure:"sasl_external"`

	LookupPoolSize     int `mapstructure:"lookup_pool_size"`
	LookupIdlePoolSize int `mapstructure:"lookup_idle_pool_size"`
	AuthPoolSize       int `mapstructure:"auth_pool_size"`
	AuthIdlePoolSize   int `mapstructure:"auth_idle_pool_size"`

	BindDN        string `mapstructure:"bind_dn"`
	BindPW        string `mapstructure:"bind_pw"`
	TLSCAFile     string `mapstructure:"tls_ca_cert"`
	TLSClientCert string `mapstructure:"tls_client_cert"`
	TLSClientKey  string `mapstructure:"tls_client_key"`

	ServerURIs []string `mapstructure:"server_uri"`
}

func (l *LDAPConf) String() string {
	var result string

	value := reflect.ValueOf(*l)
	typeOfValue := value.Type()

	for index := 0; index < value.NumField(); index++ {
		switch typeOfValue.Field(index).Name {
		case "BindPW":
			if EnvConfig.DevMode {
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
	User                string
	ListAccounts        string `mapstructure:"list_accounts"`
	WebAuthnCredentials string `mapstructure:"webauthn_credentials"`
}

type LDAPAttributeMapping struct {
	AccountField      string `mapstructure:"account_field"`
	TOTPSecretField   string `mapstructure:"totp_secret_field"`
	TOTPRecoveryField string `mapstructure:"totp_recovery_field"`
	DisplayNameField  string `mapstructure:"display_name_field"`
	CredentialObject  string `mapstructure:"credential_object"`
	CredentialIDField string `mapstructure:"credential_id_field"`
	PublicKeyField    string `mapstructure:"public_key_field"`
	UniqueUserIDField string `mapstructure:"unique_user_id_field"`
	AAGUIDField       string `mapstructure:"aaguid_field"`
	SignCountField    string `mapstructure:"sign_count_field"`
}

type LDAPSearchProtocol struct {
	Protocols []string `mapstructure:"protocol"`
	CacheName string   `mapstructure:"cache_name"`
	BaseDN    string   `mapstructure:"base_dn"`
	Scope     string

	LDAPFilter           `mapstructure:"filter"`
	LDAPAttributeMapping `mapstructure:"mapping"`

	// LDAP result attributes
	Attributes []string `mapstructure:"attribute"`
}

// GetAccountField returns the LDAP attribute for an account. It returns a DetailedError, if no value has
// been configured.
func (p *LDAPSearchProtocol) GetAccountField() (string, error) {
	if p.AccountField == "" {
		return "", errors.ErrLDAPConfig.WithDetail(
			fmt.Sprintf("Missing LDAP account field; protocols=%v", p.Protocols))
	}

	return p.AccountField, nil
}

// GetAttributes returns a list of attributes that are requested from the LDAP server.  It returns a DetailedError, if
// no value has been configured.
func (p *LDAPSearchProtocol) GetAttributes() ([]string, error) {
	if len(p.Attributes) == 0 {
		return nil, errors.ErrLDAPConfig.WithDetail(
			fmt.Sprintf("Missing LDAP result attribute; protocols=%v", p.Protocols))
	}

	return p.Attributes, nil
}

// GetUserFilter returns an LDAP search filter to find a user.  It returns a DetailedError, if no value has
// been configured.
func (p *LDAPSearchProtocol) GetUserFilter() (string, error) {
	if p.User == "" {
		return "", errors.ErrLDAPConfig.WithDetail(
			fmt.Sprintf("Missing LDAP user filter; protocols=%v", p.Protocols))
	}

	return p.User, nil
}

// GetListAccountsFilter returns an LDAP filter which is used to find all user accounts.  It returns a DetailedError, if
// no value has been configured.
func (p *LDAPSearchProtocol) GetListAccountsFilter() (string, error) {
	if p.ListAccounts == "" {
		return "", errors.ErrLDAPConfig.WithDetail(
			fmt.Sprintf("Missing LDAP list_accounts filter; protocols=%v", p.Protocols))
	}

	return p.ListAccounts, nil
}

// GetBaseDN returns the base DN that is used for each specific protocol.  It returns a DetailedError, if no value has
// been configured.
func (p *LDAPSearchProtocol) GetBaseDN() (string, error) {
	if p.BaseDN == "" {
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
	if p.Scope == "" {
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
	if p.CacheName == "" {
		return "", errors.ErrLDAPConfig.WithDetail("No cache name setting")
	}

	return p.CacheName, nil
}
