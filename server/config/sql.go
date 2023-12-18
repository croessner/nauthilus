package config

import (
	"fmt"

	"github.com/croessner/nauthilus/server/errors"
)

type SQLSection struct {
	Config *SQLConf
	Search []SQLSearchProtocol
}

func (s *SQLSection) String() string {
	return fmt.Sprintf("SQLSection: {Config[%+v] Search[%+v]}", s.Config, s.Search)
}

func (s *SQLSection) GetConfig() any {
	return s.Config
}

func (s *SQLSection) GetProtocols() any {
	return s.Search
}

type SQLConf struct {
	DSN   string
	Crypt bool `mapstructure:"password_crypt"`
}

type SQLQuery struct {
	User                string
	ListAccounts        string `mapstructure:"list_accounts"`
	TOTPSecret          string `mapstructure:"totp_secret"`
	WebAuthnCredentials string `mapstructure:"webauthn_credentials"`
}

type SQLFieldMapping struct {
	AccountField      string `mapstructure:"account_field"`
	PasswordField     string `mapstructure:"password_field"`
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

type SQLSearchProtocol struct {
	Protocols []string `mapstructure:"protocol"`
	CacheName string   `mapstructure:"cache_name"`

	SQLQuery        `mapstructure:"query"`
	SQLFieldMapping `mapstructure:"mapping"`
}

// GetAccountField returns the SQL attribute for an account. It returns a DetailedError, if no value has
// been configured.
func (p *SQLSearchProtocol) GetAccountField() (string, error) {
	if p.AccountField == "" {
		return "", errors.ErrSQLConfig.WithDetail(
			fmt.Sprintf("Missing SQL account field; protocols=%v", p.Protocols))
	}

	return p.AccountField, nil
}

// GetPasswordField returns the SQL attribute for the password. It returns a DetailedError, if no value has
// been configured.
func (p *SQLSearchProtocol) GetPasswordField() (string, error) {
	if p.PasswordField == "" {
		return "", errors.ErrSQLConfig.WithDetail(
			fmt.Sprintf("Missing SQL password field; protocols=%v", p.Protocols))
	}

	return p.PasswordField, nil
}

// GetUserQuery returns an SQL search query to find a user.  It returns a DetailedError, if no value has
// been configured.
func (p *SQLSearchProtocol) GetUserQuery() (string, error) {
	if p.User == "" {
		return "", errors.ErrSQLConfig.WithDetail(
			fmt.Sprintf("Missing SQL user query; protocols=%v", p.Protocols))
	}

	return p.User, nil
}

// GetListAccountsQuery returns an SQL query which is used to find all user accounts.  It returns a DetailedError, if
// no value has been configured.
func (p *SQLSearchProtocol) GetListAccountsQuery() (string, error) {
	if p.ListAccounts == "" {
		return "", errors.ErrSQLConfig.WithDetail(
			fmt.Sprintf("Missing SQL list_accounts query; protocols=%v", p.Protocols))
	}

	return p.ListAccounts, nil
}

// GetTOTPSecretQuery returns an SQL query which is used to find a TOTP secret.  It returns a DetailedError, if
// no value has been configured.
func (p *SQLSearchProtocol) GetTOTPSecretQuery() (string, error) {
	if p.TOTPSecret == "" {
		return "", errors.ErrSQLConfig.WithDetail(
			fmt.Sprintf("Missing SQL totp_secret query; protocols=%v", p.Protocols))
	}

	return p.TOTPSecret, nil
}

// GetCacheName returns the Redis cache domain. It returns a DetailedError, if no value has
// been configured.
func (p *SQLSearchProtocol) GetCacheName() (string, error) {
	if p.CacheName == "" {
		return "", errors.ErrSQLConfig.WithDetail("No cache name setting")
	}

	return p.CacheName, nil
}
