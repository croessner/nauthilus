package core

import (
	"errors"
	"fmt"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/decl"
	errors2 "github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/logging"
	"github.com/croessner/nauthilus/server/util"
	"github.com/go-kit/log/level"
	"github.com/go-ldap/ldap/v3"
	"github.com/go-webauthn/webauthn/webauthn"
)

// LDAPPassDB implements the LDAP password database backend.
//
//nolint:gocognit // Backends are complex
func LDAPPassDB(auth *Authentication) (passDBResult *PassDBResult, err error) {
	var (
		assertOk           bool
		accountField       string
		filter             string
		baseDN             string
		distinguishedNames any
		attributes         []string
		scope              *config.LDAPScope
		ldapReply          *backend.LDAPReply
		protocol           *config.LDAPSearchProtocol
	)

	passDBResult = &PassDBResult{}

	ldapReplyChan := make(chan *backend.LDAPReply)

	if protocol, err = config.LoadableConfig.GetLDAPSearchProtocol(auth.Protocol.Get()); err != nil {
		return
	}

	if accountField, err = protocol.GetAccountField(); err != nil {
		return
	}

	if attributes, err = protocol.GetAttributes(); err != nil {
		return
	}

	if filter, err = protocol.GetUserFilter(); err != nil {
		return
	}

	if baseDN, err = protocol.GetBaseDN(); err != nil {
		return
	}

	if scope, err = protocol.GetScope(); err != nil {
		return
	}

	ldapRequest := &backend.LDAPRequest{
		GUID:    auth.GUID,
		Command: decl.LDAPSearch,
		MacroSource: &util.MacroSource{
			Username:    auth.Username,
			XLocalIP:    auth.XLocalIP,
			XPort:       auth.XPort,
			ClientIP:    auth.ClientIP,
			XClientPort: auth.XClientPort,
			TOTPSecret:  auth.TOTPSecret,
			Protocol:    *auth.Protocol,
		},
		Filter:            filter,
		BaseDN:            baseDN,
		SearchAttributes:  attributes,
		Scope:             *scope,
		LDAPReplyChan:     ldapReplyChan,
		HTTPClientContext: auth.HTTPClientContext,
	}

	// Find user with account status enabled
	backend.LDAPRequestChan <- ldapRequest

	ldapReply = <-ldapReplyChan

	if ldapReply.Err != nil {
		return passDBResult, ldapReply.Err
	}

	// User not found
	if distinguishedNames, assertOk = ldapReply.Result[decl.DistinguishedName]; !assertOk {
		return
	}

	if len(distinguishedNames.([]any)) == 0 {
		return
	}

	dn := distinguishedNames.([]any)[decl.LDAPSingleValue].(string)

	// If a DN was returned and an account field is present, the user was found in the backend.
	passDBResult.UserFound = true
	passDBResult.Backend = decl.BackendLDAP

	if _, okay := ldapReply.Result[accountField]; okay {
		passDBResult.AccountField = &accountField
	}

	if protocol.TOTPSecretField != "" {
		passDBResult.TOTPSecretField = &protocol.TOTPSecretField
	}

	if protocol.UniqueUserIDField != "" {
		passDBResult.UniqueUserIDField = &protocol.UniqueUserIDField
	}

	if protocol.DisplayNameField != "" {
		passDBResult.DisplayNameField = &protocol.DisplayNameField
	} else {
		// Fallback
		passDBResult.DisplayNameField = &accountField
	}

	if len(ldapReply.Result) > 0 {
		passDBResult.Attributes = ldapReply.Result
	}

	if !auth.NoAuth {
		ldapReplyChan = make(chan *backend.LDAPReply)

		ldapUserBindRequest := &backend.LDAPAuthRequest{
			GUID:              auth.GUID,
			BindDN:            dn,
			BindPW:            auth.Password,
			LDAPReplyChan:     ldapReplyChan,
			HTTPClientContext: auth.HTTPClientContext,
		}

		backend.LDAPAuthRequestChan <- ldapUserBindRequest

		ldapReply = <-ldapReplyChan

		if ldapReply.Err != nil {
			level.Debug(logging.DefaultLogger).Log(decl.LogKeyGUID, auth.GUID, decl.LogKeyMsg, err)

			var ldapError *ldap.Error

			if errors.As(err, &ldapError) {
				if ldapError.ResultCode != uint16(ldap.LDAPResultInvalidCredentials) {
					return passDBResult, ldapError.Err
				}
			}

			// Authentication failed!
			return
		}
	}

	passDBResult.Authenticated = true

	return
}

// LDAPAccountDB implements the list-account mode and returns all known users from an LDAP server.
func LDAPAccountDB(auth *Authentication) (accounts AccountList, err error) {
	var (
		accountField string
		filter       string
		baseDN       string
		attributes   []string
		ldapReply    *backend.LDAPReply
		scope        *config.LDAPScope
		protocol     *config.LDAPSearchProtocol
	)

	ldapReplyChan := make(chan *backend.LDAPReply)

	if protocol, err = config.LoadableConfig.GetLDAPSearchProtocol(auth.Protocol.Get()); err != nil {
		return
	}

	if accountField, err = protocol.GetAccountField(); err != nil {
		return
	}

	if attributes, err = protocol.GetAttributes(); err != nil {
		return
	}

	if filter, err = protocol.GetListAccountsFilter(); err != nil {
		return
	}

	if baseDN, err = protocol.GetBaseDN(); err != nil {
		return
	}

	if scope, err = protocol.GetScope(); err != nil {
		return
	}

	ldapRequest := &backend.LDAPRequest{
		GUID:    auth.GUID,
		Command: decl.LDAPSearch,
		MacroSource: &util.MacroSource{
			Username:    auth.Username,
			XLocalIP:    auth.XLocalIP,
			XPort:       auth.XPort,
			ClientIP:    auth.ClientIP,
			XClientPort: auth.XClientPort,
			TOTPSecret:  auth.TOTPSecret,
			Protocol:    *auth.Protocol,
		},
		Filter:            filter,
		BaseDN:            baseDN,
		SearchAttributes:  attributes,
		Scope:             *scope,
		LDAPReplyChan:     ldapReplyChan,
		HTTPClientContext: auth.HTTPClientContext,
	}

	// Find user with account status enabled
	backend.LDAPRequestChan <- ldapRequest

	ldapReply = <-ldapReplyChan

	if ldapReply.Err != nil {
		var ldapError *ldap.Error

		if errors.As(err, &ldapError) {
			return accounts, ldapError.Err
		}

		return accounts, ldapReply.Err
	}

	if result, okay := ldapReply.Result[accountField]; okay {
		for index := range result {
			if account, okay := result[index].(string); okay {
				accounts = append(accounts, account)
			}
		}
	}

	return
}

// LDAPAddTOTPSecret adds a newly generated TOTP secret to an LDAP server.
func LDAPAddTOTPSecret(auth *Authentication, totp *TOTPSecret) (err error) {
	var (
		filter      string
		baseDN      string
		configField string
		ldapReply   *backend.LDAPReply
		scope       *config.LDAPScope
		protocol    *config.LDAPSearchProtocol
		ldapError   *ldap.Error
	)

	ldapReplyChan := make(chan *backend.LDAPReply)

	if protocol, err = config.LoadableConfig.GetLDAPSearchProtocol(auth.Protocol.Get()); err != nil {
		return
	}

	if filter, err = protocol.GetUserFilter(); err != nil {
		return
	}

	if baseDN, err = protocol.GetBaseDN(); err != nil {
		return
	}

	if scope, err = protocol.GetScope(); err != nil {
		return
	}

	configField = totp.GetLDAPTOTPSecret(protocol)
	if configField == "" {
		err = errors2.ErrLDAPConfig.WithDetail(
			fmt.Sprintf("Missing LDAP TOTP secret field; protocol=%s", auth.Protocol.Get()))

		return
	}

	ldapRequest := &backend.LDAPRequest{
		GUID:    auth.GUID,
		Command: decl.LDAPModifyAdd,
		MacroSource: &util.MacroSource{
			Username:    auth.Username,
			XLocalIP:    auth.XLocalIP,
			XPort:       auth.XPort,
			ClientIP:    auth.ClientIP,
			XClientPort: auth.XClientPort,
			TOTPSecret:  auth.TOTPSecret,
			Protocol:    *auth.Protocol,
		},
		Filter:            filter,
		BaseDN:            baseDN,
		Scope:             *scope,
		LDAPReplyChan:     ldapReplyChan,
		HTTPClientContext: auth.HTTPClientContext,
	}

	ldapRequest.ModifyAttributes = make(backend.LDAPModifyAttributes, 2)
	ldapRequest.ModifyAttributes[configField] = []string{totp.GetValue()}

	backend.LDAPRequestChan <- ldapRequest

	ldapReply = <-ldapReplyChan

	if errors.As(ldapReply.Err, &ldapError) {
		return ldapError.Err
	}

	return ldapReply.Err
}

func LDAPGetWebAuthnCredentials(uniqueUserID string) ([]webauthn.Credential, error) {
	_ = uniqueUserID

	// TODO: Use WebAuthn constructor!

	return []webauthn.Credential{}, nil
}
