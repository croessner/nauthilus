package core

import (
	"errors"
	"fmt"
	"strings"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/config"
	errors2 "github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/logging"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/go-kit/log/level"
	"github.com/go-ldap/ldap/v3"
	"github.com/go-webauthn/webauthn/webauthn"
)

// handleMasterUserMode handles the master user mode functionality for authentication.
// If master user mode is enabled and the username contains only one occurrence of the delimiter,
// it splits the username based on the delimiter and returns the appropriate part of the username
// based on the master user mode flag.
//
// Parameters:
// - auth: a pointer to the Authentication struct which contains the user authentication information.
//
// Returns:
// - string: the username based on the master user mode flag.
func handleMasterUserMode(auth *Authentication) string {
	if config.LoadableConfig.Server.MasterUser.Enabled {
		if strings.Count(auth.Username, config.LoadableConfig.Server.MasterUser.Delimiter) == 1 {
			parts := strings.Split(auth.Username, config.LoadableConfig.Server.MasterUser.Delimiter)

			if !(len(parts[0]) > 0 && len(parts[1]) > 0) {
				return auth.Username
			}

			if !auth.MasterUserMode {
				auth.MasterUserMode = true

				// Return master user
				return parts[1]
			} else {
				auth.MasterUserMode = false

				// Return real user
				return parts[0]
			}
		}
	}

	return auth.Username
}

// saveMasterUserTOTPSecret checks if the master user has a TOTP secret and returns it if present.
//
// Parameters:
// - masterUserMode: a boolean indicating if master user mode is enabled.
// - ldapReply: a pointer to the LDAPReply struct containing the LDAP query result.
// - totpSecretField: a string indicating the field in which the TOTP secret is stored in the LDAPReply.
//
// Returns:
// - totpSecretPre: a slice of interface{} containing the TOTP secret if present, nil otherwise.
func saveMasterUserTOTPSecret(masterUserMode bool, ldapReply *backend.LDAPReply, totpSecretField string) (totpSecretPre []any) {
	if masterUserMode {
		// Check if the master user does have a TOTP secret.
		if value, okay := ldapReply.Result[totpSecretField]; okay {
			return value
		}
	}

	return nil
}

// restoreMasterUserTOTPSecret restores the TOTP secret for a master user in the PassDBResult attributes.
// If the totpSecretPre parameter is not empty, it sets the TOTP secret attribute in the attributes map.
// Otherwise, it deletes the TOTP secret attribute from the attributes map.
//
// Parameters:
// - passDBResult: a pointer to the PassDBResult struct which contains the PassDB result attributes.
// - totpSecretPre: an array of any type that represents the TOTP secret from a master user.
// - totpSecretField: a string that represents the field name for the TOTP secret in the attributes map.
func restoreMasterUserTOTPSecret(passDBResult *PassDBResult, totpSecretPre []any, totpSecretField string) {
	if totpSecretPre != nil && len(totpSecretPre) != 0 {
		// Use the TOTP secret from a master user if it exists.
		passDBResult.Attributes[totpSecretField] = totpSecretPre
	} else {
		// Ignore the user TOTP secret if it exists.
		delete(passDBResult.Attributes, totpSecretField)
	}
}

// ldapPassDB implements the LDAP password database backend.
//
//nolint:gocognit // Backends are complex
func ldapPassDB(auth *Authentication) (passDBResult *PassDBResult, err error) {
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

	defer close(ldapReplyChan)

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

	username := handleMasterUserMode(auth)

	ldapRequest := &backend.LDAPRequest{
		GUID:    auth.GUID,
		Command: global.LDAPSearch,
		MacroSource: &util.MacroSource{
			Username:    username,
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
	if distinguishedNames, assertOk = ldapReply.Result[global.DistinguishedName]; !assertOk {
		return
	}

	if len(distinguishedNames.([]any)) == 0 {
		return
	}

	dn := distinguishedNames.([]any)[global.LDAPSingleValue].(string)

	// If a DN was returned and an account field is present, the user was found in the backend.
	passDBResult.UserFound = true
	passDBResult.Backend = global.BackendLDAP

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

	totpSecretPre := saveMasterUserTOTPSecret(auth.MasterUserMode, ldapReply, protocol.TOTPSecretField)

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
			var ldapError *ldap.Error

			level.Debug(logging.DefaultLogger).Log(global.LogKeyGUID, auth.GUID, global.LogKeyMsg, err)

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

	// We need to do a second user lookup, to retrieve correct data from LDAP.
	if auth.MasterUserMode {
		auth.NoAuth = true

		passDBResult, err = ldapPassDB(auth)

		restoreMasterUserTOTPSecret(passDBResult, totpSecretPre, protocol.TOTPSecretField)
	}

	return
}

// ldapAccountDB implements the list-account mode and returns all known users from an LDAP server.
func ldapAccountDB(auth *Authentication) (accounts AccountList, err error) {
	var (
		accountField string
		filter       string
		baseDN       string
		attributes   []string
		ldapReply    *backend.LDAPReply
		scope        *config.LDAPScope
		protocol     *config.LDAPSearchProtocol
	)

	stopTimer := stats.PrometheusTimer(global.PromAccount, "ldap_account_request_total")

	defer stopTimer()

	ldapReplyChan := make(chan *backend.LDAPReply)

	defer close(ldapReplyChan)

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
		Command: global.LDAPSearch,
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

// ldapAddTOTPSecret adds a newly generated TOTP secret to an LDAP server.
func ldapAddTOTPSecret(auth *Authentication, totp *TOTPSecret) (err error) {
	var (
		filter      string
		baseDN      string
		configField string
		ldapReply   *backend.LDAPReply
		scope       *config.LDAPScope
		protocol    *config.LDAPSearchProtocol
		ldapError   *ldap.Error
	)

	stopTimer := stats.PrometheusTimer(global.PromStoreTOTP, "ldap_store_totp_request_total")

	defer stopTimer()

	ldapReplyChan := make(chan *backend.LDAPReply)

	defer close(ldapReplyChan)

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

	configField = totp.getLDAPTOTPSecret(protocol)
	if configField == "" {
		err = errors2.ErrLDAPConfig.WithDetail(
			fmt.Sprintf("Missing LDAP TOTP secret field; protocol=%s", auth.Protocol.Get()))

		return
	}

	ldapRequest := &backend.LDAPRequest{
		GUID:    auth.GUID,
		Command: global.LDAPModifyAdd,
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
	ldapRequest.ModifyAttributes[configField] = []string{totp.getValue()}

	backend.LDAPRequestChan <- ldapRequest

	ldapReply = <-ldapReplyChan

	if errors.As(ldapReply.Err, &ldapError) {
		return ldapError.Err
	}

	return ldapReply.Err
}

func ldapGetWebAuthnCredentials(uniqueUserID string) ([]webauthn.Credential, error) {
	_ = uniqueUserID

	// TODO: Use WebAuthn constructor!

	return []webauthn.Credential{}, nil
}
