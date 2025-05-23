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

package core

import (
	stderrors "errors"
	"fmt"
	"strings"

	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/backend/priorityqueue"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/localcache"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/go-ldap/ldap/v3"
	"github.com/go-webauthn/webauthn/webauthn"
)

// ldapManagerImpl provides an implementation for managing LDAP connections and operations using a specific connection pool.
type ldapManagerImpl struct {
	// poolName specifies the identifier for the LDAP connection pool to be utilized by the manager implementation.
	poolName string
}

// handleMasterUserMode handles the master user mode functionality for authentication.
// If master user mode is enabled and the username contains only one occurrence of the delimiter,
// it splits the username based on the delimiter and returns the appropriate part of the username
// based on the master user mode flag.
//
// Parameters:
// - auth: a pointer to the AuthState struct which contains the user authentication information.
//
// Returns:
// - string: the username based on the master user mode flag.
func handleMasterUserMode(auth *AuthState) string {
	if config.GetFile().GetServer().GetMasterUser().IsEnabled() {
		if strings.Count(auth.Username, config.GetFile().GetServer().GetMasterUser().GetDelimiter()) == 1 {
			parts := strings.Split(auth.Username, config.GetFile().GetServer().GetMasterUser().GetDelimiter())

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
// - totpSecretPre: a slice of any containing the TOTP secret if present, nil otherwise.
func saveMasterUserTOTPSecret(masterUserMode bool, ldapReply *bktype.LDAPReply, totpSecretField string) (totpSecretPre []any) {
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
	if passDBResult == nil || passDBResult.Attributes == nil {
		return
	}

	if totpSecretPre != nil && len(totpSecretPre) != 0 {
		// Use the TOTP secret from a master user if it exists.
		passDBResult.Attributes[totpSecretField] = totpSecretPre
	} else {
		// Ignore the user TOTP secret if it exists.
		delete(passDBResult.Attributes, totpSecretField)
	}
}

// PassDB implements the LDAP password database backend.
func (lm *ldapManagerImpl) PassDB(auth *AuthState) (passDBResult *PassDBResult, err error) {
	var (
		assertOk           bool
		accountField       string
		filter             string
		baseDN             string
		distinguishedNames any
		attributes         []string
		scope              *config.LDAPScope
		ldapReply          *bktype.LDAPReply
		protocol           *config.LDAPSearchProtocol
	)

	passDBResult = GetPassDBResultFromPool()

	ldapReplyChan := make(chan *bktype.LDAPReply)

	if protocol, err = config.GetFile().GetLDAPSearchProtocol(auth.Protocol.Get(), lm.poolName); protocol == nil || err != nil {
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

	ldapRequest := &bktype.LDAPRequest{
		GUID:    auth.GUID,
		Command: definitions.LDAPSearch,
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
	// Determine priority based on NoAuth flag and whether the user is already authenticated
	priority := priorityqueue.PriorityLow
	if !auth.NoAuth {
		priority = priorityqueue.PriorityMedium
	}

	if localcache.AuthCache.IsAuthenticated(auth.Username) {
		priority = priorityqueue.PriorityHigh
	}

	// Use priority queue instead of channel
	priorityqueue.LDAPQueue.Push(ldapRequest, priority)

	ldapReply = <-ldapReplyChan

	if ldapReply.Err != nil {
		return passDBResult, ldapReply.Err
	}

	// User not found
	if distinguishedNames, assertOk = ldapReply.Result[definitions.DistinguishedName]; !assertOk {
		return
	}

	if len(distinguishedNames.([]any)) == 0 {
		return
	}

	dn := distinguishedNames.([]any)[definitions.LDAPSingleValue].(string)

	// If a DN was returned and an account field is present, the user was found in the backend.
	passDBResult.UserFound = true
	passDBResult.Backend = definitions.BackendLDAP
	passDBResult.BackendName = lm.poolName

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
		ldapReplyChan = make(chan *bktype.LDAPReply)

		ldapUserBindRequest := &bktype.LDAPAuthRequest{
			GUID:              auth.GUID,
			BindDN:            dn,
			BindPW:            auth.Password,
			LDAPReplyChan:     ldapReplyChan,
			HTTPClientContext: auth.HTTPClientContext,
		}

		// Determine priority based on NoAuth flag and whether the user is already authenticated
		priority := priorityqueue.PriorityLow
		if !auth.NoAuth {
			priority = priorityqueue.PriorityMedium
		}

		if localcache.AuthCache.IsAuthenticated(auth.Username) {
			priority = priorityqueue.PriorityHigh
		}

		// Use priority queue instead of channel
		priorityqueue.LDAPAuthQueue.Push(ldapUserBindRequest, priority)

		ldapReply = <-ldapReplyChan

		if ldapReply.Err != nil {
			var ldapError *ldap.Error

			util.DebugModule(
				definitions.DbgLDAP,
				definitions.LogKeyGUID, auth.GUID,
				definitions.LogKeyMsg, err,
			)

			if stderrors.As(err, &ldapError) {
				if ldapError.ResultCode != uint16(ldap.LDAPResultInvalidCredentials) {
					return passDBResult, ldapError.Err
				}
			}

			// AuthState failed!
			return
		}
	}

	passDBResult.Authenticated = true

	// Update the authentication cache
	localcache.AuthCache.Set(auth.Username, true)

	// We need to do a second user lookup, to retrieve correct data from LDAP.
	if auth.MasterUserMode {
		auth.NoAuth = true

		passDBResult, err = lm.PassDB(auth)

		restoreMasterUserTOTPSecret(passDBResult, totpSecretPre, protocol.TOTPSecretField)
	}

	return
}

// AccountDB implements the list-account mode and returns all known users from an LDAP server.
func (lm *ldapManagerImpl) AccountDB(auth *AuthState) (accounts AccountList, err error) {
	var (
		accountField string
		filter       string
		baseDN       string
		attributes   []string
		ldapReply    *bktype.LDAPReply
		scope        *config.LDAPScope
		protocol     *config.LDAPSearchProtocol
	)

	stopTimer := stats.PrometheusTimer(definitions.PromAccount, "ldap_account_request_total")

	if stopTimer != nil {
		defer stopTimer()
	}

	ldapReplyChan := make(chan *bktype.LDAPReply)

	if protocol, err = config.GetFile().GetLDAPSearchProtocol(auth.Protocol.Get(), lm.poolName); protocol == nil || err != nil {
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

	ldapRequest := &bktype.LDAPRequest{
		GUID:    auth.GUID,
		Command: definitions.LDAPSearch,
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
	// Determine priority based on NoAuth flag and whether the user is already authenticated
	priority := priorityqueue.PriorityLow
	if !auth.NoAuth {
		priority = priorityqueue.PriorityMedium
	}
	if localcache.AuthCache.IsAuthenticated(auth.Username) {
		priority = priorityqueue.PriorityHigh
	}

	// Use priority queue instead of channel
	priorityqueue.LDAPQueue.Push(ldapRequest, priority)

	ldapReply = <-ldapReplyChan

	if ldapReply.Err != nil {
		var ldapError *ldap.Error

		if stderrors.As(err, &ldapError) {
			return accounts, ldapError.Err
		}

		return accounts, ldapReply.Err
	}

	if result, okay := ldapReply.Result[accountField]; okay {
		// Pre-allocate the accounts slice to avoid continuous reallocation
		accounts = make([]string, 0, len(result))
		for index := range result {
			if account, okay := result[index].(string); okay {
				accounts = append(accounts, account)
			}
		}
	}

	return
}

// AddTOTPSecret adds a newly generated TOTP secret to an LDAP server.
func (lm *ldapManagerImpl) AddTOTPSecret(auth *AuthState, totp *TOTPSecret) (err error) {
	var (
		filter      string
		baseDN      string
		configField string
		ldapReply   *bktype.LDAPReply
		scope       *config.LDAPScope
		protocol    *config.LDAPSearchProtocol
		ldapError   *ldap.Error
	)

	stopTimer := stats.PrometheusTimer(definitions.PromStoreTOTP, "ldap_store_totp_request_total")

	if stopTimer != nil {
		defer stopTimer()
	}

	ldapReplyChan := make(chan *bktype.LDAPReply)

	if protocol, err = config.GetFile().GetLDAPSearchProtocol(auth.Protocol.Get(), lm.poolName); protocol == nil || err != nil {
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
		err = errors.ErrLDAPConfig.WithDetail(
			fmt.Sprintf("Missing LDAP TOTP secret field; protocol=%s", auth.Protocol.Get()))

		return
	}

	ldapRequest := &bktype.LDAPRequest{
		GUID:       auth.GUID,
		Command:    definitions.LDAPModify,
		SubCommand: definitions.LDAPModifyAdd,
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

	ldapRequest.ModifyAttributes = make(bktype.LDAPModifyAttributes, 2)
	ldapRequest.ModifyAttributes[configField] = []string{totp.getValue()}

	// Determine priority based on NoAuth flag and whether the user is already authenticated
	priority := priorityqueue.PriorityLow
	if !auth.NoAuth {
		priority = priorityqueue.PriorityMedium
	}
	if localcache.AuthCache.IsAuthenticated(auth.Username) {
		priority = priorityqueue.PriorityHigh
	}

	// Use priority queue instead of channel
	priorityqueue.LDAPQueue.Push(ldapRequest, priority)

	ldapReply = <-ldapReplyChan

	if stderrors.As(ldapReply.Err, &ldapError) {
		return ldapError.Err
	}

	return ldapReply.Err
}

func ldapGetWebAuthnCredentials(uniqueUserID string) ([]webauthn.Credential, error) {
	_ = uniqueUserID

	// TODO: Use WebAuthn constructor!

	return []webauthn.Credential{}, nil
}

var _ BackendManager = (*ldapManagerImpl)(nil)

// NewLDAPManager creates and returns a BackendManager for managing LDAP authentication backends using the specified pool name.
func NewLDAPManager(poolName string) BackendManager {
	return &ldapManagerImpl{
		poolName: poolName,
	}
}
