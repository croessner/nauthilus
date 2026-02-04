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
	"context"
	stderrors "errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/backend/priorityqueue"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/localcache"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/model/mfa"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/security"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"

	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/go-ldap/ldap/v3"
	"go.opentelemetry.io/otel/attribute"
)

// ldapManagerImpl provides an implementation for managing LDAP connections and operations using a specific connection pool.
type ldapManagerImpl struct {
	poolName string
	deps     AuthDeps
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
func handleMasterUserMode(cfg config.File, auth *AuthState) string {
	if cfg.GetServer().GetMasterUser().IsEnabled() {
		if strings.Count(auth.Request.Username, cfg.GetServer().GetMasterUser().GetDelimiter()) == 1 {
			parts := strings.Split(auth.Request.Username, cfg.GetServer().GetMasterUser().GetDelimiter())

			if !(len(parts[0]) > 0 && len(parts[1]) > 0) {
				return auth.Request.Username
			}

			if !auth.Runtime.MasterUserMode {
				auth.Runtime.MasterUserMode = true

				// Return master user
				return parts[1]
			} else {
				auth.Runtime.MasterUserMode = false

				// Return real user
				return parts[0]
			}
		}
	}

	return auth.Request.Username
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

func decryptLDAPAttributeValues(manager *security.Manager, attributes bktype.AttributeMapping, fieldName string) error {
	if manager == nil || attributes == nil || fieldName == "" {
		return nil
	}

	value, ok := attributes[fieldName]
	if !ok {
		return nil
	}

	decrypted, err := decryptLDAPAttributeValue(manager, value)
	if err != nil {
		return err
	}

	normalized, err := normalizeLDAPAttributeValues(decrypted)
	if err != nil {
		return err
	}

	attributes[fieldName] = normalized

	return nil
}

func decryptLDAPAttributeValue(manager *security.Manager, value any) (any, error) {
	if manager == nil {
		return value, nil
	}

	switch typedValue := value.(type) {
	case []any:
		decrypted := make([]any, len(typedValue))
		for index, entry := range typedValue {
			switch entryValue := entry.(type) {
			case string:
				plaintext, err := manager.Decrypt(entryValue)
				if err != nil {
					return nil, err
				}
				decrypted[index] = plaintext
			case []byte:
				plaintext, err := manager.Decrypt(string(entryValue))
				if err != nil {
					return nil, err
				}
				decrypted[index] = plaintext
			default:
				decrypted[index] = entry
			}
		}

		return decrypted, nil
	case []string:
		decrypted := make([]string, len(typedValue))
		for index, entry := range typedValue {
			plaintext, err := manager.Decrypt(entry)
			if err != nil {
				return nil, err
			}
			decrypted[index] = plaintext
		}

		return decrypted, nil
	case string:
		return manager.Decrypt(typedValue)
	case []byte:
		return manager.Decrypt(string(typedValue))
	default:
		return value, nil
	}
}

func normalizeLDAPAttributeValues(value any) ([]any, error) {
	switch typedValue := value.(type) {
	case []any:
		return typedValue, nil
	case []string:
		normalized := make([]any, len(typedValue))
		for index, entry := range typedValue {
			normalized[index] = entry
		}

		return normalized, nil
	case string:
		return []any{typedValue}, nil
	case []byte:
		return []any{string(typedValue)}, nil
	default:
		return nil, fmt.Errorf("unsupported LDAP attribute type: %T", value)
	}
}

// PassDB implements the LDAP password database backend.
func (lm *ldapManagerImpl) effectiveCfg() config.File {
	return lm.deps.Cfg
}

func (lm *ldapManagerImpl) effectiveLogger() *slog.Logger {
	return lm.deps.Logger
}

func (lm *ldapManagerImpl) effectiveEnv() config.Environment {
	return lm.deps.Env
}

func (lm *ldapManagerImpl) effectiveRedis() rediscli.Client {
	return lm.deps.Redis
}

func (lm *ldapManagerImpl) PassDB(auth *AuthState) (passDBResult *PassDBResult, err error) {
	tr := monittrace.New("nauthilus/ldap")
	lctx, lspan := tr.Start(auth.Ctx(), "ldap.passdb",
		attribute.String("pool_name", lm.poolName),
		attribute.String("service", auth.Request.Service),
		attribute.String("username", auth.Request.Username),
		attribute.String("protocol", auth.Request.Protocol.Get()),
	)

	defer lspan.End()

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

	resource := util.RequestResource(auth.Request.HTTPClientContext, auth.Request.HTTPClientRequest, lm.poolName)
	stopTimer := stats.PrometheusTimer(lm.effectiveCfg(), definitions.PromBackend, "ldap_passdb_request_total", resource)

	if stopTimer != nil {
		defer stopTimer()
	}

	passDBResult = GetPassDBResultFromPool()

	ldapReplyChan := make(chan *bktype.LDAPReply, 1)

	pCtx, pSpan := tr.Start(lctx, "ldap.passdb.search.prepare")
	_ = pCtx

	if protocol, err = lm.effectiveCfg().GetLDAPSearchProtocol(auth.Request.Protocol.Get(), lm.poolName); protocol == nil || err != nil {
		pSpan.End()

		if err == nil {
			err = errors.ErrLDAPConfig.WithDetail(
				fmt.Sprintf("Missing LDAP search protocol; protocol=%s", auth.Request.Protocol.Get()))
		}

		return
	}

	if accountField, err = protocol.GetAccountField(); err != nil {
		pSpan.End()

		return
	}

	if attributes, err = protocol.GetAttributes(); err != nil {
		pSpan.End()

		return
	}

	if filter, err = protocol.GetUserFilter(); err != nil {
		pSpan.End()

		return
	}

	if baseDN, err = protocol.GetBaseDN(); err != nil {
		pSpan.End()

		return
	}

	if scope, err = protocol.GetScope(); err != nil {
		pSpan.End()

		return
	}

	username := handleMasterUserMode(lm.effectiveCfg(), auth)

	lspan.SetAttributes(
		attribute.String("base_dn", baseDN),
		attribute.String("scope", scope.String()),
	)

	// Derive a timeout context for LDAP search
	dSearch := lm.effectiveCfg().GetServer().GetTimeouts().GetLDAPSearch()
	ctxSearch, cancelSearch := context.WithTimeout(auth.Ctx(), dSearch)
	defer cancelSearch()

	ldapRequest := &bktype.LDAPRequest{
		GUID:     auth.Runtime.GUID,
		Command:  definitions.LDAPSearch,
		PoolName: lm.poolName,
		MacroSource: &util.MacroSource{
			Username:    username,
			XLocalIP:    auth.Request.XLocalIP,
			XPort:       auth.Request.XPort,
			ClientIP:    auth.Request.ClientIP,
			XClientPort: auth.Request.XClientPort,
			TOTPSecret:  auth.Runtime.TOTPSecret,
			Protocol:    *auth.Request.Protocol,
		},
		Filter:            filter,
		BaseDN:            baseDN,
		SearchAttributes:  attributes,
		Scope:             *scope,
		LDAPReplyChan:     ldapReplyChan,
		HTTPClientContext: ctxSearch,
	}

	// Find user with account status enabled
	// Determine priority based on NoAuth flag and whether the user is already authenticated
	priority := priorityqueue.PriorityLow
	if !auth.Request.NoAuth {
		priority = priorityqueue.PriorityMedium
	}

	if localcache.AuthCache.IsAuthenticated(auth.Request.Username) {
		priority = priorityqueue.PriorityHigh
	}

	pSpan.End()

	// Use priority queue instead of channel
	priorityqueue.LDAPQueue.Push(ldapRequest, priority)

	_, wSpan := tr.Start(lctx, "ldap.passdb.search.wait")
	ldapReply = <-ldapReplyChan
	wSpan.End()

	if ldapReply.Err != nil {
		lspan.RecordError(ldapReply.Err)

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

	lspan.SetAttributes(attribute.Bool("user_found", true))

	if _, okay := ldapReply.Result[accountField]; okay {
		passDBResult.AccountField = accountField
	}

	if protocol.TOTPSecretField != "" {
		passDBResult.TOTPSecretField = protocol.TOTPSecretField
	}

	if protocol.GetTotpRecoveryField() != "" {
		passDBResult.TOTPRecoveryField = protocol.GetTotpRecoveryField()
	}

	if protocol.UniqueUserIDField != "" {
		passDBResult.UniqueUserIDField = protocol.UniqueUserIDField
	}

	if protocol.DisplayNameField != "" {
		passDBResult.DisplayNameField = protocol.DisplayNameField
	} else {
		// Fallback
		passDBResult.DisplayNameField = accountField
	}

	var securityManager *security.Manager
	if protocol.TOTPSecretField != "" || protocol.GetTotpRecoveryField() != "" {
		securityManager = security.NewManager(lm.effectiveCfg().GetLDAPConfigEncryptionSecret())
	}

	if len(ldapReply.Result) > 0 {
		passDBResult.Attributes = ldapReply.Result
	}

	totpSecretPre := saveMasterUserTOTPSecret(auth.Runtime.MasterUserMode, ldapReply, protocol.TOTPSecretField)

	if passDBResult.Attributes != nil {
		if protocol.TOTPSecretField != "" {
			if decryptErr := decryptLDAPAttributeValues(securityManager, passDBResult.Attributes, protocol.TOTPSecretField); decryptErr != nil {
				return passDBResult, errors.ErrLDAPConfig.WithDetail(
					fmt.Sprintf("Failed to decrypt LDAP TOTP secret: %v", decryptErr))
			}
		}

		if protocol.GetTotpRecoveryField() != "" {
			if decryptErr := decryptLDAPAttributeValues(securityManager, passDBResult.Attributes, protocol.GetTotpRecoveryField()); decryptErr != nil {
				return passDBResult, errors.ErrLDAPConfig.WithDetail(
					fmt.Sprintf("Failed to decrypt LDAP TOTP recovery codes: %v", decryptErr))
			}
		}
	}

	if securityManager != nil && totpSecretPre != nil {
		decryptedSecret, decryptErr := decryptLDAPAttributeValue(securityManager, totpSecretPre)
		if decryptErr != nil {
			return passDBResult, errors.ErrLDAPConfig.WithDetail(
				fmt.Sprintf("Failed to decrypt LDAP master TOTP secret: %v", decryptErr))
		}

		switch typedSecret := decryptedSecret.(type) {
		case []any:
			totpSecretPre = typedSecret
		case []string:
			totpSecretPre = make([]any, len(typedSecret))
			for index, entry := range typedSecret {
				totpSecretPre[index] = entry
			}
		}
	}

	if !auth.Request.NoAuth {
		ldapReplyChan = make(chan *bktype.LDAPReply, 1)

		apCtx, apSpan := tr.Start(lctx, "ldap.passdb.auth.prepare")
		_ = apCtx

		// Derive a timeout context for LDAP bind/auth
		dBind := lm.effectiveCfg().GetServer().GetTimeouts().GetLDAPBind()
		ctxBind, cancelBind := context.WithTimeout(auth.Ctx(), dBind)
		defer cancelBind()

		ldapUserBindRequest := &bktype.LDAPAuthRequest{
			GUID:              auth.Runtime.GUID,
			PoolName:          lm.poolName,
			BindDN:            dn,
			BindPW:            auth.Request.Password,
			LDAPReplyChan:     ldapReplyChan,
			HTTPClientContext: ctxBind,
		}

		// Determine priority based on NoAuth flag and whether the user is already authenticated
		priority := priorityqueue.PriorityLow
		if !auth.Request.NoAuth {
			priority = priorityqueue.PriorityMedium
		}

		if localcache.AuthCache.IsAuthenticated(auth.Request.Username) {
			priority = priorityqueue.PriorityHigh
		}

		apSpan.End()

		// Use priority queue instead of channel
		priorityqueue.LDAPAuthQueue.Push(ldapUserBindRequest, priority)

		_, awSpan := tr.Start(lctx, "ldap.passdb.auth.wait")
		ldapReply = <-ldapReplyChan
		awSpan.End()

		if ldapReply.Err != nil {
			var ldapError *ldap.Error

			util.DebugModuleWithCfg(
				auth.Ctx(),
				lm.effectiveCfg(),
				lm.effectiveLogger(),
				definitions.DbgLDAP,
				definitions.LogKeyGUID, auth.Runtime.GUID,
				definitions.LogKeyMsg, err,
			)

			if stderrors.As(err, &ldapError) {
				if ldapError.ResultCode != uint16(ldap.LDAPResultInvalidCredentials) {
					lspan.RecordError(ldapError)

					return passDBResult, ldapError.Err
				}
			}

			// AuthState failed!
			lspan.SetAttributes(attribute.Bool("authenticated", false))

			return
		}
	}

	passDBResult.Authenticated = true

	lspan.SetAttributes(attribute.Bool("authenticated", true))

	// Update the authentication cache
	localcache.AuthCache.Set(auth.Request.Username, true)

	// We need to do a second user lookup, to retrieve correct data from LDAP.
	if auth.Runtime.MasterUserMode {
		auth.Request.NoAuth = true

		PutPassDBResultToPool(passDBResult)

		passDBResult, err = lm.PassDB(auth)

		restoreMasterUserTOTPSecret(passDBResult, totpSecretPre, protocol.TOTPSecretField)
	}

	return
}

// AccountDB implements the list-account mode and returns all known users from an LDAP server.
func (lm *ldapManagerImpl) AccountDB(auth *AuthState) (accounts AccountList, err error) {
	tr := monittrace.New("nauthilus/ldap")
	actx, asp := tr.Start(auth.Ctx(), "ldap.accountdb",
		attribute.String("pool_name", lm.poolName),
		attribute.String("service", auth.Request.Service),
		attribute.String("protocol", auth.Request.Protocol.Get()),
	)

	_ = actx

	defer asp.End()

	var (
		accountField string
		filter       string
		baseDN       string
		attributes   []string
		ldapReply    *bktype.LDAPReply
		scope        *config.LDAPScope
		protocol     *config.LDAPSearchProtocol
	)

	resource := util.RequestResource(auth.Request.HTTPClientContext, auth.Request.HTTPClientRequest, lm.poolName)
	stopTimer := stats.PrometheusTimer(lm.effectiveCfg(), definitions.PromAccount, "ldap_account_request_total", resource)

	if stopTimer != nil {
		defer stopTimer()
	}

	ldapReplyChan := make(chan *bktype.LDAPReply, 1)

	pCtx, pSpan := tr.Start(actx, "ldap.accountdb.prepare")
	_ = pCtx

	if protocol, err = lm.effectiveCfg().GetLDAPSearchProtocol(auth.Request.Protocol.Get(), lm.poolName); protocol == nil || err != nil {
		pSpan.End()

		if err == nil {
			err = errors.ErrLDAPConfig.WithDetail(
				fmt.Sprintf("Missing LDAP search protocol; protocol=%s", auth.Request.Protocol.Get()))
		}

		return
	}

	if accountField, err = protocol.GetAccountField(); err != nil {
		pSpan.End()

		return
	}

	if attributes, err = protocol.GetAttributes(); err != nil {
		pSpan.End()

		return
	}

	if filter, err = protocol.GetListAccountsFilter(); err != nil {
		pSpan.End()

		return
	}

	if baseDN, err = protocol.GetBaseDN(); err != nil {
		pSpan.End()

		return
	}

	if scope, err = protocol.GetScope(); err != nil {
		pSpan.End()

		return
	}

	asp.SetAttributes(
		attribute.String("base_dn", baseDN),
		attribute.String("scope", scope.String()),
	)

	// Derive a timeout context for LDAP search (account list) using service-scoped context
	ctxSearch, cancelSearch := util.GetCtxWithDeadlineLDAPSearch(lm.effectiveCfg())
	defer cancelSearch()

	ldapRequest := &bktype.LDAPRequest{
		GUID:     auth.Runtime.GUID,
		Command:  definitions.LDAPSearch,
		PoolName: lm.poolName,
		MacroSource: &util.MacroSource{
			Username:    auth.Request.Username,
			XLocalIP:    auth.Request.XLocalIP,
			XPort:       auth.Request.XPort,
			ClientIP:    auth.Request.ClientIP,
			XClientPort: auth.Request.XClientPort,
			TOTPSecret:  auth.Runtime.TOTPSecret,
			Protocol:    *auth.Request.Protocol,
		},
		Filter:            filter,
		BaseDN:            baseDN,
		SearchAttributes:  attributes,
		Scope:             *scope,
		LDAPReplyChan:     ldapReplyChan,
		HTTPClientContext: ctxSearch,
	}

	pSpan.End()

	priorityqueue.LDAPQueue.Push(ldapRequest, priorityqueue.PriorityMedium)

	_, wSpan := tr.Start(actx, "ldap.accountdb.wait")
	ldapReply = <-ldapReplyChan
	wSpan.End()

	if ldapReply.Err != nil {
		var ldapError *ldap.Error

		if stderrors.As(err, &ldapError) {
			asp.RecordError(ldapError)

			return accounts, ldapError.Err
		}

		asp.RecordError(ldapReply.Err)

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

	if len(accounts) == 0 {
		level.Warn(lm.effectiveLogger()).Log(
			definitions.LogKeyGUID, auth.Runtime.GUID,
			definitions.LogKeyMsg, "No accounts found in LDAP backend",
		)
	}

	return accounts, nil
}

// AddTOTPSecret adds a newly generated TOTP secret to an LDAP server.
func (lm *ldapManagerImpl) AddTOTPSecret(auth *AuthState, totp *mfa.TOTPSecret) (err error) {
	tr := monittrace.New("nauthilus/ldap")
	mctx, msp := tr.Start(auth.Ctx(), "ldap.add_totp",
		attribute.String("pool_name", lm.poolName),
		attribute.String("service", auth.Request.Service),
		attribute.String("protocol", auth.Request.Protocol.Get()),
	)

	_ = mctx

	defer msp.End()

	var (
		filter      string
		baseDN      string
		configField string
		ldapReply   *bktype.LDAPReply
		scope       *config.LDAPScope
		protocol    *config.LDAPSearchProtocol
		ldapError   *ldap.Error
	)

	resource := util.RequestResource(auth.Request.HTTPClientContext, auth.Request.HTTPClientRequest, lm.poolName)
	stopTimer := stats.PrometheusTimer(lm.effectiveCfg(), definitions.PromStoreTOTP, "ldap_store_totp_request_total", resource)

	if stopTimer != nil {
		defer stopTimer()
	}

	ldapReplyChan := make(chan *bktype.LDAPReply)

	pCtx, pSpan := tr.Start(mctx, "ldap.add_totp.prepare")
	_ = pCtx

	if protocol, err = lm.effectiveCfg().GetLDAPSearchProtocol(auth.Request.Protocol.Get(), lm.poolName); protocol == nil || err != nil {
		pSpan.End()

		return
	}

	if filter, err = protocol.GetUserFilter(); err != nil {
		pSpan.End()

		return
	}

	if baseDN, err = protocol.GetBaseDN(); err != nil {
		pSpan.End()

		return
	}

	if scope, err = protocol.GetScope(); err != nil {
		pSpan.End()

		return
	}

	msp.SetAttributes(
		attribute.String("base_dn", baseDN),
		attribute.String("scope", scope.String()),
	)

	configField = totp.GetLDAPTOTPSecret(protocol)
	if configField == "" {
		pSpan.End()

		err = errors.ErrLDAPConfig.WithDetail(
			fmt.Sprintf("Missing LDAP TOTP secret field; protocol=%s", auth.Request.Protocol.Get()))

		return
	}

	securityManager := security.NewManager(lm.effectiveCfg().GetLDAPConfigEncryptionSecret())
	encryptedSecret, encryptErr := securityManager.Encrypt(totp.GetValue())
	if encryptErr != nil {
		pSpan.End()

		return errors.ErrLDAPConfig.WithDetail(
			fmt.Sprintf("Failed to encrypt LDAP TOTP secret: %v", encryptErr))
	}

	// Derive a timeout context for LDAP modify using service-scoped context
	ctxModify, cancelModify := util.GetCtxWithDeadlineLDAPModify(lm.effectiveCfg())
	defer cancelModify()

	ldapRequest := &bktype.LDAPRequest{
		GUID:       auth.Runtime.GUID,
		Command:    definitions.LDAPModify,
		PoolName:   lm.poolName,
		SubCommand: definitions.LDAPModifyAdd,
		MacroSource: &util.MacroSource{
			Username:    auth.Request.Username,
			XLocalIP:    auth.Request.XLocalIP,
			XPort:       auth.Request.XPort,
			ClientIP:    auth.Request.ClientIP,
			XClientPort: auth.Request.XClientPort,
			TOTPSecret:  auth.Runtime.TOTPSecret,
			Protocol:    *auth.Request.Protocol,
		},
		Filter:            filter,
		BaseDN:            baseDN,
		Scope:             *scope,
		LDAPReplyChan:     ldapReplyChan,
		HTTPClientContext: ctxModify,
	}

	ldapRequest.ModifyAttributes = make(bktype.LDAPModifyAttributes, 2)
	ldapRequest.ModifyAttributes[configField] = []string{encryptedSecret}

	totpObjectClass := protocol.GetTotpObjectClass()
	if totpObjectClass != "" {
		ldapRequest.ModifyAttributes["objectClass"] = []string{totpObjectClass}
	}

	// Determine priority based on NoAuth flag and whether the user is already authenticated
	priority := priorityqueue.PriorityLow
	if !auth.Request.NoAuth {
		priority = priorityqueue.PriorityMedium
	}

	if localcache.AuthCache.IsAuthenticated(auth.Request.Username) {
		priority = priorityqueue.PriorityHigh
	}

	pSpan.End()

	// Use priority queue instead of channel
	priorityqueue.LDAPQueue.Push(ldapRequest, priority)

	_, wSpan := tr.Start(mctx, "ldap.add_totp.wait")
	ldapReply = <-ldapReplyChan
	wSpan.End()

	if stderrors.As(ldapReply.Err, &ldapError) {
		if ldapError.ResultCode == uint16(ldap.LDAPResultAttributeOrValueExists) && totpObjectClass != "" {
			return nil
		}

		msp.RecordError(ldapError)

		return ldapError.Err
	}

	if ldapReply.Err != nil {
		msp.RecordError(ldapReply.Err)
	}

	return ldapReply.Err
}

// DeleteTOTPSecret removes the TOTP secret from an LDAP server.
func (lm *ldapManagerImpl) DeleteTOTPSecret(auth *AuthState) (err error) {
	tr := monittrace.New("nauthilus/ldap")
	mctx, msp := tr.Start(auth.Ctx(), "ldap.delete_totp",
		attribute.String("pool_name", lm.poolName),
		attribute.String("service", auth.Request.Service),
		attribute.String("protocol", auth.Request.Protocol.Get()),
	)

	_ = mctx

	defer msp.End()

	var (
		filter      string
		baseDN      string
		configField string
		ldapReply   *bktype.LDAPReply
		scope       *config.LDAPScope
		protocol    *config.LDAPSearchProtocol
	)

	resource := util.RequestResource(auth.Request.HTTPClientContext, auth.Request.HTTPClientRequest, lm.poolName)
	stopTimer := stats.PrometheusTimer(lm.effectiveCfg(), definitions.PromDeleteTOTP, "ldap_delete_totp_request_total", resource)

	if stopTimer != nil {
		defer stopTimer()
	}

	ldapReplyChan := make(chan *bktype.LDAPReply)

	pCtx, pSpan := tr.Start(mctx, "ldap.delete_totp.prepare")
	_ = pCtx

	if protocol, err = lm.effectiveCfg().GetLDAPSearchProtocol(auth.Request.Protocol.Get(), lm.poolName); protocol == nil || err != nil {
		pSpan.End()

		return
	}

	if filter, err = protocol.GetUserFilter(); err != nil {
		pSpan.End()

		return
	}

	if baseDN, err = protocol.GetBaseDN(); err != nil {
		pSpan.End()

		return
	}

	if scope, err = protocol.GetScope(); err != nil {
		pSpan.End()

		return
	}

	msp.SetAttributes(
		attribute.String("base_dn", baseDN),
		attribute.String("scope", scope.String()),
	)

	configField = protocol.GetTotpSecretField()
	if configField == "" {
		pSpan.End()

		err = errors.ErrLDAPConfig.WithDetail(
			fmt.Sprintf("Missing LDAP TOTP secret field; protocol=%s", auth.Request.Protocol.Get()))

		return
	}

	// Derive a timeout context for LDAP modify using service-scoped context
	ctxModify, cancelModify := util.GetCtxWithDeadlineLDAPModify(lm.effectiveCfg())
	defer cancelModify()

	ldapRequest := &bktype.LDAPRequest{
		GUID:       auth.Runtime.GUID,
		Command:    definitions.LDAPModify,
		PoolName:   lm.poolName,
		SubCommand: definitions.LDAPModifyDelete,
		MacroSource: &util.MacroSource{
			Username:    auth.Request.Username,
			XLocalIP:    auth.Request.XLocalIP,
			XPort:       auth.Request.XPort,
			ClientIP:    auth.Request.ClientIP,
			XClientPort: auth.Request.XClientPort,
			Protocol:    *auth.Request.Protocol,
		},
		Filter:            filter,
		BaseDN:            baseDN,
		Scope:             *scope,
		LDAPReplyChan:     ldapReplyChan,
		HTTPClientContext: ctxModify,
	}

	ldapRequest.ModifyAttributes = make(bktype.LDAPModifyAttributes, 1)
	ldapRequest.ModifyAttributes[configField] = []string{}

	// Determine priority based on NoAuth flag and whether the user is already authenticated
	priority := priorityqueue.PriorityLow
	if !auth.Request.NoAuth {
		priority = priorityqueue.PriorityMedium
	}
	if localcache.AuthCache.IsAuthenticated(auth.Request.Username) {
		priority = priorityqueue.PriorityHigh
	}

	pSpan.End()

	// Use priority queue instead of channel
	priorityqueue.LDAPQueue.Push(ldapRequest, priority)

	_, wSpan := tr.Start(mctx, "ldap.delete_totp.wait")
	ldapReply = <-ldapReplyChan
	wSpan.End()

	if isNoSuchAttributeError(ldapReply.Err) {
		return nil
	}

	if ldapReply.Err != nil {
		msp.RecordError(ldapReply.Err)
	}

	return ldapReply.Err
}

// AddTOTPRecoveryCodes adds the specified TOTP recovery codes to the user's authentication state in the LDAP backend.
func (lm *ldapManagerImpl) AddTOTPRecoveryCodes(auth *AuthState, recovery *mfa.TOTPRecovery) (err error) {
	tr := monittrace.New("nauthilus/ldap")
	mctx, msp := tr.Start(auth.Ctx(), "ldap.add_totp_recovery",
		attribute.String("pool_name", lm.poolName),
		attribute.String("service", auth.Request.Service),
		attribute.String("protocol", auth.Request.Protocol.Get()),
	)

	_ = mctx

	defer msp.End()

	var (
		filter      string
		baseDN      string
		configField string
		ldapReply   *bktype.LDAPReply
		scope       *config.LDAPScope
		protocol    *config.LDAPSearchProtocol
	)

	resource := util.RequestResource(auth.Request.HTTPClientContext, auth.Request.HTTPClientRequest, lm.poolName)
	stopTimer := stats.PrometheusTimer(lm.effectiveCfg(), definitions.PromStoreTOTPRecovery, "ldap_store_totp_recovery_request_total", resource)

	if stopTimer != nil {
		defer stopTimer()
	}

	ldapReplyChan := make(chan *bktype.LDAPReply)

	pCtx, pSpan := tr.Start(mctx, "ldap.add_totp_recovery.prepare")
	_ = pCtx

	if protocol, err = lm.effectiveCfg().GetLDAPSearchProtocol(auth.Request.Protocol.Get(), lm.poolName); protocol == nil || err != nil {
		pSpan.End()

		return
	}

	if filter, err = protocol.GetUserFilter(); err != nil {
		pSpan.End()

		return
	}

	if baseDN, err = protocol.GetBaseDN(); err != nil {
		pSpan.End()

		return
	}

	if scope, err = protocol.GetScope(); err != nil {
		pSpan.End()

		return
	}

	msp.SetAttributes(
		attribute.String("base_dn", baseDN),
		attribute.String("scope", scope.String()),
	)

	configField = recovery.GetLDAPRecoveryField(protocol)
	if configField == "" {
		pSpan.End()

		err = errors.ErrLDAPConfig.WithDetail(
			fmt.Sprintf("Missing LDAP TOTP recovery field; protocol=%s", auth.Request.Protocol.Get()))

		return
	}

	securityManager := security.NewManager(lm.effectiveCfg().GetLDAPConfigEncryptionSecret())
	codes := recovery.GetCodes()
	encryptedCodes := make([]string, len(codes))
	for index, code := range codes {
		encryptedCode, encryptErr := securityManager.Encrypt(code)
		if encryptErr != nil {
			pSpan.End()

			return errors.ErrLDAPConfig.WithDetail(
				fmt.Sprintf("Failed to encrypt LDAP TOTP recovery code: %v", encryptErr))
		}

		encryptedCodes[index] = encryptedCode
	}

	// Derive a timeout context for LDAP modify using service-scoped context
	ctxModify, cancelModify := util.GetCtxWithDeadlineLDAPModify(lm.effectiveCfg())
	defer cancelModify()

	ldapRequest := &bktype.LDAPRequest{
		GUID:       auth.Runtime.GUID,
		Command:    definitions.LDAPModify,
		PoolName:   lm.poolName,
		SubCommand: definitions.LDAPModifyReplace,
		MacroSource: &util.MacroSource{
			Username:    auth.Request.Username,
			XLocalIP:    auth.Request.XLocalIP,
			XPort:       auth.Request.XPort,
			ClientIP:    auth.Request.ClientIP,
			XClientPort: auth.Request.XClientPort,
			Protocol:    *auth.Request.Protocol,
		},
		Filter:            filter,
		BaseDN:            baseDN,
		Scope:             *scope,
		LDAPReplyChan:     ldapReplyChan,
		HTTPClientContext: ctxModify,
	}

	ldapRequest.ModifyAttributes = make(bktype.LDAPModifyAttributes, 1)
	ldapRequest.ModifyAttributes[configField] = encryptedCodes

	totpRecoveryObjectClass := protocol.GetTotpRecoveryObjectClass()

	// Determine priority based on NoAuth flag and whether the user is already authenticated
	priority := priorityqueue.PriorityLow
	if !auth.Request.NoAuth {
		priority = priorityqueue.PriorityMedium
	}

	if localcache.AuthCache.IsAuthenticated(auth.Request.Username) {
		priority = priorityqueue.PriorityHigh
	}

	if totpRecoveryObjectClass != "" {
		objectClassReplyChan := make(chan *bktype.LDAPReply, 1)
		ctxAddObjectClass, cancelAddObjectClass := util.GetCtxWithDeadlineLDAPModify(lm.effectiveCfg())
		defer cancelAddObjectClass()

		objectClassRequest := &bktype.LDAPRequest{
			GUID:       auth.Runtime.GUID,
			Command:    definitions.LDAPModify,
			PoolName:   lm.poolName,
			SubCommand: definitions.LDAPModifyAdd,
			MacroSource: &util.MacroSource{
				Username:    auth.Request.Username,
				XLocalIP:    auth.Request.XLocalIP,
				XPort:       auth.Request.XPort,
				ClientIP:    auth.Request.ClientIP,
				XClientPort: auth.Request.XClientPort,
				Protocol:    *auth.Request.Protocol,
			},
			Filter: filter,
			BaseDN: baseDN,
			Scope:  *scope,
			ModifyAttributes: bktype.LDAPModifyAttributes{
				"objectClass": []string{totpRecoveryObjectClass},
			},
			LDAPReplyChan:     objectClassReplyChan,
			HTTPClientContext: ctxAddObjectClass,
		}

		priorityqueue.LDAPQueue.Push(objectClassRequest, priority)
		objectClassReply := <-objectClassReplyChan
		if objectClassReply.Err != nil && !isAttributeOrValueExistsError(objectClassReply.Err) {
			msp.RecordError(objectClassReply.Err)

			return objectClassReply.Err
		}
	}

	pSpan.End()

	// Use priority queue instead of channel
	priorityqueue.LDAPQueue.Push(ldapRequest, priority)

	_, wSpan := tr.Start(mctx, "ldap.add_totp_recovery.wait")
	ldapReply = <-ldapReplyChan
	wSpan.End()

	if ldapReply.Err != nil {
		msp.RecordError(ldapReply.Err)
	}

	return ldapReply.Err
}

// DeleteTOTPRecoveryCodes removes all TOTP recovery codes for the user in the LDAP backend.
func (lm *ldapManagerImpl) DeleteTOTPRecoveryCodes(auth *AuthState) (err error) {
	tr := monittrace.New("nauthilus/ldap")
	mctx, msp := tr.Start(auth.Ctx(), "ldap.delete_totp_recovery",
		attribute.String("pool_name", lm.poolName),
		attribute.String("service", auth.Request.Service),
		attribute.String("protocol", auth.Request.Protocol.Get()),
	)

	_ = mctx

	defer msp.End()

	var (
		filter      string
		baseDN      string
		configField string
		ldapReply   *bktype.LDAPReply
		scope       *config.LDAPScope
		protocol    *config.LDAPSearchProtocol
	)

	resource := util.RequestResource(auth.Request.HTTPClientContext, auth.Request.HTTPClientRequest, lm.poolName)
	stopTimer := stats.PrometheusTimer(lm.effectiveCfg(), definitions.PromDeleteTOTPRecovery, "ldap_delete_totp_recovery_request_total", resource)

	if stopTimer != nil {
		defer stopTimer()
	}

	ldapReplyChan := make(chan *bktype.LDAPReply)

	pCtx, pSpan := tr.Start(mctx, "ldap.delete_totp_recovery.prepare")
	_ = pCtx

	if protocol, err = lm.effectiveCfg().GetLDAPSearchProtocol(auth.Request.Protocol.Get(), lm.poolName); protocol == nil || err != nil {
		pSpan.End()

		return
	}

	if filter, err = protocol.GetUserFilter(); err != nil {
		pSpan.End()

		return
	}

	if baseDN, err = protocol.GetBaseDN(); err != nil {
		pSpan.End()

		return
	}

	if scope, err = protocol.GetScope(); err != nil {
		pSpan.End()

		return
	}

	msp.SetAttributes(
		attribute.String("base_dn", baseDN),
		attribute.String("scope", scope.String()),
	)

	configField = protocol.GetTotpRecoveryField()
	if configField == "" {
		pSpan.End()

		err = errors.ErrLDAPConfig.WithDetail(
			fmt.Sprintf("Missing LDAP TOTP recovery field; protocol=%s", auth.Request.Protocol.Get()))

		return
	}

	// Derive a timeout context for LDAP modify using service-scoped context
	ctxModify, cancelModify := util.GetCtxWithDeadlineLDAPModify(lm.effectiveCfg())
	defer cancelModify()

	ldapRequest := &bktype.LDAPRequest{
		GUID:       auth.Runtime.GUID,
		Command:    definitions.LDAPModify,
		PoolName:   lm.poolName,
		SubCommand: definitions.LDAPModifyDelete,
		MacroSource: &util.MacroSource{
			Username:    auth.Request.Username,
			XLocalIP:    auth.Request.XLocalIP,
			XPort:       auth.Request.XPort,
			ClientIP:    auth.Request.ClientIP,
			XClientPort: auth.Request.XClientPort,
			Protocol:    *auth.Request.Protocol,
		},
		Filter:            filter,
		BaseDN:            baseDN,
		Scope:             *scope,
		LDAPReplyChan:     ldapReplyChan,
		HTTPClientContext: ctxModify,
	}

	ldapRequest.ModifyAttributes = make(bktype.LDAPModifyAttributes, 1)
	ldapRequest.ModifyAttributes[configField] = []string{}

	// Determine priority based on NoAuth flag and whether the user is already authenticated
	priority := priorityqueue.PriorityLow
	if !auth.Request.NoAuth {
		priority = priorityqueue.PriorityMedium
	}

	if localcache.AuthCache.IsAuthenticated(auth.Request.Username) {
		priority = priorityqueue.PriorityHigh
	}

	pSpan.End()

	// Use priority queue instead of channel
	priorityqueue.LDAPQueue.Push(ldapRequest, priority)

	_, wSpan := tr.Start(mctx, "ldap.delete_totp_recovery.wait")
	ldapReply = <-ldapReplyChan
	wSpan.End()

	if isNoSuchAttributeError(ldapReply.Err) {
		return nil
	}

	if ldapReply.Err != nil {
		msp.RecordError(ldapReply.Err)
	}

	return ldapReply.Err
}

// isNoSuchAttributeError checks if the error is an LDAP "No Such Attribute" error.
func isNoSuchAttributeError(err error) bool {
	if err == nil {
		return false
	}

	var ldapErr *ldap.Error
	if stderrors.As(err, &ldapErr) {
		return ldapErr.ResultCode == ldap.LDAPResultNoSuchAttribute
	}

	return false
}

func isAttributeOrValueExistsError(err error) bool {
	if err == nil {
		return false
	}

	var ldapErr *ldap.Error
	if stderrors.As(err, &ldapErr) {
		return ldapErr.ResultCode == ldap.LDAPResultAttributeOrValueExists
	}

	return false
}

var _ BackendManager = (*ldapManagerImpl)(nil)

// NewLDAPManager creates and returns a BackendManager for managing LDAP authentication backends using the specified pool name.
func NewLDAPManager(poolName string, deps AuthDeps) BackendManager {
	if poolName == "" {
		poolName = definitions.DefaultBackendName
	}

	return &ldapManagerImpl{
		poolName: poolName,
		deps:     deps,
	}
}
