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

	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/backend/priorityqueue"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/localcache"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/model/mfa"
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

// ldapQueue returns the configured LDAP request queue, falling back to the global queue.
func (lm *ldapManagerImpl) ldapQueue() LDAPRequestQueue {
	if lm.deps.LDAPQueue != nil {
		return lm.deps.LDAPQueue
	}

	return priorityqueue.LDAPQueue
}

// ldapAuthQueue returns the configured LDAP auth request queue, falling back to the global queue.
func (lm *ldapManagerImpl) ldapAuthQueue() LDAPAuthRequestQueue {
	if lm.deps.LDAPAuthQueue != nil {
		return lm.deps.LDAPAuthQueue
	}

	return priorityqueue.LDAPAuthQueue
}

// spanEnder closes a tracing span.
type spanEnder func()

// ldapSearchConfigOptions controls how LDAP search configuration is loaded.
type ldapSearchConfigOptions struct {
	requireProtocol       bool
	missingProtocolDetail string
	filterGetter          func(*config.LDAPSearchProtocol) (string, error)
	ignoreFilterError     bool
	includeAccountField   bool
	includeAttributes     bool
}

// ldapSearchConfig bundles resolved LDAP search settings.
type ldapSearchConfig struct {
	protocol     *config.LDAPSearchProtocol
	filter       string
	baseDN       string
	scope        *config.LDAPScope
	attributes   []string
	accountField string
}

// ldapModifyRequestInput collects fields required to build an LDAP modify request.
type ldapModifyRequestInput struct {
	auth              *AuthState
	filter            string
	baseDN            string
	scope             *config.LDAPScope
	subCommand        definitions.LDAPSubCommand
	ctx               context.Context
	replyChan         chan *bktype.LDAPReply
	includeTOTPSecret bool
}

// loadSearchConfig resolves LDAP search settings with optional protocol and attribute handling.
func (lm *ldapManagerImpl) loadSearchConfig(endSpan spanEnder, protocolName string, opts ldapSearchConfigOptions) (ldapSearchConfig, error) {
	var cfg ldapSearchConfig

	protocol, err := lm.effectiveCfg().GetLDAPSearchProtocol(protocolName, lm.poolName)
	if err != nil || protocol == nil {
		if err == nil && opts.requireProtocol {
			err = errors.ErrLDAPConfig.WithDetail(fmt.Sprintf(opts.missingProtocolDetail, protocolName))
		}

		if endSpan != nil {
			endSpan()
		}

		return cfg, err
	}

	cfg.protocol = protocol

	if opts.filterGetter != nil {
		filter, err := opts.filterGetter(protocol)
		if err != nil {
			if endSpan != nil {
				endSpan()
			}

			if opts.ignoreFilterError {
				return ldapSearchConfig{}, nil
			}

			return cfg, err
		}

		cfg.filter = filter
	}

	if opts.includeAccountField {
		accountField, err := protocol.GetAccountField()
		if err != nil {
			if endSpan != nil {
				endSpan()
			}

			return cfg, err
		}

		cfg.accountField = accountField
	}

	if opts.includeAttributes {
		attributes, err := protocol.GetAttributes()
		if err != nil {
			if endSpan != nil {
				endSpan()
			}

			return cfg, err
		}

		cfg.attributes = attributes
	}

	baseDN, err := protocol.GetBaseDN()
	if err != nil {
		if endSpan != nil {
			endSpan()
		}

		return cfg, err
	}

	cfg.baseDN = baseDN

	scope, err := protocol.GetScope()
	if err != nil {
		if endSpan != nil {
			endSpan()
		}

		return cfg, err
	}

	cfg.scope = scope

	return cfg, nil
}

// requestPriority derives a queue priority based on authentication state and cache hits.
func (lm *ldapManagerImpl) requestPriority(auth *AuthState) int {
	priority := priorityqueue.PriorityLow
	if !auth.Request.NoAuth {
		priority = priorityqueue.PriorityMedium
	}

	if localcache.AuthCache.IsAuthenticated(auth.Request.Username) {
		priority = priorityqueue.PriorityHigh
	}

	return priority
}

// ldapModifyContext creates a timeout context for LDAP modify operations.
func (lm *ldapManagerImpl) ldapModifyContext() (context.Context, context.CancelFunc) {
	return util.GetCtxWithDeadlineLDAPModify(lm.effectiveCfg())
}

// newMacroSource builds a macro source from the authentication request.
func (lm *ldapManagerImpl) newMacroSource(auth *AuthState, includeTOTPSecret bool) *util.MacroSource {
	macro := &util.MacroSource{
		Username:    auth.Request.Username,
		XLocalIP:    auth.Request.XLocalIP,
		XPort:       auth.Request.XPort,
		ClientIP:    auth.Request.ClientIP,
		XClientPort: auth.Request.XClientPort,
		Protocol:    *auth.Request.Protocol,
	}

	if includeTOTPSecret {
		macro.TOTPSecret = auth.Runtime.TOTPSecret
	}

	return macro
}

// newLDAPModifyRequest constructs an LDAP modify request from the provided input.
func (lm *ldapManagerImpl) newLDAPModifyRequest(input ldapModifyRequestInput) *bktype.LDAPRequest {
	return &bktype.LDAPRequest{
		GUID:              input.auth.Runtime.GUID,
		Command:           definitions.LDAPModify,
		PoolName:          lm.poolName,
		SubCommand:        input.subCommand,
		MacroSource:       lm.newMacroSource(input.auth, input.includeTOTPSecret),
		Filter:            input.filter,
		BaseDN:            input.baseDN,
		Scope:             *input.scope,
		LDAPReplyChan:     input.replyChan,
		HTTPClientContext: input.ctx,
	}
}

// startSpan starts a tracing span and returns a closure to end it.
func startSpan(tr monittrace.Tracer, ctx context.Context, name string) (context.Context, spanEnder) {
	ctx, span := tr.Start(ctx, name)

	return ctx, func() { span.End() }
}

// waitLDAPReply waits for a reply and wraps the wait with a tracing span.
func waitLDAPReply(tr monittrace.Tracer, ctx context.Context, name string, replyChan <-chan *bktype.LDAPReply) *bktype.LDAPReply {
	_, endSpan := startSpan(tr, ctx, name)
	reply := <-replyChan
	endSpan()

	return reply
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

	if len(totpSecretPre) != 0 {
		// Use the TOTP secret from a master user if it exists.
		passDBResult.Attributes[totpSecretField] = totpSecretPre
	} else {
		// Ignore the user TOTP secret if it exists.
		delete(passDBResult.Attributes, totpSecretField)
	}
}

// decryptLDAPAttributeValues decrypts and normalizes a specific LDAP attribute in-place.
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

// decryptLDAPAttributeValue decrypts a single LDAP attribute value, preserving its shape.
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

// normalizeLDAPAttributeValues converts LDAP attribute values to a uniform []any representation.
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

// effectiveCfg returns the configured file accessor.
func (lm *ldapManagerImpl) effectiveCfg() config.File {
	return lm.deps.Cfg
}

// effectiveLogger returns the configured logger.
func (lm *ldapManagerImpl) effectiveLogger() *slog.Logger {
	return lm.deps.Logger
}

// PassDB implements the LDAP password database backend.
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
		searchConfig       ldapSearchConfig
	)

	resource := util.RequestResource(auth.Request.HTTPClientContext, auth.Request.HTTPClientRequest, lm.poolName)
	stopTimer := stats.PrometheusTimer(lm.effectiveCfg(), definitions.PromBackend, "ldap_passdb_request_total", resource)

	if stopTimer != nil {
		defer stopTimer()
	}

	passDBResult = GetPassDBResultFromPool()

	ldapReplyChan := make(chan *bktype.LDAPReply, 1)

	_, endPrepare := startSpan(tr, lctx, "ldap.passdb.search.prepare")

	searchConfig, err = lm.loadSearchConfig(endPrepare, auth.Request.Protocol.Get(), ldapSearchConfigOptions{
		requireProtocol:       true,
		missingProtocolDetail: "Missing LDAP search protocol; protocol=%s",
		filterGetter:          (*config.LDAPSearchProtocol).GetUserFilter,
		includeAccountField:   true,
		includeAttributes:     true,
	})
	if err != nil {
		return
	}

	if searchConfig.protocol == nil {
		return
	}

	protocol = searchConfig.protocol
	accountField = searchConfig.accountField
	attributes = searchConfig.attributes
	filter = searchConfig.filter
	baseDN = searchConfig.baseDN
	scope = searchConfig.scope

	username := auth.handleMasterUserMode()

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
	priority := lm.requestPriority(auth)

	endPrepare()

	// Use priority queue instead of channel
	lm.ldapQueue().Push(ldapRequest, priority)

	ldapReply = waitLDAPReply(tr, lctx, "ldap.passdb.search.wait", ldapReplyChan)

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

		_, endAuthPrepare := startSpan(tr, lctx, "ldap.passdb.auth.prepare")

		// Derive a timeout context for LDAP bind/auth
		dBind := lm.effectiveCfg().GetServer().GetTimeouts().GetLDAPBind()
		ctxBind, cancelBind := context.WithTimeout(auth.Ctx(), dBind)
		defer cancelBind()

		var bindPassword string
		auth.Request.Password.WithString(func(value string) {
			bindPassword = value
		})

		ldapUserBindRequest := &bktype.LDAPAuthRequest{
			GUID:              auth.Runtime.GUID,
			PoolName:          lm.poolName,
			BindDN:            dn,
			BindPW:            bindPassword,
			LDAPReplyChan:     ldapReplyChan,
			HTTPClientContext: ctxBind,
		}

		// Determine priority based on NoAuth flag and whether the user is already authenticated
		priority = lm.requestPriority(auth)

		endAuthPrepare()

		// Use priority queue instead of channel
		lm.ldapAuthQueue().Push(ldapUserBindRequest, priority)

		ldapReply = waitLDAPReply(tr, lctx, "ldap.passdb.auth.wait", ldapReplyChan)

		if ldapReply.Err != nil {
			util.DebugModuleWithCfg(
				auth.Ctx(),
				lm.effectiveCfg(),
				lm.effectiveLogger(),
				definitions.DbgLDAP,
				definitions.LogKeyGUID, auth.Runtime.GUID,
				definitions.LogKeyMsg, err,
			)

			if ldapError, ok := stderrors.AsType[*ldap.Error](err); ok {
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
		searchConfig ldapSearchConfig
	)

	resource := util.RequestResource(auth.Request.HTTPClientContext, auth.Request.HTTPClientRequest, lm.poolName)
	stopTimer := stats.PrometheusTimer(lm.effectiveCfg(), definitions.PromAccount, "ldap_account_request_total", resource)

	if stopTimer != nil {
		defer stopTimer()
	}

	ldapReplyChan := make(chan *bktype.LDAPReply, 1)

	_, endPrepare := startSpan(tr, actx, "ldap.accountdb.prepare")

	searchConfig, err = lm.loadSearchConfig(endPrepare, auth.Request.Protocol.Get(), ldapSearchConfigOptions{
		filterGetter:        (*config.LDAPSearchProtocol).GetListAccountsFilter,
		ignoreFilterError:   true,
		includeAccountField: true,
		includeAttributes:   true,
	})

	if err != nil || searchConfig.protocol == nil {
		return
	}

	accountField = searchConfig.accountField
	attributes = searchConfig.attributes
	filter = searchConfig.filter
	baseDN = searchConfig.baseDN
	scope = searchConfig.scope

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

	endPrepare()

	lm.ldapQueue().Push(ldapRequest, priorityqueue.PriorityMedium)

	ldapReply = waitLDAPReply(tr, actx, "ldap.accountdb.wait", ldapReplyChan)

	if ldapReply.Err != nil {
		if ldapError, ok := stderrors.AsType[*ldap.Error](err); ok {
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
		filter       string
		baseDN       string
		configField  string
		ldapReply    *bktype.LDAPReply
		scope        *config.LDAPScope
		protocol     *config.LDAPSearchProtocol
		searchConfig ldapSearchConfig
	)

	resource := util.RequestResource(auth.Request.HTTPClientContext, auth.Request.HTTPClientRequest, lm.poolName)
	stopTimer := stats.PrometheusTimer(lm.effectiveCfg(), definitions.PromStoreTOTP, "ldap_store_totp_request_total", resource)

	if stopTimer != nil {
		defer stopTimer()
	}

	ldapReplyChan := make(chan *bktype.LDAPReply)

	_, endPrepare := startSpan(tr, mctx, "ldap.add_totp.prepare")

	searchConfig, err = lm.loadSearchConfig(endPrepare, auth.Request.Protocol.Get(), ldapSearchConfigOptions{
		filterGetter: (*config.LDAPSearchProtocol).GetUserFilter,
	})
	if err != nil || searchConfig.protocol == nil {
		return
	}

	protocol = searchConfig.protocol
	filter = searchConfig.filter
	baseDN = searchConfig.baseDN
	scope = searchConfig.scope

	msp.SetAttributes(
		attribute.String("base_dn", baseDN),
		attribute.String("scope", scope.String()),
	)

	configField = totp.GetLDAPTOTPSecret(protocol)
	if configField == "" {
		endPrepare()

		err = errors.ErrLDAPConfig.WithDetail(
			fmt.Sprintf("Missing LDAP TOTP secret field; protocol=%s", auth.Request.Protocol.Get()))

		return
	}

	securityManager := security.NewManager(lm.effectiveCfg().GetLDAPConfigEncryptionSecret())
	encryptedSecret, encryptErr := securityManager.Encrypt(totp.GetValue())
	if encryptErr != nil {
		endPrepare()

		return errors.ErrLDAPConfig.WithDetail(
			fmt.Sprintf("Failed to encrypt LDAP TOTP secret: %v", encryptErr))
	}

	// Derive a timeout context for LDAP modify using service-scoped context
	ctxModify, cancelModify := lm.ldapModifyContext()
	defer cancelModify()

	ldapRequest := lm.newLDAPModifyRequest(ldapModifyRequestInput{
		auth:              auth,
		filter:            filter,
		baseDN:            baseDN,
		scope:             scope,
		subCommand:        definitions.LDAPModifyAdd,
		ctx:               ctxModify,
		replyChan:         ldapReplyChan,
		includeTOTPSecret: true,
	})

	ldapRequest.ModifyAttributes = make(bktype.LDAPModifyAttributes, 2)
	ldapRequest.ModifyAttributes[configField] = []string{encryptedSecret}

	totpObjectClass := protocol.GetTotpObjectClass()
	if totpObjectClass != "" {
		ldapRequest.ModifyAttributes["objectClass"] = []string{totpObjectClass}
	}

	// Determine priority based on NoAuth flag and whether the user is already authenticated
	priority := lm.requestPriority(auth)

	endPrepare()

	// Use priority queue instead of channel
	lm.ldapQueue().Push(ldapRequest, priority)

	ldapReply = waitLDAPReply(tr, mctx, "ldap.add_totp.wait", ldapReplyChan)

	if ldapError, ok := stderrors.AsType[*ldap.Error](ldapReply.Err); ok {
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

// deleteLDAPFieldParams holds the per-operation parameters for deleteLDAPField.
type deleteLDAPFieldParams struct {
	spanName      string
	promLabel     string
	promMetric    string
	prepareSpan   string
	waitSpan      string
	fieldGetter   func(*config.LDAPSearchProtocol) string
	missingDetail string
}

// deleteLDAPField is the shared implementation for deleting a single LDAP attribute (TOTP secret, recovery codes, etc.).
func (lm *ldapManagerImpl) deleteLDAPField(auth *AuthState, params deleteLDAPFieldParams) (err error) {
	tr := monittrace.New("nauthilus/ldap")
	mctx, msp := tr.Start(auth.Ctx(), params.spanName,
		attribute.String("pool_name", lm.poolName),
		attribute.String("service", auth.Request.Service),
		attribute.String("protocol", auth.Request.Protocol.Get()),
	)

	_ = mctx

	defer msp.End()

	var (
		filter       string
		baseDN       string
		configField  string
		ldapReply    *bktype.LDAPReply
		scope        *config.LDAPScope
		protocol     *config.LDAPSearchProtocol
		searchConfig ldapSearchConfig
	)

	resource := util.RequestResource(auth.Request.HTTPClientContext, auth.Request.HTTPClientRequest, lm.poolName)
	stopTimer := stats.PrometheusTimer(lm.effectiveCfg(), params.promLabel, params.promMetric, resource)

	if stopTimer != nil {
		defer stopTimer()
	}

	ldapReplyChan := make(chan *bktype.LDAPReply)

	_, endPrepare := startSpan(tr, mctx, params.prepareSpan)

	searchConfig, err = lm.loadSearchConfig(endPrepare, auth.Request.Protocol.Get(), ldapSearchConfigOptions{
		filterGetter: (*config.LDAPSearchProtocol).GetUserFilter,
	})
	if err != nil || searchConfig.protocol == nil {
		return
	}

	protocol = searchConfig.protocol
	filter = searchConfig.filter
	baseDN = searchConfig.baseDN
	scope = searchConfig.scope

	msp.SetAttributes(
		attribute.String("base_dn", baseDN),
		attribute.String("scope", scope.String()),
	)

	configField = params.fieldGetter(protocol)
	if configField == "" {
		endPrepare()

		err = errors.ErrLDAPConfig.WithDetail(
			fmt.Sprintf("%s; protocol=%s", params.missingDetail, auth.Request.Protocol.Get()))

		return
	}

	// Derive a timeout context for LDAP modify using service-scoped context
	ctxModify, cancelModify := lm.ldapModifyContext()
	defer cancelModify()

	ldapRequest := lm.newLDAPModifyRequest(ldapModifyRequestInput{
		auth:       auth,
		filter:     filter,
		baseDN:     baseDN,
		scope:      scope,
		subCommand: definitions.LDAPModifyDelete,
		ctx:        ctxModify,
		replyChan:  ldapReplyChan,
	})

	ldapRequest.ModifyAttributes = make(bktype.LDAPModifyAttributes, 1)
	ldapRequest.ModifyAttributes[configField] = []string{}

	// Determine priority based on NoAuth flag and whether the user is already authenticated
	priority := lm.requestPriority(auth)

	endPrepare()

	// Use priority queue instead of channel
	lm.ldapQueue().Push(ldapRequest, priority)

	ldapReply = waitLDAPReply(tr, mctx, params.waitSpan, ldapReplyChan)

	if isNoSuchAttributeError(ldapReply.Err) {
		return nil
	}

	if ldapReply.Err != nil {
		msp.RecordError(ldapReply.Err)
	}

	return ldapReply.Err
}

// DeleteTOTPSecret removes the TOTP secret from an LDAP server.
func (lm *ldapManagerImpl) DeleteTOTPSecret(auth *AuthState) (err error) {
	return lm.deleteLDAPField(auth, deleteLDAPFieldParams{
		spanName:      "ldap.delete_totp",
		promLabel:     definitions.PromDeleteTOTP,
		promMetric:    "ldap_delete_totp_request_total",
		prepareSpan:   "ldap.delete_totp.prepare",
		waitSpan:      "ldap.delete_totp.wait",
		fieldGetter:   (*config.LDAPSearchProtocol).GetTotpSecretField,
		missingDetail: "Missing LDAP TOTP secret field",
	})
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
		filter       string
		baseDN       string
		configField  string
		ldapReply    *bktype.LDAPReply
		scope        *config.LDAPScope
		protocol     *config.LDAPSearchProtocol
		searchConfig ldapSearchConfig
	)

	resource := util.RequestResource(auth.Request.HTTPClientContext, auth.Request.HTTPClientRequest, lm.poolName)
	stopTimer := stats.PrometheusTimer(lm.effectiveCfg(), definitions.PromStoreTOTPRecovery, "ldap_store_totp_recovery_request_total", resource)

	if stopTimer != nil {
		defer stopTimer()
	}

	ldapReplyChan := make(chan *bktype.LDAPReply)

	_, endPrepare := startSpan(tr, mctx, "ldap.add_totp_recovery.prepare")

	searchConfig, err = lm.loadSearchConfig(endPrepare, auth.Request.Protocol.Get(), ldapSearchConfigOptions{
		filterGetter: (*config.LDAPSearchProtocol).GetUserFilter,
	})
	if err != nil || searchConfig.protocol == nil {
		return
	}

	protocol = searchConfig.protocol
	filter = searchConfig.filter
	baseDN = searchConfig.baseDN
	scope = searchConfig.scope

	msp.SetAttributes(
		attribute.String("base_dn", baseDN),
		attribute.String("scope", scope.String()),
	)

	configField = recovery.GetLDAPRecoveryField(protocol)
	if configField == "" {
		endPrepare()

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
			endPrepare()

			return errors.ErrLDAPConfig.WithDetail(
				fmt.Sprintf("Failed to encrypt LDAP TOTP recovery code: %v", encryptErr))
		}

		encryptedCodes[index] = encryptedCode
	}

	// Derive a timeout context for LDAP modify using service-scoped context
	ctxModify, cancelModify := lm.ldapModifyContext()
	defer cancelModify()

	ldapRequest := lm.newLDAPModifyRequest(ldapModifyRequestInput{
		auth:       auth,
		filter:     filter,
		baseDN:     baseDN,
		scope:      scope,
		subCommand: definitions.LDAPModifyReplace,
		ctx:        ctxModify,
		replyChan:  ldapReplyChan,
	})

	ldapRequest.ModifyAttributes = make(bktype.LDAPModifyAttributes, 1)
	ldapRequest.ModifyAttributes[configField] = encryptedCodes

	totpRecoveryObjectClass := protocol.GetTotpRecoveryObjectClass()

	// Determine priority based on NoAuth flag and whether the user is already authenticated
	priority := lm.requestPriority(auth)

	if totpRecoveryObjectClass != "" {
		objectClassReplyChan := make(chan *bktype.LDAPReply, 1)
		ctxAddObjectClass, cancelAddObjectClass := lm.ldapModifyContext()
		defer cancelAddObjectClass()

		objectClassRequest := lm.newLDAPModifyRequest(ldapModifyRequestInput{
			auth:       auth,
			filter:     filter,
			baseDN:     baseDN,
			scope:      scope,
			subCommand: definitions.LDAPModifyAdd,
			ctx:        ctxAddObjectClass,
			replyChan:  objectClassReplyChan,
		})
		objectClassRequest.ModifyAttributes = bktype.LDAPModifyAttributes{
			"objectClass": []string{totpRecoveryObjectClass},
		}

		lm.ldapQueue().Push(objectClassRequest, priority)
		objectClassReply := <-objectClassReplyChan
		if objectClassReply.Err != nil && !isAttributeOrValueExistsError(objectClassReply.Err) {
			msp.RecordError(objectClassReply.Err)

			return objectClassReply.Err
		}
	}

	endPrepare()

	// Use priority queue instead of channel
	lm.ldapQueue().Push(ldapRequest, priority)

	ldapReply = waitLDAPReply(tr, mctx, "ldap.add_totp_recovery.wait", ldapReplyChan)

	if ldapReply.Err != nil {
		msp.RecordError(ldapReply.Err)
	}

	return ldapReply.Err
}

// DeleteTOTPRecoveryCodes removes all TOTP recovery codes for the user in the LDAP backend.
func (lm *ldapManagerImpl) DeleteTOTPRecoveryCodes(auth *AuthState) (err error) {
	return lm.deleteLDAPField(auth, deleteLDAPFieldParams{
		spanName:      "ldap.delete_totp_recovery",
		promLabel:     definitions.PromDeleteTOTPRecovery,
		promMetric:    "ldap_delete_totp_recovery_request_total",
		prepareSpan:   "ldap.delete_totp_recovery.prepare",
		waitSpan:      "ldap.delete_totp_recovery.wait",
		fieldGetter:   (*config.LDAPSearchProtocol).GetTotpRecoveryField,
		missingDetail: "Missing LDAP TOTP recovery field",
	})
}

// isNoSuchAttributeError checks if the error is an LDAP "No Such Attribute" error.
func isNoSuchAttributeError(err error) bool {
	if err == nil {
		return false
	}

	if ldapErr, ok := stderrors.AsType[*ldap.Error](err); ok {
		return ldapErr.ResultCode == ldap.LDAPResultNoSuchAttribute
	}

	return false
}

// isAttributeOrValueExistsError checks if the error is an LDAP "Attribute Or Value Exists" error.
func isAttributeOrValueExistsError(err error) bool {
	if err == nil {
		return false
	}

	if ldapErr, ok := stderrors.AsType[*ldap.Error](err); ok {
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
