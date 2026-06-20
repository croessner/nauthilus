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

	"github.com/croessner/nauthilus/v3/server/backend/bktype"
	"github.com/croessner/nauthilus/v3/server/backend/priorityqueue"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/errors"
	"github.com/croessner/nauthilus/v3/server/localcache"
	"github.com/croessner/nauthilus/v3/server/log/level"
	"github.com/croessner/nauthilus/v3/server/model/mfa"
	"github.com/croessner/nauthilus/v3/server/security"
	"github.com/croessner/nauthilus/v3/server/stats"
	"github.com/croessner/nauthilus/v3/server/util"

	monittrace "github.com/croessner/nauthilus/v3/server/monitoring/trace"
	"github.com/go-ldap/ldap/v3"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const (
	ldapMissingTOTPSecretFieldDetail   = "Missing LDAP TOTP secret field"
	ldapMissingTOTPRecoveryFieldDetail = "Missing LDAP TOTP recovery field"
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

type ldapAccountSearchPlan struct {
	scope        *config.LDAPScope
	filter       string
	baseDN       string
	accountField string
	attributes   []string
}

type ldapPassDBSearchPlan struct {
	protocol     *config.LDAPSearchProtocol
	scope        *config.LDAPScope
	cancelSearch context.CancelFunc
	filter       string
	baseDN       string
	accountField string
	attributes   []string
}

type ldapPassDBFoundState struct {
	securityManager *security.Manager
	totpSecretPre   []any
	dn              string
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

type ldapObjectClassAddInput struct {
	scope             *config.LDAPScope
	filter            string
	baseDN            string
	objectClass       string
	waitSpan          string
	priority          int
	includeTOTPSecret bool
}

type ldapAttributeReplaceParams struct {
	prepareSpan           string
	missingProtocolDetail string
	missingFieldDetail    string
	fieldGetter           func(*config.LDAPSearchProtocol) string
}

type ldapAttributeReplacePlan struct {
	protocol    *config.LDAPSearchProtocol
	scope       *config.LDAPScope
	filter      string
	baseDN      string
	configField string
}

// loadSearchConfig resolves LDAP search settings with optional protocol and attribute handling.
func (lm *ldapManagerImpl) loadSearchConfig(endSpan spanEnder, protocolName string, opts ldapSearchConfigOptions) (ldapSearchConfig, error) {
	var cfg ldapSearchConfig

	protocol, err := lm.effectiveCfg().GetLDAPSearchProtocol(protocolName, lm.poolName)
	if err != nil || protocol == nil {
		if err == nil && opts.requireProtocol {
			err = errors.ErrLDAPConfig.WithDetail(fmt.Sprintf(opts.missingProtocolDetail, protocolName))
		}

		endLDAPPrepareSpan(endSpan)

		return cfg, err
	}

	cfg.protocol = protocol

	ignored, err := cfg.loadOptionalSearchFields(protocol, opts)
	if ignored {
		endLDAPPrepareSpan(endSpan)

		return ldapSearchConfig{}, nil
	}

	if err != nil {
		endLDAPPrepareSpan(endSpan)

		return cfg, err
	}

	if err := cfg.loadRequiredSearchFields(protocol); err != nil {
		endLDAPPrepareSpan(endSpan)

		return cfg, err
	}

	return cfg, nil
}

// endLDAPPrepareSpan closes an LDAP preparation span when it has been started.
func endLDAPPrepareSpan(endSpan spanEnder) {
	if endSpan != nil {
		endSpan()
	}
}

// loadOptionalSearchFields loads optional LDAP filter, account, and attribute settings.
func (cfg *ldapSearchConfig) loadOptionalSearchFields(protocol *config.LDAPSearchProtocol, opts ldapSearchConfigOptions) (bool, error) {
	if err := cfg.loadSearchFilter(protocol, opts); err != nil {
		return opts.ignoreFilterError, err
	}

	if err := cfg.loadSearchAccountField(protocol, opts); err != nil {
		return false, err
	}

	if err := cfg.loadSearchAttributes(protocol, opts); err != nil {
		return false, err
	}

	return false, nil
}

// loadSearchFilter resolves the optional LDAP search filter.
func (cfg *ldapSearchConfig) loadSearchFilter(protocol *config.LDAPSearchProtocol, opts ldapSearchConfigOptions) error {
	if opts.filterGetter == nil {
		return nil
	}

	filter, err := opts.filterGetter(protocol)
	if err != nil {
		return err
	}

	cfg.filter = filter

	return nil
}

// loadSearchAccountField resolves the optional LDAP account field.
func (cfg *ldapSearchConfig) loadSearchAccountField(protocol *config.LDAPSearchProtocol, opts ldapSearchConfigOptions) error {
	if !opts.includeAccountField {
		return nil
	}

	accountField, err := protocol.GetAccountField()
	if err != nil {
		return err
	}

	cfg.accountField = accountField

	return nil
}

// loadSearchAttributes resolves optional LDAP search attributes.
func (cfg *ldapSearchConfig) loadSearchAttributes(protocol *config.LDAPSearchProtocol, opts ldapSearchConfigOptions) error {
	if !opts.includeAttributes {
		return nil
	}

	attributes, err := protocol.GetAttributes()
	if err != nil {
		return err
	}

	cfg.attributes = attributes

	return nil
}

// loadRequiredSearchFields resolves the LDAP base DN and scope.
func (cfg *ldapSearchConfig) loadRequiredSearchFields(protocol *config.LDAPSearchProtocol) error {
	baseDN, err := protocol.GetBaseDN()
	if err != nil {
		return err
	}

	scope, err := protocol.GetScope()
	if err != nil {
		return err
	}

	cfg.baseDN = baseDN
	cfg.scope = scope

	return nil
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
		Account:     auth.GetAccount(),
		XLocalIP:    auth.Request.XLocalIP,
		XPort:       auth.Request.XPort,
		ClientIP:    auth.Request.ClientIP,
		XClientPort: auth.Request.XClientPort,
		Protocol:    *auth.Request.Protocol,
	}

	if dnValues, ok := auth.GetAttribute(definitions.DistinguishedName); ok && len(dnValues) > 0 {
		if userDN, ok := dnValues[definitions.LDAPSingleValue].(string); ok {
			macro.UserDN = userDN
		}
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
func startSpan(ctx context.Context, tr monittrace.Tracer, name string) (context.Context, spanEnder) {
	ctx, span := tr.Start(ctx, name)

	return ctx, func() { span.End() }
}

// waitLDAPReply waits for a reply and wraps the wait with a tracing span.
func waitLDAPReply(ctx context.Context, tr monittrace.Tracer, name string, replyChan <-chan *bktype.LDAPReply) *bktype.LDAPReply {
	_, endSpan := startSpan(ctx, tr, name)
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
			plaintext, handled, err := decryptLDAPScalarAttribute(manager, entry)
			if handled {
				if err != nil {
					return nil, err
				}

				decrypted[index] = plaintext

				continue
			}

			decrypted[index] = entry
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

// decryptLDAPScalarAttribute decrypts supported scalar LDAP attribute values.
func decryptLDAPScalarAttribute(manager *security.Manager, value any) (any, bool, error) {
	switch typedValue := value.(type) {
	case string:
		plaintext, err := manager.Decrypt(typedValue)

		return plaintext, true, err
	case []byte:
		plaintext, err := manager.Decrypt(string(typedValue))

		return plaintext, true, err
	default:
		return nil, false, nil
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

	resource := util.RequestResource(auth.Request.HTTPClientContext, auth.Request.HTTPClientRequest, lm.poolName)

	stopTimer := stats.PrometheusTimer(lm.effectiveCfg(), definitions.PromBackend, "ldap_passdb_request_total", resource)
	if stopTimer != nil {
		defer stopTimer()
	}

	passDBResult = GetPassDBResultFromPool()

	ldapReplyChan := make(chan *bktype.LDAPReply, 1)

	searchPlan, ok, err := lm.prepareLDAPPassDBSearch(lctx, auth, tr, lspan, ldapReplyChan)
	if err != nil || !ok {
		return
	}

	defer searchPlan.cancelSearch()

	ldapReply := waitLDAPReply(lctx, tr, "ldap.passdb.search.wait", ldapReplyChan)
	if ldapReply.Err != nil {
		return passDBResult, recordLDAPReplyError(lspan, ldapReply.Err)
	}

	foundState, found, err := lm.applyLDAPPassDBSearchReply(auth, lspan, passDBResult, searchPlan, ldapReply)
	if err != nil || !found {
		return
	}

	authenticated, err := lm.authenticateLDAPPassDBUser(lctx, auth, tr, lspan, foundState.dn)
	if err != nil || !authenticated {
		return passDBResult, err
	}

	completeLDAPPassDBAuthentication(auth, lspan, passDBResult)

	return lm.refreshLDAPPassDBForMasterUser(auth, passDBResult, foundState.totpSecretPre, searchPlan.protocol)
}

// prepareLDAPPassDBSearch resolves search settings, builds the search request, and queues it.
func (lm *ldapManagerImpl) prepareLDAPPassDBSearch(
	lctx context.Context,
	auth *AuthState,
	tr monittrace.Tracer,
	lspan trace.Span,
	replyChan chan *bktype.LDAPReply,
) (ldapPassDBSearchPlan, bool, error) {
	_, endPrepare := startSpan(lctx, tr, "ldap.passdb.search.prepare")

	searchConfig, err := lm.loadSearchConfig(endPrepare, auth.Request.Protocol.Get(), ldapSearchConfigOptions{
		requireProtocol:       true,
		missingProtocolDetail: "Missing LDAP search protocol; protocol=%s",
		filterGetter:          (*config.LDAPSearchProtocol).GetUserFilter,
		includeAccountField:   true,
		includeAttributes:     true,
	})
	if err != nil || searchConfig.protocol == nil {
		return ldapPassDBSearchPlan{}, false, err
	}

	ctxSearch, cancelSearch := context.WithTimeout(auth.Ctx(), lm.effectiveCfg().GetServer().GetTimeouts().GetLDAPSearch())
	plan := ldapPassDBSearchPlan{
		protocol:     searchConfig.protocol,
		scope:        searchConfig.scope,
		cancelSearch: cancelSearch,
		filter:       searchConfig.filter,
		baseDN:       searchConfig.baseDN,
		accountField: searchConfig.accountField,
		attributes:   searchConfig.attributes,
	}

	lspan.SetAttributes(
		attribute.String("base_dn", plan.baseDN),
		attribute.String("scope", plan.scope.String()),
	)

	request := lm.newLDAPPassDBSearchRequest(ctxSearch, auth, plan, replyChan)

	endPrepare()
	lm.ldapQueue().Push(request, lm.requestPriority(auth))

	return plan, true, nil
}

// newLDAPPassDBSearchRequest builds the queued LDAP search request for PassDB.
func (lm *ldapManagerImpl) newLDAPPassDBSearchRequest(
	ctxSearch context.Context,
	auth *AuthState,
	plan ldapPassDBSearchPlan,
	replyChan chan *bktype.LDAPReply,
) *bktype.LDAPRequest {
	macroSource := lm.newMacroSource(auth, true)
	macroSource.Username = auth.handleMasterUserMode()

	return &bktype.LDAPRequest{
		GUID:              auth.Runtime.GUID,
		Command:           definitions.LDAPSearch,
		PoolName:          lm.poolName,
		MacroSource:       macroSource,
		Filter:            plan.filter,
		BaseDN:            plan.baseDN,
		SearchAttributes:  plan.attributes,
		Scope:             *plan.scope,
		LDAPReplyChan:     replyChan,
		HTTPClientContext: ctxSearch,
	}
}

// applyLDAPPassDBSearchReply applies a successful LDAP search reply to the PassDB result.
func (lm *ldapManagerImpl) applyLDAPPassDBSearchReply(
	auth *AuthState,
	lspan trace.Span,
	passDBResult *PassDBResult,
	plan ldapPassDBSearchPlan,
	ldapReply *bktype.LDAPReply,
) (ldapPassDBFoundState, bool, error) {
	distinguishedNames, ok := ldapReply.Result[definitions.DistinguishedName]
	if !ok {
		return ldapPassDBFoundState{}, false, nil
	}

	if len(distinguishedNames) == 0 {
		return ldapPassDBFoundState{}, false, nil
	}

	state := ldapPassDBFoundState{
		dn:              distinguishedNames[definitions.LDAPSingleValue].(string),
		securityManager: lm.ldapPassDBSecurityManager(plan.protocol),
		totpSecretPre:   saveMasterUserTOTPSecret(auth.Runtime.MasterUserMode, ldapReply, plan.protocol.TOTPSecretField),
	}

	lm.applyLDAPPassDBFoundFields(lspan, passDBResult, plan, ldapReply)

	if err := lm.decryptLDAPPassDBMFAAttributes(passDBResult, plan.protocol, state.securityManager); err != nil {
		return ldapPassDBFoundState{}, false, err
	}

	if passDBResult.Attributes != nil {
		passDBResult.Groups, passDBResult.GroupDistinguishedNames = lm.resolveGroups(auth, plan.protocol, passDBResult.Attributes, plan.accountField, lm.effectiveLogger())
	}

	totpSecretPre, err := decryptLDAPMasterTOTPSecret(state.securityManager, state.totpSecretPre)
	if err != nil {
		return ldapPassDBFoundState{}, false, err
	}

	state.totpSecretPre = totpSecretPre

	return state, true, nil
}

// applyLDAPPassDBFoundFields marks the user as found and copies configured LDAP fields.
func (lm *ldapManagerImpl) applyLDAPPassDBFoundFields(
	lspan trace.Span,
	passDBResult *PassDBResult,
	plan ldapPassDBSearchPlan,
	ldapReply *bktype.LDAPReply,
) {
	passDBResult.UserFound = true
	passDBResult.Backend = definitions.BackendLDAP
	passDBResult.BackendName = lm.poolName

	lspan.SetAttributes(attribute.Bool("user_found", true))

	if _, okay := ldapReply.Result[plan.accountField]; okay {
		passDBResult.AccountField = plan.accountField
	}

	applyLDAPPassDBProtocolFields(passDBResult, plan.protocol, plan.accountField)

	if len(ldapReply.Result) > 0 {
		passDBResult.Attributes = ldapReply.Result
	}
}

// applyLDAPPassDBProtocolFields copies MFA and display-name field configuration.
func applyLDAPPassDBProtocolFields(passDBResult *PassDBResult, protocol *config.LDAPSearchProtocol, accountField string) {
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

		return
	}

	passDBResult.DisplayNameField = accountField
}

// ldapPassDBSecurityManager returns a decrypter when encrypted MFA fields are configured.
func (lm *ldapManagerImpl) ldapPassDBSecurityManager(protocol *config.LDAPSearchProtocol) *security.Manager {
	if protocol.TOTPSecretField == "" && protocol.GetTotpRecoveryField() == "" {
		return nil
	}

	return security.NewManager(lm.effectiveCfg().GetLDAPConfigEncryptionSecret())
}

// decryptLDAPPassDBMFAAttributes decrypts configured TOTP fields in the LDAP attribute map.
func (lm *ldapManagerImpl) decryptLDAPPassDBMFAAttributes(
	passDBResult *PassDBResult,
	protocol *config.LDAPSearchProtocol,
	securityManager *security.Manager,
) error {
	if passDBResult.Attributes == nil {
		return nil
	}

	if protocol.TOTPSecretField != "" {
		if decryptErr := decryptLDAPAttributeValues(securityManager, passDBResult.Attributes, protocol.TOTPSecretField); decryptErr != nil {
			return errors.ErrLDAPConfig.WithDetail(
				fmt.Sprintf("Failed to decrypt LDAP TOTP secret: %v", decryptErr))
		}
	}

	if protocol.GetTotpRecoveryField() != "" {
		if decryptErr := decryptLDAPAttributeValues(securityManager, passDBResult.Attributes, protocol.GetTotpRecoveryField()); decryptErr != nil {
			return errors.ErrLDAPConfig.WithDetail(
				fmt.Sprintf("Failed to decrypt LDAP TOTP recovery codes: %v", decryptErr))
		}
	}

	return nil
}

// decryptLDAPMasterTOTPSecret decrypts the saved master-user TOTP secret when present.
func decryptLDAPMasterTOTPSecret(securityManager *security.Manager, totpSecretPre []any) ([]any, error) {
	if securityManager == nil || totpSecretPre == nil {
		return totpSecretPre, nil
	}

	decryptedSecret, decryptErr := decryptLDAPAttributeValue(securityManager, totpSecretPre)
	if decryptErr != nil {
		return nil, errors.ErrLDAPConfig.WithDetail(
			fmt.Sprintf("Failed to decrypt LDAP master TOTP secret: %v", decryptErr))
	}

	switch typedSecret := decryptedSecret.(type) {
	case []any:
		return typedSecret, nil
	case []string:
		normalized := make([]any, len(typedSecret))
		for index, entry := range typedSecret {
			normalized[index] = entry
		}

		return normalized, nil
	default:
		return totpSecretPre, nil
	}
}

// authenticateLDAPPassDBUser performs the optional LDAP bind for password verification.
func (lm *ldapManagerImpl) authenticateLDAPPassDBUser(
	lctx context.Context,
	auth *AuthState,
	tr monittrace.Tracer,
	lspan trace.Span,
	dn string,
) (bool, error) {
	if auth.Request.NoAuth {
		return true, nil
	}

	replyChan := make(chan *bktype.LDAPReply, 1)
	_, endAuthPrepare := startSpan(lctx, tr, "ldap.passdb.auth.prepare")

	ctxBind, cancelBind := context.WithTimeout(auth.Ctx(), lm.effectiveCfg().GetServer().GetTimeouts().GetLDAPBind())
	defer cancelBind()

	request := lm.newLDAPPassDBBindRequest(ctxBind, auth, dn, replyChan)
	priority := lm.requestPriority(auth)

	endAuthPrepare()
	lm.ldapAuthQueue().Push(request, priority)

	ldapReply := waitLDAPReply(lctx, tr, "ldap.passdb.auth.wait", replyChan)
	if ldapReply.Err == nil {
		return true, nil
	}

	return lm.handleLDAPPassDBBindError(auth, lspan, ldapReply.Err)
}

// newLDAPPassDBBindRequest builds the queued LDAP bind request for PassDB.
func (lm *ldapManagerImpl) newLDAPPassDBBindRequest(
	ctxBind context.Context,
	auth *AuthState,
	dn string,
	replyChan chan *bktype.LDAPReply,
) *bktype.LDAPAuthRequest {
	var bindPassword string

	auth.Request.Password.WithString(func(value string) {
		bindPassword = value
	})

	return &bktype.LDAPAuthRequest{
		GUID:              auth.Runtime.GUID,
		PoolName:          lm.poolName,
		BindDN:            dn,
		BindPW:            bindPassword,
		LDAPReplyChan:     replyChan,
		HTTPClientContext: ctxBind,
	}
}

// handleLDAPPassDBBindError distinguishes invalid credentials from transport errors.
func (lm *ldapManagerImpl) handleLDAPPassDBBindError(auth *AuthState, lspan trace.Span, err error) (bool, error) {
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

			return false, ldapError.Err
		}
	}

	lspan.SetAttributes(attribute.Bool("authenticated", false))

	return false, nil
}

// completeLDAPPassDBAuthentication records successful bind state and cache status.
func completeLDAPPassDBAuthentication(auth *AuthState, lspan trace.Span, passDBResult *PassDBResult) {
	passDBResult.Authenticated = true

	lspan.SetAttributes(attribute.Bool("authenticated", true))
	localcache.AuthCache.Set(auth.Request.Username, true)
}

// refreshLDAPPassDBForMasterUser performs the second lookup required for master-user mode.
func (lm *ldapManagerImpl) refreshLDAPPassDBForMasterUser(
	auth *AuthState,
	passDBResult *PassDBResult,
	totpSecretPre []any,
	protocol *config.LDAPSearchProtocol,
) (*PassDBResult, error) {
	if !auth.Runtime.MasterUserMode {
		return passDBResult, nil
	}

	previousNoAuth := auth.Request.NoAuth
	auth.Request.NoAuth = true

	PutPassDBResultToPool(passDBResult)

	refreshedResult, err := lm.PassDB(auth)
	auth.Request.NoAuth = previousNoAuth

	restoreMasterUserTOTPSecret(refreshedResult, totpSecretPre, protocol.TOTPSecretField)

	return refreshedResult, err
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

	resource := util.RequestResource(auth.Request.HTTPClientContext, auth.Request.HTTPClientRequest, lm.poolName)
	stopTimer := stats.PrometheusTimer(lm.effectiveCfg(), definitions.PromAccount, "ldap_account_request_total", resource)

	if stopTimer != nil {
		defer stopTimer()
	}

	ldapReplyChan := make(chan *bktype.LDAPReply, 1)

	plan, endPrepare, err := lm.prepareLDAPAccountSearch(actx, auth, asp, tr)
	if err != nil || endPrepare == nil {
		return
	}

	ctxSearch, cancelSearch := util.GetCtxWithDeadlineLDAPSearch(lm.effectiveCfg())
	defer cancelSearch()

	ldapRequest := lm.newLDAPAccountRequest(ctxSearch, auth, plan, ldapReplyChan)

	endPrepare()

	lm.ldapQueue().Push(ldapRequest, priorityqueue.PriorityMedium)

	ldapReply := waitLDAPReply(actx, tr, "ldap.accountdb.wait", ldapReplyChan)

	if ldapReply.Err != nil {
		return accounts, recordLDAPReplyError(asp, ldapReply.Err)
	}

	accounts = lm.accountsFromLDAPReply(auth, ldapReply, plan.accountField)

	return accounts, nil
}

// accountsFromLDAPReply converts the configured LDAP account field into an account list.
func (lm *ldapManagerImpl) accountsFromLDAPReply(auth *AuthState, ldapReply *bktype.LDAPReply, accountField string) AccountList {
	var accounts AccountList

	if result, okay := ldapReply.Result[accountField]; okay {
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

	return accounts
}

// prepareLDAPAccountSearch resolves LDAP search settings for account listing.
func (lm *ldapManagerImpl) prepareLDAPAccountSearch(ctx context.Context, auth *AuthState, span trace.Span, tr monittrace.Tracer) (ldapAccountSearchPlan, spanEnder, error) {
	var plan ldapAccountSearchPlan

	_, endPrepare := startSpan(ctx, tr, "ldap.accountdb.prepare")

	searchConfig, err := lm.loadSearchConfig(endPrepare, auth.Request.Protocol.Get(), ldapSearchConfigOptions{
		filterGetter:        (*config.LDAPSearchProtocol).GetListAccountsFilter,
		ignoreFilterError:   true,
		includeAccountField: true,
		includeAttributes:   true,
	})
	if err != nil || searchConfig.protocol == nil {
		return plan, nil, err
	}

	span.SetAttributes(
		attribute.String("base_dn", searchConfig.baseDN),
		attribute.String("scope", searchConfig.scope.String()),
	)

	plan.accountField = searchConfig.accountField
	plan.attributes = searchConfig.attributes
	plan.filter = searchConfig.filter
	plan.baseDN = searchConfig.baseDN
	plan.scope = searchConfig.scope

	return plan, endPrepare, nil
}

// newLDAPAccountRequest builds the LDAP search request used for account listing.
func (lm *ldapManagerImpl) newLDAPAccountRequest(ctx context.Context, auth *AuthState, plan ldapAccountSearchPlan, replyChan chan *bktype.LDAPReply) *bktype.LDAPRequest {
	return &bktype.LDAPRequest{
		GUID:              auth.Runtime.GUID,
		Command:           definitions.LDAPSearch,
		PoolName:          lm.poolName,
		MacroSource:       lm.newMacroSource(auth, true),
		Filter:            plan.filter,
		BaseDN:            plan.baseDN,
		SearchAttributes:  plan.attributes,
		Scope:             *plan.scope,
		LDAPReplyChan:     replyChan,
		HTTPClientContext: ctx,
	}
}

// recordLDAPReplyError records and returns an LDAP reply error without changing its concrete value.
func recordLDAPReplyError(span trace.Span, err error) error {
	if err != nil {
		span.RecordError(err)
	}

	return err
}

// encryptLDAPString encrypts a value with the configured LDAP encryption secret.
func (lm *ldapManagerImpl) encryptLDAPString(value string, failureDetail string) (string, error) {
	securityManager := security.NewManager(lm.effectiveCfg().GetLDAPConfigEncryptionSecret())

	encryptedValue, err := securityManager.Encrypt(value)
	if err != nil {
		return "", errors.ErrLDAPConfig.WithDetail(fmt.Sprintf("%s: %v", failureDetail, err))
	}

	return encryptedValue, nil
}

// encryptLDAPStrings encrypts a list of values with the configured LDAP encryption secret.
func (lm *ldapManagerImpl) encryptLDAPStrings(values []string, failureDetail string) ([]string, error) {
	securityManager := security.NewManager(lm.effectiveCfg().GetLDAPConfigEncryptionSecret())
	encryptedValues := make([]string, len(values))

	for index, value := range values {
		encryptedValue, err := securityManager.Encrypt(value)
		if err != nil {
			return nil, errors.ErrLDAPConfig.WithDetail(fmt.Sprintf("%s: %v", failureDetail, err))
		}

		encryptedValues[index] = encryptedValue
	}

	return encryptedValues, nil
}

// addLDAPObjectClass adds an optional objectClass before mutating an LDAP attribute.
func (lm *ldapManagerImpl) addLDAPObjectClass(ctx context.Context, auth *AuthState, tr monittrace.Tracer, input ldapObjectClassAddInput) error {
	if input.objectClass == "" {
		return nil
	}

	ctxAddOC, cancelAddOC := lm.ldapModifyContext()
	defer cancelAddOC()

	objectClassReplyChan := make(chan *bktype.LDAPReply, 1)
	ocRequest := lm.newLDAPModifyRequest(ldapModifyRequestInput{
		auth:              auth,
		filter:            input.filter,
		baseDN:            input.baseDN,
		scope:             input.scope,
		subCommand:        definitions.LDAPModifyAdd,
		ctx:               ctxAddOC,
		replyChan:         objectClassReplyChan,
		includeTOTPSecret: input.includeTOTPSecret,
	})

	ocRequest.ModifyAttributes = bktype.LDAPModifyAttributes{
		ldapAttributeObjectClass: []string{input.objectClass},
	}

	lm.ldapQueue().Push(ocRequest, input.priority)

	var ocReply *bktype.LDAPReply
	if input.waitSpan != "" {
		ocReply = waitLDAPReply(ctx, tr, input.waitSpan, objectClassReplyChan)
	} else {
		ocReply = <-objectClassReplyChan
	}

	if ocReply.Err == nil || isAttributeOrValueExistsError(ocReply.Err) {
		return nil
	}

	return ocReply.Err
}

// prepareLDAPAttributeReplace resolves LDAP search settings for a single attribute replacement.
func (lm *ldapManagerImpl) prepareLDAPAttributeReplace(ctx context.Context, auth *AuthState, span trace.Span, tr monittrace.Tracer, params ldapAttributeReplaceParams) (ldapAttributeReplacePlan, spanEnder, error) {
	var plan ldapAttributeReplacePlan

	_, endPrepare := startSpan(ctx, tr, params.prepareSpan)

	searchConfig, err := lm.loadSearchConfig(endPrepare, auth.Request.Protocol.Get(), ldapSearchConfigOptions{
		filterGetter:          (*config.LDAPSearchProtocol).GetUserFilter,
		requireProtocol:       true,
		missingProtocolDetail: params.missingProtocolDetail,
	})
	if err != nil || searchConfig.protocol == nil {
		return plan, nil, err
	}

	span.SetAttributes(
		attribute.String("base_dn", searchConfig.baseDN),
		attribute.String("scope", searchConfig.scope.String()),
	)

	configField := params.fieldGetter(searchConfig.protocol)
	if configField == "" {
		endPrepare()

		return plan, nil, errors.ErrLDAPConfig.WithDetail(
			fmt.Sprintf("%s; protocol=%s", params.missingFieldDetail, auth.Request.Protocol.Get()))
	}

	plan.protocol = searchConfig.protocol
	plan.filter = searchConfig.filter
	plan.baseDN = searchConfig.baseDN
	plan.scope = searchConfig.scope
	plan.configField = configField

	return plan, endPrepare, nil
}

// newLDAPReplaceAttributeRequest builds the LDAP modify-replace request for one attribute.
func (lm *ldapManagerImpl) newLDAPReplaceAttributeRequest(ctx context.Context, auth *AuthState, plan ldapAttributeReplacePlan, replyChan chan *bktype.LDAPReply, values []string, includeTOTPSecret bool) *bktype.LDAPRequest {
	ldapRequest := lm.newLDAPModifyRequest(ldapModifyRequestInput{
		auth:              auth,
		filter:            plan.filter,
		baseDN:            plan.baseDN,
		scope:             plan.scope,
		subCommand:        definitions.LDAPModifyReplace,
		ctx:               ctx,
		replyChan:         replyChan,
		includeTOTPSecret: includeTOTPSecret,
	})

	ldapRequest.ModifyAttributes = bktype.LDAPModifyAttributes{
		plan.configField: values,
	}

	return ldapRequest
}

// replaceLDAPAttribute executes the LDAP modify-replace operation for one attribute.
func (lm *ldapManagerImpl) replaceLDAPAttribute(ctx context.Context, auth *AuthState, tr monittrace.Tracer, waitSpan string, plan ldapAttributeReplacePlan, values []string, priority int, includeTOTPSecret bool) error {
	ldapReplyChan := make(chan *bktype.LDAPReply)

	ctxModify, cancelModify := lm.ldapModifyContext()
	defer cancelModify()

	ldapRequest := lm.newLDAPReplaceAttributeRequest(ctxModify, auth, plan, ldapReplyChan, values, includeTOTPSecret)
	lm.ldapQueue().Push(ldapRequest, priority)

	return waitLDAPReply(ctx, tr, waitSpan, ldapReplyChan).Err
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

	resource := util.RequestResource(auth.Request.HTTPClientContext, auth.Request.HTTPClientRequest, lm.poolName)
	stopTimer := stats.PrometheusTimer(lm.effectiveCfg(), definitions.PromStoreTOTP, "ldap_store_totp_request_total", resource)

	if stopTimer != nil {
		defer stopTimer()
	}

	plan, endPrepare, err := lm.prepareLDAPAttributeReplace(mctx, auth, msp, tr, ldapAttributeReplaceParams{
		prepareSpan:           "ldap.add_totp.prepare",
		missingProtocolDetail: "Missing LDAP search protocol for TOTP; protocol=%s",
		missingFieldDetail:    ldapMissingTOTPSecretFieldDetail,
		fieldGetter:           (*config.LDAPSearchProtocol).GetTotpSecretField,
	})
	if err != nil || endPrepare == nil {
		return
	}

	encryptedSecret, encryptErr := lm.encryptLDAPString(totp.GetValue(), "Failed to encrypt LDAP TOTP secret")
	if encryptErr != nil {
		endPrepare()

		return encryptErr
	}

	totpObjectClass := plan.protocol.GetTotpObjectClass()
	priority := lm.requestPriority(auth)

	endPrepare()

	if err := lm.addLDAPObjectClass(mctx, auth, tr, ldapObjectClassAddInput{
		scope:             plan.scope,
		filter:            plan.filter,
		baseDN:            plan.baseDN,
		objectClass:       totpObjectClass,
		waitSpan:          "ldap.add_totp.objectclass",
		priority:          priority,
		includeTOTPSecret: true,
	}); err != nil {
		msp.RecordError(err)

		return wrapLDAPModifyError(err, "Failed to add objectClass for TOTP")
	}

	replyErr := lm.replaceLDAPAttribute(mctx, auth, tr, "ldap.add_totp.wait", plan, []string{encryptedSecret}, priority, true)
	if replyErr != nil {
		msp.RecordError(replyErr)
	}

	return wrapLDAPModifyError(replyErr, "Failed to add TOTP secret")
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

type deleteLDAPFieldPlan struct {
	scope       *config.LDAPScope
	filter      string
	baseDN      string
	configField string
}

// prepareDeleteLDAPField resolves LDAP search settings and the attribute to delete.
func (lm *ldapManagerImpl) prepareDeleteLDAPField(ctx context.Context, auth *AuthState, params deleteLDAPFieldParams, span trace.Span, tr monittrace.Tracer) (deleteLDAPFieldPlan, spanEnder, error) {
	var plan deleteLDAPFieldPlan

	_, endPrepare := startSpan(ctx, tr, params.prepareSpan)

	searchConfig, err := lm.loadSearchConfig(endPrepare, auth.Request.Protocol.Get(), ldapSearchConfigOptions{
		filterGetter:          (*config.LDAPSearchProtocol).GetUserFilter,
		requireProtocol:       true,
		missingProtocolDetail: "Missing LDAP search protocol for delete; protocol=%s",
	})
	if err != nil || searchConfig.protocol == nil {
		return plan, nil, err
	}

	span.SetAttributes(
		attribute.String("base_dn", searchConfig.baseDN),
		attribute.String("scope", searchConfig.scope.String()),
	)

	configField := params.fieldGetter(searchConfig.protocol)
	if configField == "" {
		endPrepare()

		return plan, nil, errors.ErrLDAPConfig.WithDetail(
			fmt.Sprintf("%s; protocol=%s", params.missingDetail, auth.Request.Protocol.Get()))
	}

	plan.filter = searchConfig.filter
	plan.baseDN = searchConfig.baseDN
	plan.scope = searchConfig.scope
	plan.configField = configField

	return plan, endPrepare, nil
}

// newDeleteLDAPFieldRequest builds the LDAP modify-delete request for one attribute.
func (lm *ldapManagerImpl) newDeleteLDAPFieldRequest(ctx context.Context, auth *AuthState, plan deleteLDAPFieldPlan, replyChan chan *bktype.LDAPReply) *bktype.LDAPRequest {
	ldapRequest := lm.newLDAPModifyRequest(ldapModifyRequestInput{
		auth:       auth,
		filter:     plan.filter,
		baseDN:     plan.baseDN,
		scope:      plan.scope,
		subCommand: definitions.LDAPModifyDelete,
		ctx:        ctx,
		replyChan:  replyChan,
	})

	ldapRequest.ModifyAttributes = make(bktype.LDAPModifyAttributes, 1)
	ldapRequest.ModifyAttributes[plan.configField] = []string{}

	return ldapRequest
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

	resource := util.RequestResource(auth.Request.HTTPClientContext, auth.Request.HTTPClientRequest, lm.poolName)
	stopTimer := stats.PrometheusTimer(lm.effectiveCfg(), params.promLabel, params.promMetric, resource)

	if stopTimer != nil {
		defer stopTimer()
	}

	ldapReplyChan := make(chan *bktype.LDAPReply)

	plan, endPrepare, err := lm.prepareDeleteLDAPField(mctx, auth, params, msp, tr)
	if err != nil || endPrepare == nil {
		return
	}

	ctxModify, cancelModify := lm.ldapModifyContext()
	defer cancelModify()

	ldapRequest := lm.newDeleteLDAPFieldRequest(ctxModify, auth, plan, ldapReplyChan)

	endPrepare()

	// Use priority queue instead of channel
	lm.ldapQueue().Push(ldapRequest, lm.requestPriority(auth))

	ldapReply := waitLDAPReply(mctx, tr, params.waitSpan, ldapReplyChan)

	if isNoSuchAttributeError(ldapReply.Err) {
		return nil
	}

	if ldapReply.Err != nil {
		msp.RecordError(ldapReply.Err)
	}

	return wrapLDAPModifyError(ldapReply.Err, "Failed to delete LDAP field")
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
		missingDetail: ldapMissingTOTPSecretFieldDetail,
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

	resource := util.RequestResource(auth.Request.HTTPClientContext, auth.Request.HTTPClientRequest, lm.poolName)
	stopTimer := stats.PrometheusTimer(lm.effectiveCfg(), definitions.PromStoreTOTPRecovery, "ldap_store_totp_recovery_request_total", resource)

	if stopTimer != nil {
		defer stopTimer()
	}

	plan, endPrepare, err := lm.prepareLDAPAttributeReplace(mctx, auth, msp, tr, ldapAttributeReplaceParams{
		prepareSpan:           "ldap.add_totp_recovery.prepare",
		missingProtocolDetail: "Missing LDAP search protocol for TOTP recovery; protocol=%s",
		missingFieldDetail:    ldapMissingTOTPRecoveryFieldDetail,
		fieldGetter:           (*config.LDAPSearchProtocol).GetTotpRecoveryField,
	})
	if err != nil || endPrepare == nil {
		return
	}

	codes := recovery.GetCodes()

	encryptedCodes, encryptErr := lm.encryptLDAPStrings(codes, "Failed to encrypt LDAP TOTP recovery code")
	if encryptErr != nil {
		endPrepare()

		return encryptErr
	}

	totpRecoveryObjectClass := plan.protocol.GetTotpRecoveryObjectClass()
	priority := lm.requestPriority(auth)

	if err := lm.addLDAPObjectClass(mctx, auth, tr, ldapObjectClassAddInput{
		scope:       plan.scope,
		filter:      plan.filter,
		baseDN:      plan.baseDN,
		objectClass: totpRecoveryObjectClass,
		priority:    priority,
	}); err != nil {
		msp.RecordError(err)

		return wrapLDAPModifyError(err, "Failed to add objectClass for TOTP recovery")
	}

	endPrepare()

	replyErr := lm.replaceLDAPAttribute(mctx, auth, tr, "ldap.add_totp_recovery.wait", plan, encryptedCodes, priority, false)
	if replyErr != nil {
		msp.RecordError(replyErr)
	}

	return wrapLDAPModifyError(replyErr, "Failed to add TOTP recovery codes")
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
		missingDetail: ldapMissingTOTPRecoveryFieldDetail,
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

// wrapLDAPModifyError wraps a raw LDAP error (or any error returned from an
// LDAP modify operation) into ErrLDAPModify with a human-readable detail that
// includes the LDAP result code description. If the error is nil it returns nil.
func wrapLDAPModifyError(err error, operation string) error {
	if err == nil {
		return nil
	}

	if ldapErr, ok := stderrors.AsType[*ldap.Error](err); ok {
		desc := ldap.LDAPResultCodeMap[ldapErr.ResultCode]

		return errors.ErrLDAPModify.WithDetail(
			fmt.Sprintf("%s: LDAP result code %d (%s)", operation, ldapErr.ResultCode, desc))
	}

	return errors.ErrLDAPModify.WithDetail(fmt.Sprintf("%s: %v", operation, err))
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
