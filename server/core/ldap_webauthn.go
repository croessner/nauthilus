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
	"fmt"
	"strings"

	"github.com/croessner/nauthilus/v3/server/backend/bktype"
	"github.com/croessner/nauthilus/v3/server/backend/priorityqueue"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/errors"
	"github.com/croessner/nauthilus/v3/server/model/mfa"
	monittrace "github.com/croessner/nauthilus/v3/server/monitoring/trace"
	"github.com/croessner/nauthilus/v3/server/util"
	"go.opentelemetry.io/otel/attribute"
)

type webAuthnLDAPCredentialPlan struct {
	scope           *config.LDAPScope
	replyChan       chan *bktype.LDAPReply
	credentialField string
	objectClass     string
	username        string
	filter          string
	baseDN          string
	priority        int
}

// webAuthnLookupProtocolName resolves and normalizes the protocol used for LDAP WebAuthn lookup.
func webAuthnLookupProtocolName(auth *AuthState) string {
	protocolName := definitions.ProtoIDP
	if auth.Request.Protocol == nil {
		auth.Request.Protocol = config.NewProtocol(protocolName)

		return protocolName
	}

	if currentProtocol := auth.Request.Protocol.Get(); currentProtocol != "" {
		return currentProtocol
	}

	auth.Request.Protocol.Set(protocolName)

	return protocolName
}

// newWebAuthnLDAPLookupPlan resolves LDAP settings for credential lookup.
func (lm *ldapManagerImpl) newWebAuthnLDAPLookupPlan(auth *AuthState) (webAuthnLDAPCredentialPlan, bool, error) {
	var plan webAuthnLDAPCredentialPlan

	protocol, err := lm.effectiveCfg().GetLDAPSearchProtocol(webAuthnLookupProtocolName(auth), lm.poolName)
	if err != nil {
		return plan, false, err
	}

	if protocol == nil || protocol.GetWebAuthnCredentialField() == "" {
		return plan, false, nil
	}

	filter, err := protocol.GetUserFilter()
	if err != nil {
		return plan, false, err
	}

	baseDN, err := protocol.GetBaseDN()
	if err != nil {
		return plan, false, err
	}

	scope, err := protocol.GetScope()
	if err != nil {
		return plan, false, err
	}

	plan.scope = scope
	plan.replyChan = make(chan *bktype.LDAPReply, 1)
	plan.credentialField = protocol.GetWebAuthnCredentialField()
	plan.username = auth.handleMasterUserMode()
	plan.filter = filter
	plan.baseDN = baseDN
	plan.priority = webAuthnLDAPPriority(auth)

	return plan, true, nil
}

// decodeLDAPWebAuthnCredentials unmarshals credential JSON values from LDAP.
func decodeLDAPWebAuthnCredentials(values []any) []mfa.PersistentCredential {
	credentials := make([]mfa.PersistentCredential, 0, len(values))

	for _, val := range values {
		var cred mfa.PersistentCredential
		if err := jsonIter.Unmarshal([]byte(val.(string)), &cred); err == nil {
			credentials = append(credentials, cred)
		}
	}

	return credentials
}

// logWebAuthnLDAPLookup records the LDAP lookup settings for debugging.
func logWebAuthnLDAPLookup(ctx context.Context, lm *ldapManagerImpl, auth *AuthState, plan webAuthnLDAPCredentialPlan) {
	util.DebugModuleWithCfg(
		ctx,
		lm.effectiveCfg(),
		lm.effectiveLogger(),
		definitions.DbgWebAuthn,
		definitions.LogKeyGUID, auth.Runtime.GUID,
		definitions.LogKeyMsg, "WebAuthn LDAP lookup",
		"pool", lm.poolName,
		"username", plan.username,
		"filter", plan.filter,
		"base_dn", plan.baseDN,
		"scope", *plan.scope,
		"credential_field", plan.credentialField,
	)
}

// logWebAuthnLDAPLookupResult records the LDAP lookup result metadata.
func logWebAuthnLDAPLookupResult(ctx context.Context, lm *ldapManagerImpl, auth *AuthState, ldapReply *bktype.LDAPReply) {
	util.DebugModuleWithCfg(
		ctx,
		lm.effectiveCfg(),
		lm.effectiveLogger(),
		definitions.DbgWebAuthn,
		definitions.LogKeyGUID, auth.Runtime.GUID,
		definitions.LogKeyMsg, "WebAuthn LDAP lookup result",
		definitions.LogKeyError, ldapReply.Err,
		"num_results", len(ldapReply.Result),
	)
}

// runWebAuthnLDAPLookup executes one LDAP credential lookup.
func (lm *ldapManagerImpl) runWebAuthnLDAPLookup(ctx context.Context, auth *AuthState, plan webAuthnLDAPCredentialPlan) ([]mfa.PersistentCredential, error) {
	ctxSearch, cancelSearch := context.WithTimeout(ctx, lm.effectiveCfg().GetServer().GetTimeouts().GetLDAPSearch())
	defer cancelSearch()

	ldapRequest := &bktype.LDAPRequest{
		GUID:     auth.Runtime.GUID,
		Command:  definitions.LDAPSearch,
		PoolName: lm.poolName,
		MacroSource: &util.MacroSource{
			Username: plan.username,
			Protocol: *auth.Request.Protocol,
		},
		Filter:            plan.filter,
		BaseDN:            plan.baseDN,
		SearchAttributes:  []string{plan.credentialField},
		Scope:             *plan.scope,
		LDAPReplyChan:     plan.replyChan,
		HTTPClientContext: ctxSearch,
	}

	lm.ldapQueue().Push(ldapRequest, plan.priority)

	select {
	case <-ctxSearch.Done():
		return nil, errors.ErrLDAPSearchTimeout
	case ldapReply := <-plan.replyChan:
		logWebAuthnLDAPLookupResult(ctx, lm, auth, ldapReply)

		if ldapReply.Err != nil {
			return nil, ldapReply.Err
		}

		if values, ok := ldapReply.Result[plan.credentialField]; ok {
			return decodeLDAPWebAuthnCredentials(values), nil
		}
	}

	return nil, nil
}

// GetWebAuthnCredentials retrieves WebAuthn credentials for the user in the LDAP backend.
func (lm *ldapManagerImpl) GetWebAuthnCredentials(auth *AuthState) (credentials []mfa.PersistentCredential, err error) {
	tr := monittrace.New("nauthilus/ldap")

	lctx, lspan := tr.Start(auth.Ctx(), "ldap.get_webauthn_credentials",
		attribute.String("pool_name", lm.poolName),
		attribute.String("username", auth.Request.Username),
	)
	defer lspan.End()

	plan, ok, err := lm.newWebAuthnLDAPLookupPlan(auth)
	if err != nil {
		return nil, err
	}

	if !ok {
		return []mfa.PersistentCredential{}, nil
	}

	if plan.username == "" {
		util.DebugModuleWithCfg(
			lctx,
			lm.effectiveCfg(),
			lm.effectiveLogger(),
			definitions.DbgWebAuthn,
			definitions.LogKeyGUID, auth.Runtime.GUID,
			definitions.LogKeyMsg, "WebAuthn LDAP lookup skipped: empty username",
			"pool", lm.poolName,
		)

		return nil, nil
	}

	logWebAuthnLDAPLookup(lctx, lm, auth, plan)

	return lm.runWebAuthnLDAPLookup(lctx, auth, plan)
}

// newWebAuthnLDAPCredentialPlan resolves LDAP settings shared by WebAuthn credential mutations.
func (lm *ldapManagerImpl) newWebAuthnLDAPCredentialPlan(auth *AuthState) (webAuthnLDAPCredentialPlan, error) {
	var plan webAuthnLDAPCredentialPlan

	protocol, credentialField, err := lm.webAuthnProtocolAndField(auth)
	if err != nil {
		return plan, err
	}

	filter, err := protocol.GetUserFilter()
	if err != nil {
		return plan, err
	}

	baseDN, err := protocol.GetBaseDN()
	if err != nil {
		return plan, err
	}

	scope, err := protocol.GetScope()
	if err != nil {
		return plan, err
	}

	plan.scope = scope
	plan.replyChan = make(chan *bktype.LDAPReply, 1)
	plan.credentialField = credentialField
	plan.objectClass = protocol.GetWebAuthnObjectClass()
	plan.username = auth.handleMasterUserMode()
	plan.filter = filter
	plan.baseDN = baseDN
	plan.priority = webAuthnLDAPPriority(auth)

	return plan, nil
}

// webAuthnLDAPPriority derives the LDAP queue priority for WebAuthn mutations.
func webAuthnLDAPPriority(auth *AuthState) int {
	if auth.Request.NoAuth {
		return priorityqueue.PriorityLow
	}

	return priorityqueue.PriorityMedium
}

// skipEmptyWebAuthnLDAPUsername logs and reports empty WebAuthn LDAP usernames.
func (lm *ldapManagerImpl) skipEmptyWebAuthnLDAPUsername(ctx context.Context, auth *AuthState, action string, username string) bool {
	if username != "" {
		return false
	}

	util.DebugModuleWithCfg(
		ctx,
		lm.effectiveCfg(),
		lm.effectiveLogger(),
		definitions.DbgWebAuthn,
		definitions.LogKeyGUID, auth.Runtime.GUID,
		definitions.LogKeyMsg, fmt.Sprintf("WebAuthn LDAP %s skipped: empty username", action),
		"pool", lm.poolName,
	)

	return true
}

// fetchWebAuthnObjectClassState checks whether the required WebAuthn objectClass is already present.
func (lm *ldapManagerImpl) fetchWebAuthnObjectClassState(ctx context.Context, auth *AuthState, plan webAuthnLDAPCredentialPlan) (bool, error) {
	currentObjectClasses, err := lm.fetchObjectClasses(ctx, auth, plan.username, plan.filter, plan.baseDN, plan.scope, plan.replyChan, plan.priority)
	if err != nil {
		return false, err
	}

	return hasRequiredObjectClass(plan.objectClass, currentObjectClasses), nil
}

// addMissingWebAuthnObjectClass adds the WebAuthn objectClass when it was absent.
func (lm *ldapManagerImpl) addMissingWebAuthnObjectClass(ctx context.Context, auth *AuthState, plan webAuthnLDAPCredentialPlan, hasObjectClass bool) error {
	if hasObjectClass {
		return nil
	}

	return lm.addObjectClass(ctx, auth, plan.username, plan.filter, plan.baseDN, plan.scope, plan.objectClass, plan.replyChan, plan.priority)
}

// logWebAuthnLDAPSave records the LDAP save settings for debugging.
func (lm *ldapManagerImpl) logWebAuthnLDAPSave(ctx context.Context, auth *AuthState, plan webAuthnLDAPCredentialPlan, hasObjectClass bool) {
	util.DebugModuleWithCfg(
		ctx,
		lm.effectiveCfg(),
		lm.effectiveLogger(),
		definitions.DbgWebAuthn,
		definitions.LogKeyGUID, auth.Runtime.GUID,
		definitions.LogKeyMsg, "WebAuthn LDAP save",
		"pool", lm.poolName,
		"username", plan.username,
		"filter", plan.filter,
		"base_dn", plan.baseDN,
		"scope", *plan.scope,
		"credential_field", plan.credentialField,
		"object_class", plan.objectClass,
		"has_object_class", hasObjectClass,
	)
}

// oldWebAuthnCredentialBytes returns stored raw JSON or marshals the old credential.
func oldWebAuthnCredentialBytes(credential *mfa.PersistentCredential) ([]byte, error) {
	if len(credential.RawJSON) > 0 {
		return []byte(credential.RawJSON), nil
	}

	return jsonIter.Marshal(credential)
}

// webAuthnLDAPCredentialOperation builds one LDAP WebAuthn credential modify operation.
func webAuthnLDAPCredentialOperation(auth *AuthState, plan webAuthnLDAPCredentialPlan, credentialBytes []byte, subCommand definitions.LDAPSubCommand, timeoutDetail string, failureDetail string, ignoreNoSuchAttributeErr bool) webAuthnLDAPModifyOperation {
	return webAuthnLDAPModifyOperation{
		auth:                     auth,
		scope:                    plan.scope,
		replyChan:                plan.replyChan,
		attributes:               webAuthnCredentialModifyAttributes(plan.credentialField, credentialBytes),
		username:                 plan.username,
		filter:                   plan.filter,
		baseDN:                   plan.baseDN,
		timeoutDetail:            timeoutDetail,
		failureDetail:            failureDetail,
		subCommand:               subCommand,
		priority:                 plan.priority,
		ignoreNoSuchAttributeErr: ignoreNoSuchAttributeErr,
	}
}

// SaveWebAuthnCredential saves a WebAuthn credential for the user in the LDAP backend.
func (lm *ldapManagerImpl) SaveWebAuthnCredential(auth *AuthState, credential *mfa.PersistentCredential) (err error) {
	tr := monittrace.New("nauthilus/ldap")

	lctx, lspan := tr.Start(auth.Ctx(), "ldap.save_webauthn_credential",
		attribute.String("pool_name", lm.poolName),
		attribute.String("username", auth.Request.Username),
	)
	defer lspan.End()

	plan, err := lm.newWebAuthnLDAPCredentialPlan(auth)
	if err != nil {
		return err
	}

	if lm.skipEmptyWebAuthnLDAPUsername(lctx, auth, "save", plan.username) {
		return nil
	}

	hasRequiredObjectClassValue, err := lm.fetchWebAuthnObjectClassState(lctx, auth, plan)
	if err != nil {
		return err
	}

	credBytes, err := jsonIter.Marshal(credential)
	if err != nil {
		return err
	}

	lm.logWebAuthnLDAPSave(lctx, auth, plan, hasRequiredObjectClassValue)

	if err := lm.addMissingWebAuthnObjectClass(lctx, auth, plan, hasRequiredObjectClassValue); err != nil {
		return err
	}

	return lm.runWebAuthnLDAPModifyOperation(lctx, webAuthnLDAPModifyOperation{
		auth:          auth,
		scope:         plan.scope,
		replyChan:     plan.replyChan,
		attributes:    webAuthnCredentialModifyAttributes(plan.credentialField, credBytes),
		username:      plan.username,
		filter:        plan.filter,
		baseDN:        plan.baseDN,
		timeoutDetail: "LDAP modify timeout (credential phase)",
		failureDetail: "Failed to save WebAuthn credential",
		debugMessage:  "WebAuthn LDAP save result",
		subCommand:    definitions.LDAPModifyAdd,
		priority:      plan.priority,
	})
}

// DeleteWebAuthnCredential removes a WebAuthn credential for the user in the LDAP backend.
func (lm *ldapManagerImpl) DeleteWebAuthnCredential(auth *AuthState, credential *mfa.PersistentCredential) (err error) {
	tr := monittrace.New("nauthilus/ldap")

	lctx, lspan := tr.Start(auth.Ctx(), "ldap.delete_webauthn_credential",
		attribute.String("pool_name", lm.poolName),
		attribute.String("username", auth.Request.Username),
	)
	defer lspan.End()

	protocol, credentialField, err := lm.webAuthnProtocolAndField(auth)
	if err != nil {
		return err
	}

	filter, err := protocol.GetUserFilter()
	if err != nil {
		return err
	}

	baseDN, err := protocol.GetBaseDN()
	if err != nil {
		return err
	}

	scope, err := protocol.GetScope()
	if err != nil {
		return err
	}

	username := auth.handleMasterUserMode()

	credBytes, err := jsonIter.Marshal(credential)
	if err != nil {
		return err
	}

	ldapReplyChan := make(chan *bktype.LDAPReply, 1)

	priority := priorityqueue.PriorityLow
	if !auth.Request.NoAuth {
		priority = priorityqueue.PriorityMedium
	}

	return lm.runWebAuthnLDAPModifyOperation(lctx, webAuthnLDAPModifyOperation{
		auth:                     auth,
		scope:                    scope,
		replyChan:                ldapReplyChan,
		attributes:               webAuthnCredentialModifyAttributes(credentialField, credBytes),
		username:                 username,
		filter:                   filter,
		baseDN:                   baseDN,
		timeoutDetail:            "LDAP modify timeout",
		failureDetail:            "Failed to delete WebAuthn credential",
		subCommand:               definitions.LDAPModifyDelete,
		priority:                 priority,
		ignoreNoSuchAttributeErr: true,
	})
}

// UpdateWebAuthnCredential updates an existing WebAuthn credential for the user in the LDAP backend.
func (lm *ldapManagerImpl) UpdateWebAuthnCredential(auth *AuthState, oldCredential *mfa.PersistentCredential, newCredential *mfa.PersistentCredential) (err error) {
	tr := monittrace.New("nauthilus/ldap")

	lctx, lspan := tr.Start(auth.Ctx(), "ldap.update_webauthn_credential",
		attribute.String("pool_name", lm.poolName),
		attribute.String("username", auth.Request.Username),
	)
	defer lspan.End()

	plan, err := lm.newWebAuthnLDAPCredentialPlan(auth)
	if err != nil {
		return err
	}

	if lm.skipEmptyWebAuthnLDAPUsername(lctx, auth, "update", plan.username) {
		return nil
	}

	hasRequiredObjectClassValue, err := lm.fetchWebAuthnObjectClassState(lctx, auth, plan)
	if err != nil {
		return err
	}

	oldCredBytes, err := oldWebAuthnCredentialBytes(oldCredential)
	if err != nil {
		return err
	}

	newCredBytes, err := jsonIter.Marshal(newCredential)
	if err != nil {
		return err
	}

	if err := lm.addMissingWebAuthnObjectClass(lctx, auth, plan, hasRequiredObjectClassValue); err != nil {
		return err
	}

	addOperation := webAuthnLDAPCredentialOperation(auth, plan, newCredBytes, definitions.LDAPModifyAdd, "LDAP modify timeout (add phase)", "Failed to add new WebAuthn credential", false)
	if err := lm.runWebAuthnLDAPModifyOperation(lctx, addOperation); err != nil {
		return err
	}

	deleteOperation := webAuthnLDAPCredentialOperation(auth, plan, oldCredBytes, definitions.LDAPModifyDelete, "LDAP modify timeout (delete phase)", "Failed to delete old WebAuthn credential", true)

	return lm.runWebAuthnLDAPModifyOperation(lctx, deleteOperation)
}

type webAuthnLDAPModifyOperation struct {
	auth                     *AuthState
	scope                    *config.LDAPScope
	replyChan                chan *bktype.LDAPReply
	attributes               bktype.LDAPModifyAttributes
	username                 string
	filter                   string
	baseDN                   string
	timeoutDetail            string
	failureDetail            string
	debugMessage             string
	subCommand               definitions.LDAPSubCommand
	priority                 int
	ignoreNoSuchAttributeErr bool
}

// runWebAuthnLDAPModifyOperation enqueues and waits for one WebAuthn LDAP modify request.
func (lm *ldapManagerImpl) runWebAuthnLDAPModifyOperation(ctx context.Context, operation webAuthnLDAPModifyOperation) error {
	ctxModify, cancelModify := context.WithTimeout(ctx, lm.effectiveCfg().GetServer().GetTimeouts().GetLDAPModify())
	defer cancelModify()

	lm.ldapQueue().Push(&bktype.LDAPRequest{
		GUID:       operation.auth.Runtime.GUID,
		Command:    definitions.LDAPModify,
		PoolName:   lm.poolName,
		SubCommand: operation.subCommand,
		MacroSource: &util.MacroSource{
			Username: operation.username,
			Protocol: *operation.auth.Request.Protocol,
		},
		Filter:            operation.filter,
		BaseDN:            operation.baseDN,
		Scope:             *operation.scope,
		ModifyAttributes:  operation.attributes,
		LDAPReplyChan:     operation.replyChan,
		HTTPClientContext: ctxModify,
	}, operation.priority)

	select {
	case <-ctxModify.Done():
		return errors.ErrLDAPModify.WithDetail(operation.timeoutDetail)
	case ldapReply := <-operation.replyChan:
		if operation.debugMessage != "" {
			util.DebugModuleWithCfg(
				ctx,
				lm.effectiveCfg(),
				lm.effectiveLogger(),
				definitions.DbgWebAuthn,
				definitions.LogKeyGUID, operation.auth.Runtime.GUID,
				definitions.LogKeyMsg, operation.debugMessage,
				definitions.LogKeyError, ldapReply.Err,
			)
		}

		if operation.ignoreNoSuchAttributeErr && isNoSuchAttributeError(ldapReply.Err) {
			return nil
		}

		return wrapLDAPModifyError(ldapReply.Err, operation.failureDetail)
	}
}

// webAuthnCredentialModifyAttributes creates the LDAP modify payload for one credential value.
func webAuthnCredentialModifyAttributes(credentialField string, credentialBytes []byte) bktype.LDAPModifyAttributes {
	return bktype.LDAPModifyAttributes{
		credentialField: []string{string(credentialBytes)},
	}
}

func (lm *ldapManagerImpl) fetchObjectClasses(ctx context.Context, auth *AuthState, username string, filter string, baseDN string, scope *config.LDAPScope, ldapReplyChan chan *bktype.LDAPReply, priority int) ([]string, error) {
	ctxSearch, cancelSearch := context.WithTimeout(ctx, lm.effectiveCfg().GetServer().GetTimeouts().GetLDAPSearch())
	defer cancelSearch()

	ldapSearchRequest := &bktype.LDAPRequest{
		GUID:     auth.Runtime.GUID,
		Command:  definitions.LDAPSearch,
		PoolName: lm.poolName,
		MacroSource: &util.MacroSource{
			Username: username,
			Protocol: *auth.Request.Protocol,
		},
		Filter:            filter,
		BaseDN:            baseDN,
		SearchAttributes:  []string{ldapAttributeObjectClass},
		Scope:             *scope,
		LDAPReplyChan:     ldapReplyChan,
		HTTPClientContext: ctxSearch,
	}

	lm.ldapQueue().Push(ldapSearchRequest, priority)

	var currentObjectClasses []string

	select {
	case <-ctxSearch.Done():
		return nil, errors.ErrLDAPSearchTimeout
	case ldapReply := <-ldapReplyChan:
		if ldapReply.Err != nil {
			return nil, wrapLDAPModifyError(ldapReply.Err, "Failed to fetch objectClasses")
		}

		if values, ok := ldapReply.Result[ldapAttributeObjectClass]; ok {
			for _, val := range values {
				if strVal, ok := val.(string); ok {
					currentObjectClasses = append(currentObjectClasses, strVal)
				}
			}
		}
	}

	return currentObjectClasses, nil
}

func hasRequiredObjectClass(objectClass string, currentObjectClasses []string) bool {
	if objectClass == "" {
		return true
	}

	for _, oc := range currentObjectClasses {
		if strings.EqualFold(oc, objectClass) {
			return true
		}
	}

	return false
}

func (lm *ldapManagerImpl) webAuthnProtocolAndField(auth *AuthState) (*config.LDAPSearchProtocol, string, error) {
	protocolName := auth.Request.Protocol.Get()

	protocol, err := lm.effectiveCfg().GetLDAPSearchProtocol(protocolName, lm.poolName)
	if err != nil {
		return nil, "", err
	}

	// This pool does not handle the requested protocol — signal a config mismatch
	// so the caller can skip to the next backend.
	if protocol == nil {
		return nil, "", errors.ErrLDAPConfig.WithDetail(
			fmt.Sprintf("Pool %q has no search protocol for %q", lm.poolName, protocolName))
	}

	credentialField := protocol.GetWebAuthnCredentialField()
	if credentialField == "" {
		return nil, "", errors.ErrLDAPConfig.WithDetail(
			fmt.Sprintf("Pool %q: missing webauthn_credential_field for protocol %q", lm.poolName, protocolName))
	}

	return protocol, credentialField, nil
}

func (lm *ldapManagerImpl) addObjectClass(ctx context.Context, auth *AuthState, username string, filter string, baseDN string, scope *config.LDAPScope, objectClass string, ldapReplyChan chan *bktype.LDAPReply, priority int) error {
	ctxModifyOC, cancelModifyOC := context.WithTimeout(ctx, lm.effectiveCfg().GetServer().GetTimeouts().GetLDAPModify())
	defer cancelModifyOC()

	ocRequest := &bktype.LDAPRequest{
		GUID:       auth.Runtime.GUID,
		Command:    definitions.LDAPModify,
		PoolName:   lm.poolName,
		SubCommand: definitions.LDAPModifyAdd,
		MacroSource: &util.MacroSource{
			Username: username,
			Protocol: *auth.Request.Protocol,
		},
		Filter: filter,
		BaseDN: baseDN,
		Scope:  *scope,
		ModifyAttributes: bktype.LDAPModifyAttributes{
			ldapAttributeObjectClass: []string{objectClass},
		},
		LDAPReplyChan:     ldapReplyChan,
		HTTPClientContext: ctxModifyOC,
	}

	lm.ldapQueue().Push(ocRequest, priority)

	select {
	case <-ctxModifyOC.Done():
		return errors.ErrLDAPModify.WithDetail("LDAP modify timeout (objectClass phase)")
	case ldapReply := <-ldapReplyChan:
		if ldapReply.Err != nil && !isAttributeOrValueExistsError(ldapReply.Err) {
			return wrapLDAPModifyError(ldapReply.Err, "Failed to add objectClass")
		}
	}

	return nil
}
