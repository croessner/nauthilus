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

	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/backend/priorityqueue"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/model/mfa"
	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/croessner/nauthilus/server/util"
	"go.opentelemetry.io/otel/attribute"
)

// GetWebAuthnCredentials retrieves WebAuthn credentials for the user in the LDAP backend.
func (lm *ldapManagerImpl) GetWebAuthnCredentials(auth *AuthState) (credentials []mfa.PersistentCredential, err error) {
	tr := monittrace.New("nauthilus/ldap")
	lctx, lspan := tr.Start(auth.Ctx(), "ldap.get_webauthn_credentials",
		attribute.String("pool_name", lm.poolName),
		attribute.String("username", auth.Request.Username),
	)
	defer lspan.End()

	protocolName := definitions.ProtoIDP

	if auth.Request.Protocol == nil {
		auth.Request.Protocol = config.NewProtocol(protocolName)
	}

	if auth.Request.Protocol != nil {
		if currentProtocol := auth.Request.Protocol.Get(); currentProtocol != "" {
			protocolName = currentProtocol
		} else {
			auth.Request.Protocol.Set(protocolName)
		}
	}

	protocol, err := lm.effectiveCfg().GetLDAPSearchProtocol(protocolName, lm.poolName)
	if err != nil || protocol == nil {
		if err == nil {
			err = errors.ErrLDAPConfig.WithDetail(
				fmt.Sprintf("Missing LDAP search protocol; protocol=%s", protocolName))
		}

		return nil, err
	}

	credentialField := protocol.GetWebAuthnCredentialField()
	if credentialField == "" {
		return []mfa.PersistentCredential{}, nil
	}

	filter, err := protocol.GetUserFilter()
	if err != nil {
		return nil, err
	}

	baseDN, err := protocol.GetBaseDN()
	if err != nil {
		return nil, err
	}

	scope, err := protocol.GetScope()
	if err != nil {
		return nil, err
	}

	username := handleMasterUserMode(lm.effectiveCfg(), auth)

	if username == "" {
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

	util.DebugModuleWithCfg(
		lctx,
		lm.effectiveCfg(),
		lm.effectiveLogger(),
		definitions.DbgWebAuthn,
		definitions.LogKeyGUID, auth.Runtime.GUID,
		definitions.LogKeyMsg, "WebAuthn LDAP lookup",
		"pool", lm.poolName,
		"username", username,
		"filter", filter,
		"base_dn", baseDN,
		"scope", *scope,
		"credential_field", credentialField,
	)

	ldapReplyChan := make(chan *bktype.LDAPReply, 1)
	ctxSearch, cancelSearch := context.WithTimeout(lctx, lm.effectiveCfg().GetServer().GetTimeouts().GetLDAPSearch())
	defer cancelSearch()

	ldapRequest := &bktype.LDAPRequest{
		GUID:     auth.Runtime.GUID,
		Command:  definitions.LDAPSearch,
		PoolName: lm.poolName,
		MacroSource: &util.MacroSource{
			Username: username,
			Protocol: *auth.Request.Protocol,
		},
		Filter:            filter,
		BaseDN:            baseDN,
		SearchAttributes:  []string{credentialField},
		Scope:             *scope,
		LDAPReplyChan:     ldapReplyChan,
		HTTPClientContext: ctxSearch,
	}

	priority := priorityqueue.PriorityLow
	if !auth.Request.NoAuth {
		priority = priorityqueue.PriorityMedium
	}

	priorityqueue.LDAPQueue.Push(ldapRequest, priority)

	select {
	case <-ctxSearch.Done():
		return nil, errors.ErrLDAPSearchTimeout
	case ldapReply := <-ldapReplyChan:
		util.DebugModuleWithCfg(
			lctx,
			lm.effectiveCfg(),
			lm.effectiveLogger(),
			definitions.DbgWebAuthn,
			definitions.LogKeyGUID, auth.Runtime.GUID,
			definitions.LogKeyMsg, "WebAuthn LDAP lookup result",
			definitions.LogKeyError, ldapReply.Err,
			"num_results", len(ldapReply.Result),
		)

		if ldapReply.Err != nil {
			return nil, ldapReply.Err
		}

		if values, ok := ldapReply.Result[credentialField]; ok {
			for _, val := range values {
				var cred mfa.PersistentCredential
				if err := jsonIter.Unmarshal([]byte(val.(string)), &cred); err == nil {
					credentials = append(credentials, cred)
				}
			}
		}
	}

	return credentials, nil
}

// SaveWebAuthnCredential saves a WebAuthn credential for the user in the LDAP backend.
func (lm *ldapManagerImpl) SaveWebAuthnCredential(auth *AuthState, credential *mfa.PersistentCredential) (err error) {
	tr := monittrace.New("nauthilus/ldap")
	lctx, lspan := tr.Start(auth.Ctx(), "ldap.save_webauthn_credential",
		attribute.String("pool_name", lm.poolName),
		attribute.String("username", auth.Request.Username),
	)
	defer lspan.End()

	protocol, credentialField, err := lm.webAuthnProtocolAndField(auth)
	if err != nil {
		return err
	}

	objectClass := protocol.GetWebAuthnObjectClass()

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

	username := handleMasterUserMode(lm.effectiveCfg(), auth)
	if username == "" {
		util.DebugModuleWithCfg(
			lctx,
			lm.effectiveCfg(),
			lm.effectiveLogger(),
			definitions.DbgWebAuthn,
			definitions.LogKeyGUID, auth.Runtime.GUID,
			definitions.LogKeyMsg, "WebAuthn LDAP save skipped: empty username",
			"pool", lm.poolName,
		)

		return nil
	}

	ldapReplyChan := make(chan *bktype.LDAPReply, 1)
	priority := priorityqueue.PriorityLow

	if !auth.Request.NoAuth {
		priority = priorityqueue.PriorityMedium
	}

	// Step 1: Search for user to check current objectClasses
	currentObjectClasses, err := lm.fetchObjectClasses(lctx, auth, username, filter, baseDN, scope, ldapReplyChan, priority)
	if err != nil {
		return err
	}

	hasRequiredObjectClassValue := hasRequiredObjectClass(objectClass, currentObjectClasses)

	credBytes, err := jsonIter.Marshal(credential)
	if err != nil {
		return err
	}

	util.DebugModuleWithCfg(
		lctx,
		lm.effectiveCfg(),
		lm.effectiveLogger(),
		definitions.DbgWebAuthn,
		definitions.LogKeyGUID, auth.Runtime.GUID,
		definitions.LogKeyMsg, "WebAuthn LDAP save",
		"pool", lm.poolName,
		"username", username,
		"filter", filter,
		"base_dn", baseDN,
		"scope", *scope,
		"credential_field", credentialField,
		"object_class", objectClass,
		"has_object_class", hasRequiredObjectClassValue,
	)

	// Step 2: Add objectClass if missing
	if !hasRequiredObjectClassValue {
		if err := lm.addObjectClass(lctx, auth, username, filter, baseDN, scope, objectClass, ldapReplyChan, priority); err != nil {
			return err
		}
	}

	// Step 3: Add the credential
	ctxModifyCred, cancelModifyCred := context.WithTimeout(lctx, lm.effectiveCfg().GetServer().GetTimeouts().GetLDAPModify())
	defer cancelModifyCred()

	credRequest := &bktype.LDAPRequest{
		GUID:       auth.Runtime.GUID,
		Command:    definitions.LDAPModify,
		PoolName:   lm.poolName,
		SubCommand: definitions.LDAPModifyAdd,
		MacroSource: &util.MacroSource{
			Username: username,
			Protocol: *auth.Request.Protocol,
		},
		Filter: baseDN, // Use BaseDN if it's uniquely identified or the same filter
		BaseDN: baseDN,
		Scope:  *scope,
		ModifyAttributes: bktype.LDAPModifyAttributes{
			credentialField: []string{string(credBytes)},
		},
		LDAPReplyChan:     ldapReplyChan,
		HTTPClientContext: ctxModifyCred,
	}
	// Re-using same Filter and BaseDN/Scope as search
	credRequest.Filter = filter

	priorityqueue.LDAPQueue.Push(credRequest, priority)

	select {
	case <-ctxModifyCred.Done():
		return errors.ErrLDAPModify.WithDetail("LDAP modify timeout (credential phase)")
	case ldapReply := <-ldapReplyChan:
		util.DebugModuleWithCfg(
			lctx,
			lm.effectiveCfg(),
			lm.effectiveLogger(),
			definitions.DbgWebAuthn,
			definitions.LogKeyGUID, auth.Runtime.GUID,
			definitions.LogKeyMsg, "WebAuthn LDAP save result",
			definitions.LogKeyError, ldapReply.Err,
		)

		return ldapReply.Err
	}
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

	username := handleMasterUserMode(lm.effectiveCfg(), auth)
	credBytes, err := jsonIter.Marshal(credential)
	if err != nil {
		return err
	}

	ldapReplyChan := make(chan *bktype.LDAPReply, 1)
	ctxModify, cancelModify := context.WithTimeout(lctx, lm.effectiveCfg().GetServer().GetTimeouts().GetLDAPModify())
	defer cancelModify()

	ldapRequest := &bktype.LDAPRequest{
		GUID:       auth.Runtime.GUID,
		Command:    definitions.LDAPModify,
		PoolName:   lm.poolName,
		SubCommand: definitions.LDAPModifyDelete,
		MacroSource: &util.MacroSource{
			Username: username,
			Protocol: *auth.Request.Protocol,
		},
		Filter: filter,
		BaseDN: baseDN,
		Scope:  *scope,
		ModifyAttributes: bktype.LDAPModifyAttributes{
			credentialField: []string{string(credBytes)},
		},
		LDAPReplyChan:     ldapReplyChan,
		HTTPClientContext: ctxModify,
	}

	priority := priorityqueue.PriorityLow
	if !auth.Request.NoAuth {
		priority = priorityqueue.PriorityMedium
	}

	priorityqueue.LDAPQueue.Push(ldapRequest, priority)

	select {
	case <-ctxModify.Done():
		return errors.ErrLDAPModify.WithDetail("LDAP modify timeout")
	case ldapReply := <-ldapReplyChan:
		if isNoSuchAttributeError(ldapReply.Err) {
			return nil
		}

		return ldapReply.Err
	}
}

// UpdateWebAuthnCredential updates an existing WebAuthn credential for the user in the LDAP backend.
func (lm *ldapManagerImpl) UpdateWebAuthnCredential(auth *AuthState, oldCredential *mfa.PersistentCredential, newCredential *mfa.PersistentCredential) (err error) {
	tr := monittrace.New("nauthilus/ldap")
	lctx, lspan := tr.Start(auth.Ctx(), "ldap.update_webauthn_credential",
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

	objectClass := protocol.GetWebAuthnObjectClass()

	username := handleMasterUserMode(lm.effectiveCfg(), auth)
	if username == "" {
		util.DebugModuleWithCfg(
			lctx,
			lm.effectiveCfg(),
			lm.effectiveLogger(),
			definitions.DbgWebAuthn,
			definitions.LogKeyGUID, auth.Runtime.GUID,
			definitions.LogKeyMsg, "WebAuthn LDAP update skipped: empty username",
			"pool", lm.poolName,
		)

		return nil
	}

	ldapReplyChan := make(chan *bktype.LDAPReply, 1)
	priority := priorityqueue.PriorityLow

	if !auth.Request.NoAuth {
		priority = priorityqueue.PriorityMedium
	}

	// Step 1: Search for user to check current objectClasses
	currentObjectClasses, err := lm.fetchObjectClasses(lctx, auth, username, filter, baseDN, scope, ldapReplyChan, priority)
	if err != nil {
		return err
	}

	hasRequiredObjectClassValue := hasRequiredObjectClass(objectClass, currentObjectClasses)

	oldCredBytes := []byte(oldCredential.RawJSON)
	if len(oldCredBytes) == 0 {
		oldCredBytes, err = jsonIter.Marshal(oldCredential)
		if err != nil {
			return err
		}
	}

	newCredBytes, err := jsonIter.Marshal(newCredential)
	if err != nil {
		return err
	}

	// Step 2: Add objectClass if missing
	if !hasRequiredObjectClassValue {
		if err := lm.addObjectClass(lctx, auth, username, filter, baseDN, scope, objectClass, ldapReplyChan, priority); err != nil {
			return err
		}
	}

	// Step 3: Add new credential
	ctxAdd, cancelAdd := context.WithTimeout(lctx, lm.effectiveCfg().GetServer().GetTimeouts().GetLDAPModify())
	defer cancelAdd()

	addModifyAttributes := bktype.LDAPModifyAttributes{
		credentialField: []string{string(newCredBytes)},
	}

	addRequest := &bktype.LDAPRequest{
		GUID:       auth.Runtime.GUID,
		Command:    definitions.LDAPModify,
		PoolName:   lm.poolName,
		SubCommand: definitions.LDAPModifyAdd,
		MacroSource: &util.MacroSource{
			Username: username,
			Protocol: *auth.Request.Protocol,
		},
		Filter:            filter,
		BaseDN:            baseDN,
		Scope:             *scope,
		ModifyAttributes:  addModifyAttributes,
		LDAPReplyChan:     ldapReplyChan,
		HTTPClientContext: ctxAdd,
	}

	priorityqueue.LDAPQueue.Push(addRequest, priority)

	select {
	case <-ctxAdd.Done():
		return errors.ErrLDAPModify.WithDetail("LDAP modify timeout (add phase)")
	case ldapReply := <-ldapReplyChan:
		if ldapReply.Err != nil {
			return ldapReply.Err
		}
	}

	// Step 4: Delete old credential
	ctxDelete, cancelDelete := context.WithTimeout(lctx, lm.effectiveCfg().GetServer().GetTimeouts().GetLDAPModify())
	defer cancelDelete()

	deleteModifyAttributes := bktype.LDAPModifyAttributes{
		credentialField: []string{string(oldCredBytes)},
	}

	deleteRequest := &bktype.LDAPRequest{
		GUID:       auth.Runtime.GUID,
		Command:    definitions.LDAPModify,
		PoolName:   lm.poolName,
		SubCommand: definitions.LDAPModifyDelete,
		MacroSource: &util.MacroSource{
			Username: username,
			Protocol: *auth.Request.Protocol,
		},
		Filter:            filter,
		BaseDN:            baseDN,
		Scope:             *scope,
		ModifyAttributes:  deleteModifyAttributes,
		LDAPReplyChan:     ldapReplyChan,
		HTTPClientContext: ctxDelete,
	}

	priorityqueue.LDAPQueue.Push(deleteRequest, priority)

	select {
	case <-ctxDelete.Done():
		return errors.ErrLDAPModify.WithDetail("LDAP modify timeout (delete phase)")
	case ldapReply := <-ldapReplyChan:
		if isNoSuchAttributeError(ldapReply.Err) {
			return nil
		}

		return ldapReply.Err
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
		SearchAttributes:  []string{"objectClass"},
		Scope:             *scope,
		LDAPReplyChan:     ldapReplyChan,
		HTTPClientContext: ctxSearch,
	}

	priorityqueue.LDAPQueue.Push(ldapSearchRequest, priority)

	var currentObjectClasses []string
	select {
	case <-ctxSearch.Done():
		return nil, errors.ErrLDAPSearchTimeout
	case ldapReply := <-ldapReplyChan:
		if ldapReply.Err != nil {
			return nil, ldapReply.Err
		}

		if values, ok := ldapReply.Result["objectClass"]; ok {
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
	if err != nil || protocol == nil {
		if err == nil {
			err = errors.ErrLDAPConfig.WithDetail(
				fmt.Sprintf("Missing LDAP search protocol; protocol=%s", protocolName))
		}

		return nil, "", err
	}

	credentialField := protocol.GetWebAuthnCredentialField()
	if credentialField == "" {
		return nil, "", errors.ErrLDAPConfig.WithDetail("Missing LDAP webauthn_credential_field mapping")
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
			"objectClass": []string{objectClass},
		},
		LDAPReplyChan:     ldapReplyChan,
		HTTPClientContext: ctxModifyOC,
	}

	priorityqueue.LDAPQueue.Push(ocRequest, priority)

	select {
	case <-ctxModifyOC.Done():
		return errors.ErrLDAPModify.WithDetail("LDAP modify timeout (objectClass phase)")
	case ldapReply := <-ldapReplyChan:
		if ldapReply.Err != nil && !isAttributeOrValueExistsError(ldapReply.Err) {
			return ldapReply.Err
		}
	}

	return nil
}
