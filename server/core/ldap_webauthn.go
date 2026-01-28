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

	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/backend/priorityqueue"
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

	protocol, err := lm.effectiveCfg().GetLDAPSearchProtocol(auth.Request.Protocol.Get(), lm.poolName)
	if err != nil || protocol == nil {
		return nil, err
	}

	credentialField := protocol.GetCredentialObject()
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

	protocol, err := lm.effectiveCfg().GetLDAPSearchProtocol(auth.Request.Protocol.Get(), lm.poolName)
	if err != nil || protocol == nil {
		return err
	}

	credentialField := protocol.GetCredentialObject()
	if credentialField == "" {
		return errors.ErrLDAPConfig.WithDetail("Missing LDAP credential_object mapping")
	}

	filter, err := protocol.GetUserFilter()
	if err != nil {
		return err
	}

	baseDN, err := protocol.GetBaseDN()
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
		SubCommand: definitions.LDAPModifyAdd,
		MacroSource: &util.MacroSource{
			Username: username,
			Protocol: *auth.Request.Protocol,
		},
		Filter: filter,
		BaseDN: baseDN,
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

	protocol, err := lm.effectiveCfg().GetLDAPSearchProtocol(auth.Request.Protocol.Get(), lm.poolName)
	if err != nil || protocol == nil {
		return err
	}

	credentialField := protocol.GetCredentialObject()
	if credentialField == "" {
		return errors.ErrLDAPConfig.WithDetail("Missing LDAP credential_object mapping")
	}

	filter, err := protocol.GetUserFilter()
	if err != nil {
		return err
	}

	baseDN, err := protocol.GetBaseDN()
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

	protocol, err := lm.effectiveCfg().GetLDAPSearchProtocol(auth.Request.Protocol.Get(), lm.poolName)
	if err != nil || protocol == nil {
		return err
	}

	credentialField := protocol.GetCredentialObject()
	if credentialField == "" {
		return errors.ErrLDAPConfig.WithDetail("Missing LDAP credential_object mapping")
	}

	filter, err := protocol.GetUserFilter()
	if err != nil {
		return err
	}

	baseDN, err := protocol.GetBaseDN()
	if err != nil {
		return err
	}

	username := handleMasterUserMode(lm.effectiveCfg(), auth)

	oldCredBytes, err := jsonIter.Marshal(oldCredential)
	if err != nil {
		return err
	}

	newCredBytes, err := jsonIter.Marshal(newCredential)
	if err != nil {
		return err
	}

	ldapReplyChan := make(chan *bktype.LDAPReply, 1)

	// Step 1: Delete old credential
	ctxDelete, cancelDelete := context.WithTimeout(lctx, lm.effectiveCfg().GetServer().GetTimeouts().GetLDAPModify())
	defer cancelDelete()

	deleteRequest := &bktype.LDAPRequest{
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
		ModifyAttributes: bktype.LDAPModifyAttributes{
			credentialField: []string{string(oldCredBytes)},
		},
		LDAPReplyChan:     ldapReplyChan,
		HTTPClientContext: ctxDelete,
	}

	priority := priorityqueue.PriorityLow
	if !auth.Request.NoAuth {
		priority = priorityqueue.PriorityMedium
	}

	priorityqueue.LDAPQueue.Push(deleteRequest, priority)

	select {
	case <-ctxDelete.Done():
		return errors.ErrLDAPModify.WithDetail("LDAP modify timeout (delete phase)")
	case ldapReply := <-ldapReplyChan:
		if ldapReply.Err != nil {
			return ldapReply.Err
		}
	}

	// Step 2: Add new credential
	ctxAdd, cancelAdd := context.WithTimeout(lctx, lm.effectiveCfg().GetServer().GetTimeouts().GetLDAPModify())
	defer cancelAdd()

	addRequest := &bktype.LDAPRequest{
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
		ModifyAttributes: bktype.LDAPModifyAttributes{
			credentialField: []string{string(newCredBytes)},
		},
		LDAPReplyChan:     ldapReplyChan,
		HTTPClientContext: ctxAdd,
	}

	priorityqueue.LDAPQueue.Push(addRequest, priority)

	select {
	case <-ctxAdd.Done():
		return errors.ErrLDAPModify.WithDetail("LDAP modify timeout (add phase)")
	case ldapReply := <-ldapReplyChan:
		return ldapReply.Err
	}
}
