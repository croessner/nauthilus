// Copyright 2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"crypto/subtle"
	"fmt"

	"github.com/croessner/nauthilus/v4/server/backend/bktype"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/log/level"
	monittrace "github.com/croessner/nauthilus/v4/server/monitoring/trace"
	"github.com/croessner/nauthilus/v4/server/security"
)

var _ TOTPRecoveryCodeConsumer = (*ldapManagerImpl)(nil)

// ConsumeTOTPRecoveryCode deletes exact stored values atomically, so concurrent reuse fails.
func (lm *ldapManagerImpl) ConsumeTOTPRecoveryCode(auth *AuthState, code string) (bool, int, error) {
	tr := monittrace.New("nauthilus/ldap")

	ctx, span := tr.Start(auth.Ctx(), "ldap.consume_totp_recovery")
	defer span.End()

	plan, end, err := lm.prepareLDAPAttributeReplace(ctx, auth, span, tr, ldapAttributeReplaceParams{
		prepareSpan:           "ldap.consume_totp_recovery.prepare",
		missingProtocolDetail: ldapMissingTOTPRecoveryProtocolDetail,
		missingFieldDetail:    ldapMissingTOTPRecoveryFieldDetail,
		fieldGetter:           (*config.LDAPSearchProtocol).GetTotpRecoveryField,
	})
	if err != nil {
		return false, 0, err
	}

	if end == nil {
		return false, 0, fmt.Errorf("recovery consume: missing LDAP configuration")
	}

	end()

	reply := lm.readStoredRecoveryValues(auth, plan)
	if reply.Err != nil {
		return false, 0, reply.Err
	}

	values := reply.Result[plan.configField]

	matched, err := lm.matchStoredRecoveryCodes(values, code)
	if err != nil || len(matched) == 0 {
		return false, len(values), err
	}

	dn, err := recoveryLDAPIdentityDN(auth, reply.Result)
	if err != nil {
		return false, 0, err
	}

	err = lm.deleteStoredRecoveryValues(auth, plan, dn, matched)
	if isNoSuchAttributeError(err) {
		return false, len(values), nil
	}

	if err != nil {
		return false, len(values), fmt.Errorf("recovery consume: LDAP delete failed")
	}

	return true, len(values) - len(matched), nil
}

// readStoredRecoveryValues bypasses cached passdb state and reads the authoritative recovery attribute.
func (lm *ldapManagerImpl) readStoredRecoveryValues(auth *AuthState, plan ldapAttributeReplacePlan) *bktype.LDAPReply {
	requestCtx, cancel := lm.ldapModifyContext()
	defer cancel()

	replies := make(chan *bktype.LDAPReply, 1)
	request := lm.newLDAPReplaceAttributeRequest(requestCtx, auth, plan, replies, nil, false)
	request.Command = definitions.LDAPSearch
	request.ModifyAttributes = nil

	request.SearchAttributes = []string{plan.configField}
	if field := auth.GetUniqueUserIDField(); field != "" {
		request.SearchAttributes = append(request.SearchAttributes, field)
	}

	lm.ldapQueue().Push(request, lm.requestPriority(auth))

	return waitLDAPReply(requestCtx, monittrace.New("nauthilus/ldap"), "ldap.consume_totp_recovery.read", replies)
}

// deleteStoredRecoveryValues submits a single atomic modify against the freshly resolved DN.
func (lm *ldapManagerImpl) deleteStoredRecoveryValues(auth *AuthState, plan ldapAttributeReplacePlan, dn string, values []string) error {
	ctx, cancel := lm.ldapModifyContext()
	defer cancel()

	replies := make(chan *bktype.LDAPReply, 1)
	request := lm.newLDAPReplaceAttributeRequest(ctx, auth, plan, replies, values, false)
	request.SubCommand = definitions.LDAPModifyDelete
	request.ModifyDN = dn
	lm.ldapQueue().Push(request, lm.requestPriority(auth))

	return waitLDAPReply(ctx, monittrace.New("nauthilus/ldap"), "ldap.consume_totp_recovery.delete", replies).Err
}

// matchStoredRecoveryCodes preserves ciphertext for exact-value deletion, including duplicate plaintext codes.
func (lm *ldapManagerImpl) matchStoredRecoveryCodes(values []any, code string) ([]string, error) {
	manager := security.NewManager(lm.effectiveCfg().GetLDAPConfigEncryptionSecret())
	matched := make([]string, 0, 1)

	for _, value := range values {
		raw, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("recovery consume: invalid stored value")
		}

		decoded, _, err := decryptLDAPScalarAttribute(manager, raw)
		if err != nil {
			level.Warn(lm.effectiveLogger()).Log(definitions.LogKeyMsg, "Recovery consume: skipping undecryptable stored value")

			continue
		}

		if plaintext, ok := decoded.(string); ok && subtle.ConstantTimeCompare([]byte(plaintext), []byte(code)) == 1 {
			matched = append(matched, raw)
		}
	}

	return matched, nil
}

// recoveryLDAPIdentityDN binds the atomic delete to the one freshly resolved directory identity.
func recoveryLDAPIdentityDN(auth *AuthState, attributes bktype.AttributeMapping) (string, error) {
	values := attributes[definitions.DistinguishedName]
	if len(values) != 1 {
		return "", fmt.Errorf("recovery consume: ambiguous LDAP identity")
	}

	dn, ok := values[0].(string)
	if !ok || dn == "" {
		return "", fmt.Errorf("recovery consume: missing LDAP identity")
	}

	if id := auth.GetUniqueUserID(); id != "" {
		identifiers := attributes[auth.GetUniqueUserIDField()]
		if len(identifiers) != 1 || identifiers[0] != id {
			return "", fmt.Errorf("recovery consume: LDAP identity changed")
		}
	}

	return dn, nil
}
