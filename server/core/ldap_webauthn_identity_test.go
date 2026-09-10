// Copyright 2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package core

import (
	"testing"

	"github.com/croessner/nauthilus/v4/server/backend/bktype"
	"github.com/croessner/nauthilus/v4/server/backend/priorityqueue"
	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/model/mfa"
	"github.com/stretchr/testify/assert"
)

// TestLDAPWebAuthnDeleteUsesStoredValues reproduces deletion after cache JSON normalization.
func TestLDAPWebAuthnDeleteUsesStoredValues(t *testing.T) {
	lm, deps, _ := newLDAPWebAuthnTestManager(t.Name(), definitions.ProtoIDP)
	auth := newLDAPWebAuthnTestAuth(deps, definitions.ProtoIDP)
	values := []string{`{ "id": "dGVzdC1pZA==", "name": "Key", "signCount": 1 }`,
		`{ "id": "dGVzdC1pZA==", "name": "Key", "signCount": 2 }`}

	var credential mfa.PersistentCredential
	assert.NoError(t, jsonIter.Unmarshal([]byte(values[0]), &credential))

	requests := make(chan *bktype.LDAPRequest, 1)

	go func() {
		request := priorityqueue.LDAPQueue.Pop(t.Name())
		if request.Command == definitions.LDAPSearch {
			request.LDAPReplyChan <- &bktype.LDAPReply{Result: bktype.AttributeMapping{
				"nauthilusFido2Credential": {values[0], values[1], `{"id":"b3RoZXI="}`},
			}}

			request = priorityqueue.LDAPQueue.Pop(t.Name())
		}

		requests <- request

		request.LDAPReplyChan <- &bktype.LDAPReply{}
	}()

	assert.NoError(t, lm.DeleteWebAuthnCredential(auth, &credential))

	request := <-requests
	assert.Equal(t, definitions.LDAPModifyDelete, request.SubCommand)
	assert.Equal(t, values, request.ModifyAttributes["nauthilusFido2Credential"])
}
