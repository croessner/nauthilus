// Copyright (C) 2026 Christian Rößner
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
	"testing"

	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/secret"
	"github.com/croessner/nauthilus/server/security"
)

func TestMasterUserTOTPSecretDecryptOrder(t *testing.T) {
	manager := security.NewManager(secret.New("testsecret12345678"))

	encrypted, err := manager.Encrypt("totp-secret")
	if err != nil {
		t.Fatalf("expected encryption to succeed, got error: %v", err)
	}

	attributes := bktype.AttributeMapping{
		"totp_secret": {encrypted},
	}
	ldapReply := &bktype.LDAPReply{Result: attributes}

	totpSecretPre := saveMasterUserTOTPSecret(true, ldapReply, "totp_secret")

	if err := decryptLDAPAttributeValues(manager, attributes, "totp_secret"); err != nil {
		t.Fatalf("expected attribute decryption to succeed, got error: %v", err)
	}

	decrypted, err := decryptLDAPAttributeValue(manager, totpSecretPre)
	if err != nil {
		t.Fatalf("expected master-user secret decryption to succeed, got error: %v", err)
	}

	values, ok := decrypted.([]any)
	if !ok {
		t.Fatalf("expected decrypted value to be []any, got %T", decrypted)
	}
	if len(values) != 1 {
		t.Fatalf("expected decrypted value to have one element, got %d", len(values))
	}

	secret, ok := values[0].(string)
	if !ok {
		t.Fatalf("expected decrypted value to be string, got %T", values[0])
	}
	if secret != "totp-secret" {
		t.Fatalf("expected decrypted value to match, got %q", secret)
	}
}
