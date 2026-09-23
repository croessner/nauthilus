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

package idp

import (
	"testing"
)

// TestValidateTokenReusesVerificationKeyButRechecksRevocation pins that repeated validation reads the signing key
// once while the user epoch and the denylist are still read from Redis for every token.
func TestValidateTokenReusesVerificationKeyButRechecksRevocation(t *testing.T) {
	const (
		kid         = "cached-verification-key"
		validations = 3
	)

	pemData := generateTestKey()
	idp, mock, _ := newTestIDPWithMock(t, classificationOIDCConfig())
	token := signedTestAccessToken(t, kid, pemData)

	mock.ExpectHGet(testOIDCKeysHashKey(), kid).SetVal(redisKeyMetadataJSON(t, kid, pemData))

	for range validations {
		expectUserTokenEpoch(mock, testUserID)
		expectDeniedAccessTokenLookup(mock, token, false)
	}

	for range validations {
		if _, err := idp.ValidateToken(t.Context(), token); err != nil {
			t.Fatalf("ValidateToken() error = %v", err)
		}
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("Redis expectations: %v", err)
	}
}
