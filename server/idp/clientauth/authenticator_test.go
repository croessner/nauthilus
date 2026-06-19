// Copyright (C) 2025 Christian Rößner
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

package clientauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/idp/signing"
	"github.com/croessner/nauthilus/v3/server/secret"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

const privateKeyJWTTestClaimNotBefore = "nbf"

func TestClientSecretAuthenticator_Basic(t *testing.T) {
	auth := NewClientSecretAuthenticator(secret.New("my-secret"), MethodClientSecretBasic)
	assert.Equal(t, MethodClientSecretBasic, auth.Method())

	t.Run("valid secret", func(t *testing.T) {
		err := auth.Authenticate(&AuthRequest{
			ClientID:     "client1",
			ClientSecret: secret.New("my-secret"),
		})
		assert.NoError(t, err)
	})

	t.Run("invalid secret", func(t *testing.T) {
		err := auth.Authenticate(&AuthRequest{
			ClientID:     "client1",
			ClientSecret: secret.New("wrong-secret"),
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "mismatch")
	})

	t.Run("empty secret", func(t *testing.T) {
		err := auth.Authenticate(&AuthRequest{
			ClientID:     "client1",
			ClientSecret: secret.Value{},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "empty")
	})

	t.Run("nil request", func(t *testing.T) {
		err := auth.Authenticate(nil)
		assert.Error(t, err)
	})
}

func TestClientSecretAuthenticator_Post(t *testing.T) {
	auth := NewClientSecretAuthenticator(secret.New("post-secret"), MethodClientSecretPost)
	assert.Equal(t, MethodClientSecretPost, auth.Method())

	err := auth.Authenticate(&AuthRequest{
		ClientID:     "client1",
		ClientSecret: secret.New("post-secret"),
	})
	assert.NoError(t, err)
}

func TestPrivateKeyJWTAuthenticator_RS256(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	clientID := "my-client"
	tokenEndpoint := "https://issuer.local/idp/oidc/token"

	verifier := signing.NewRS256Verifier(&key.PublicKey)
	auth := NewPrivateKeyJWTAuthenticator(verifier, clientID, tokenEndpoint)
	assert.Equal(t, MethodPrivateKeyJWT, auth.Method())

	t.Run("valid assertion", func(t *testing.T) {
		signer := signing.NewRS256Signer(key, "test-kid")

		assertion, err := signer.Sign(jwt.MapClaims{
			"iss": clientID,
			"sub": clientID,
			"aud": tokenEndpoint,
			"exp": time.Now().Add(5 * time.Minute).Unix(),
			"iat": time.Now().Unix(),
			"jti": "unique-id-1",
		})
		if !assert.NoError(t, err) {
			return
		}

		err = auth.Authenticate(&AuthRequest{
			ClientID:            clientID,
			ClientAssertionType: AssertionTypeJWTBearer,
			ClientAssertion:     assertion,
			TokenEndpointURL:    tokenEndpoint,
		})
		assert.NoError(t, err)
	})

	t.Run("wrong assertion type", func(t *testing.T) {
		err := auth.Authenticate(&AuthRequest{
			ClientID:            clientID,
			ClientAssertionType: "wrong-type",
			ClientAssertion:     "some-jwt",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported")
	})

	t.Run("empty assertion", func(t *testing.T) {
		err := auth.Authenticate(&AuthRequest{
			ClientID:            clientID,
			ClientAssertionType: AssertionTypeJWTBearer,
			ClientAssertion:     "",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "empty")
	})

	t.Run("wrong issuer", func(t *testing.T) {
		signer := signing.NewRS256Signer(key, "test-kid")

		assertion, err := signer.Sign(jwt.MapClaims{
			"iss": "wrong-client",
			"sub": clientID,
			"aud": tokenEndpoint,
			"exp": time.Now().Add(5 * time.Minute).Unix(),
		})
		if !assert.NoError(t, err) {
			return
		}

		err = auth.Authenticate(&AuthRequest{
			ClientID:            clientID,
			ClientAssertionType: AssertionTypeJWTBearer,
			ClientAssertion:     assertion,
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "iss")
	})

	t.Run("wrong subject", func(t *testing.T) {
		signer := signing.NewRS256Signer(key, "test-kid")

		assertion, err := signer.Sign(jwt.MapClaims{
			"iss": clientID,
			"sub": "wrong-client",
			"aud": tokenEndpoint,
			"exp": time.Now().Add(5 * time.Minute).Unix(),
		})
		if !assert.NoError(t, err) {
			return
		}

		err = auth.Authenticate(&AuthRequest{
			ClientID:            clientID,
			ClientAssertionType: AssertionTypeJWTBearer,
			ClientAssertion:     assertion,
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "sub")
	})

	t.Run("wrong audience", func(t *testing.T) {
		signer := signing.NewRS256Signer(key, "test-kid")

		assertion, err := signer.Sign(jwt.MapClaims{
			"iss": clientID,
			"sub": clientID,
			"aud": "https://wrong.local/token",
			"exp": time.Now().Add(5 * time.Minute).Unix(),
		})
		if !assert.NoError(t, err) {
			return
		}

		err = auth.Authenticate(&AuthRequest{
			ClientID:            clientID,
			ClientAssertionType: AssertionTypeJWTBearer,
			ClientAssertion:     assertion,
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "aud")
	})

	t.Run("expired assertion", func(t *testing.T) {
		signer := signing.NewRS256Signer(key, "test-kid")

		assertion, err := signer.Sign(jwt.MapClaims{
			"iss": clientID,
			"sub": clientID,
			"aud": tokenEndpoint,
			"exp": time.Now().Add(-5 * time.Minute).Unix(),
		})
		if !assert.NoError(t, err) {
			return
		}

		err = auth.Authenticate(&AuthRequest{
			ClientID:            clientID,
			ClientAssertionType: AssertionTypeJWTBearer,
			ClientAssertion:     assertion,
		})
		assert.Error(t, err)
	})

	t.Run("recently expired assertion within clock skew", func(t *testing.T) {
		signer := signing.NewRS256Signer(key, "test-kid")
		now := time.Now()

		assertion, err := signer.Sign(jwt.MapClaims{
			"iss": clientID,
			"sub": clientID,
			"aud": tokenEndpoint,
			"exp": now.Add(-defaultPrivateKeyJWTClockSkew / 2).Unix(),
			"iat": now.Add(-time.Minute).Unix(),
			"jti": "recently-expired-jti",
		})
		if !assert.NoError(t, err) {
			return
		}

		err = auth.Authenticate(&AuthRequest{
			ClientID:            clientID,
			ClientAssertionType: AssertionTypeJWTBearer,
			ClientAssertion:     assertion,
		})
		assert.NoError(t, err)
	})

	t.Run("nil request", func(t *testing.T) {
		err := auth.Authenticate(nil)
		assert.Error(t, err)
	})
}

func TestPrivateKeyJWTAuthenticator_EdDSA(t *testing.T) {
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	clientID := "eddsa-client"
	tokenEndpoint := "https://issuer.local/idp/oidc/token"

	pubKey := edKey.Public().(ed25519.PublicKey)
	verifier := signing.NewEdDSAVerifier(pubKey)
	auth := NewPrivateKeyJWTAuthenticator(verifier, clientID, tokenEndpoint)

	t.Run("valid EdDSA assertion", func(t *testing.T) {
		signer := signing.NewEdDSASigner(edKey, "ed-kid")

		assertion, err := signer.Sign(jwt.MapClaims{
			"iss": clientID,
			"sub": clientID,
			"aud": tokenEndpoint,
			"exp": time.Now().Add(5 * time.Minute).Unix(),
			"iat": time.Now().Unix(),
			"jti": "unique-id-2",
		})
		if !assert.NoError(t, err) {
			return
		}

		err = auth.Authenticate(&AuthRequest{
			ClientID:            clientID,
			ClientAssertionType: AssertionTypeJWTBearer,
			ClientAssertion:     assertion,
			TokenEndpointURL:    tokenEndpoint,
		})
		assert.NoError(t, err)
	})

	t.Run("wrong key", func(t *testing.T) {
		// Sign with a different key
		_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
		signer := signing.NewEdDSASigner(otherKey, "other-kid")

		assertion, err := signer.Sign(jwt.MapClaims{
			"iss": clientID,
			"sub": clientID,
			"aud": tokenEndpoint,
			"exp": time.Now().Add(5 * time.Minute).Unix(),
		})
		if !assert.NoError(t, err) {
			return
		}

		err = auth.Authenticate(&AuthRequest{
			ClientID:            clientID,
			ClientAssertionType: AssertionTypeJWTBearer,
			ClientAssertion:     assertion,
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "verification failed")
	})
}

func TestPrivateKeyJWTAuthenticator_AudienceArray(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	clientID := "array-aud-client"
	tokenEndpoint := "https://issuer.local/idp/oidc/token"

	verifier := signing.NewRS256Verifier(&key.PublicKey)
	auth := NewPrivateKeyJWTAuthenticator(verifier, clientID, tokenEndpoint)

	signer := signing.NewRS256Signer(key, "test-kid")

	assertion, err := signer.Sign(jwt.MapClaims{
		"iss": clientID,
		"sub": clientID,
		"aud": []string{tokenEndpoint, "https://other.local"},
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"iat": time.Now().Unix(),
		"jti": "audience-array-jti",
	})
	if !assert.NoError(t, err) {
		return
	}

	err = auth.Authenticate(&AuthRequest{
		ClientID:            clientID,
		ClientAssertionType: AssertionTypeJWTBearer,
		ClientAssertion:     assertion,
	})
	assert.NoError(t, err)
}

func TestPrivateKeyJWTAuthenticator_ReplayClaimRequirements(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	clientID := "replay-client"
	tokenEndpoint := "https://issuer.local/idp/oidc/token"
	verifier := signing.NewRS256Verifier(&key.PublicKey)
	auth := NewPrivateKeyJWTAuthenticator(verifier, clientID, tokenEndpoint)
	now := time.Now()

	for _, tc := range privateKeyJWTReplayClaimRequirementCases(clientID, tokenEndpoint, now) {
		t.Run(tc.name, func(t *testing.T) {
			assertion := signPrivateKeyJWTTestAssertion(t, key, tc.claims)

			err := auth.Authenticate(&AuthRequest{
				ClientID:            clientID,
				ClientAssertionType: AssertionTypeJWTBearer,
				ClientAssertion:     assertion,
				TokenEndpointURL:    tokenEndpoint,
			})

			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.errContains)
		})
	}
}

type privateKeyJWTReplayClaimRequirementCase struct {
	name        string
	claims      jwt.MapClaims
	errContains string
}

// privateKeyJWTReplayClaimRequirementCases returns invalid replay claim fixtures.
func privateKeyJWTReplayClaimRequirementCases(clientID string, tokenEndpoint string, now time.Time) []privateKeyJWTReplayClaimRequirementCase {
	return []privateKeyJWTReplayClaimRequirementCase{
		{
			name: "missing jti",
			claims: privateKeyJWTTestClaims(clientID, tokenEndpoint, now, map[string]any{
				"jti": nil,
			}),
			errContains: "jti",
		},
		{
			name: "empty jti",
			claims: privateKeyJWTTestClaims(clientID, tokenEndpoint, now, map[string]any{
				"jti": "   ",
			}),
			errContains: "jti",
		},
		{
			name: "assertion lifetime beyond maximum",
			claims: privateKeyJWTTestClaims(clientID, tokenEndpoint, now, map[string]any{
				"exp": now.Add(defaultPrivateKeyJWTMaxAssertionLifetime + time.Minute).Unix(),
			}),
			errContains: "lifetime",
		},
		{
			name: "iat too far in the future",
			claims: privateKeyJWTTestClaims(clientID, tokenEndpoint, now, map[string]any{
				"iat": now.Add(defaultPrivateKeyJWTClockSkew + time.Minute).Unix(),
				"exp": now.Add(defaultPrivateKeyJWTMaxAssertionLifetime).Unix(),
			}),
			errContains: "iat",
		},
		{
			name: "nbf too far in the future",
			claims: privateKeyJWTTestClaims(clientID, tokenEndpoint, now, map[string]any{
				privateKeyJWTTestClaimNotBefore: now.Add(defaultPrivateKeyJWTClockSkew + time.Minute).Unix(),
			}),
			errContains: privateKeyJWTTestClaimNotBefore,
		},
	}
}

// privateKeyJWTTestClaims builds baseline claims for private_key_jwt tests.
func privateKeyJWTTestClaims(clientID string, audience string, now time.Time, overrides map[string]any) jwt.MapClaims {
	claims := jwt.MapClaims{
		"iss": clientID,
		"sub": clientID,
		"aud": audience,
		"exp": now.Add(time.Minute).Unix(),
		"iat": now.Unix(),
		"jti": "test-jti",
	}

	for key, value := range overrides {
		if value == nil {
			delete(claims, key)

			continue
		}

		claims[key] = value
	}

	return claims
}

// signPrivateKeyJWTTestAssertion signs claims with the test RSA key.
func signPrivateKeyJWTTestAssertion(t testing.TB, key *rsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()

	signer := signing.NewRS256Signer(key, "test-kid")

	assertion, err := signer.Sign(claims)
	if err != nil {
		t.Fatalf("sign client assertion: %v", err)
	}

	return assertion
}
