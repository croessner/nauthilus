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

// assertPrivateKeyJWTAuthenticates signs and verifies a valid private_key_jwt request.
func assertPrivateKeyJWTAuthenticates(
	t *testing.T,
	auth ClientAuthenticator,
	signer signing.Signer,
	clientID string,
	tokenEndpoint string,
	jti string,
) {
	t.Helper()

	assertion, err := signer.Sign(jwt.MapClaims{
		"iss": clientID,
		"sub": clientID,
		"aud": tokenEndpoint,
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"iat": time.Now().Unix(),
		"jti": jti,
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
}

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
	fixture := newRS256PrivateKeyJWTFixture(t)
	assert.Equal(t, MethodPrivateKeyJWT, fixture.auth.Method())

	t.Run("valid assertion", func(t *testing.T) {
		signer := signing.NewRS256Signer(fixture.key, "test-kid")

		assertPrivateKeyJWTAuthenticates(t, fixture.auth, signer, fixture.clientID, fixture.tokenEndpoint, "unique-id-1")
	})

	runRS256PrivateKeyJWTNegativeAssertions(t, fixture)
}

// runRS256PrivateKeyJWTNegativeAssertions verifies failing RS256 private_key_jwt paths.
func runRS256PrivateKeyJWTNegativeAssertions(t *testing.T, fixture privateKeyJWTFixture) {
	t.Helper()

	runRS256MalformedJWTAssertionTests(t, fixture)

	t.Run("wrong issuer", func(t *testing.T) {
		assertRS256PrivateKeyJWTRejected(t, fixture, jwt.MapClaims{"iss": "wrong-client"}, "iss")
	})

	t.Run("wrong subject", func(t *testing.T) {
		assertRS256PrivateKeyJWTRejected(t, fixture, jwt.MapClaims{"sub": "wrong-client"}, "sub")
	})

	t.Run("wrong audience", func(t *testing.T) {
		assertRS256PrivateKeyJWTRejected(t, fixture, jwt.MapClaims{"aud": "https://wrong.local/token"}, "aud")
	})

	t.Run("expired assertion", func(t *testing.T) {
		assertRS256PrivateKeyJWTRejected(t, fixture, jwt.MapClaims{"exp": time.Now().Add(-5 * time.Minute).Unix()}, "")
	})

	t.Run("recently expired assertion within clock skew", func(t *testing.T) {
		assertRS256PrivateKeyJWTClockSkew(t, fixture)
	})
}

// runRS256MalformedJWTAssertionTests verifies malformed RS256 request paths.
func runRS256MalformedJWTAssertionTests(t *testing.T, fixture privateKeyJWTFixture) {
	t.Helper()

	t.Run("wrong assertion type", func(t *testing.T) {
		err := fixture.auth.Authenticate(&AuthRequest{
			ClientID:            fixture.clientID,
			ClientAssertionType: "wrong-type",
			ClientAssertion:     "some-jwt",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported")
	})

	t.Run("empty assertion", func(t *testing.T) {
		err := fixture.auth.Authenticate(&AuthRequest{
			ClientID:            fixture.clientID,
			ClientAssertionType: AssertionTypeJWTBearer,
			ClientAssertion:     "",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "empty")
	})

	t.Run("nil request", func(t *testing.T) {
		err := fixture.auth.Authenticate(nil)
		assert.Error(t, err)
	})
}

// assertRS256PrivateKeyJWTClockSkew verifies recently expired assertions within clock skew.
func assertRS256PrivateKeyJWTClockSkew(t *testing.T, fixture privateKeyJWTFixture) {
	t.Helper()

	now := time.Now()

	assertion, err := fixture.sign(jwt.MapClaims{
		"exp": now.Add(-defaultPrivateKeyJWTClockSkew / 2).Unix(),
		"iat": now.Add(-time.Minute).Unix(),
		"jti": "recently-expired-jti",
	})
	if !assert.NoError(t, err) {
		return
	}

	err = fixture.auth.Authenticate(&AuthRequest{
		ClientID:            fixture.clientID,
		ClientAssertionType: AssertionTypeJWTBearer,
		ClientAssertion:     assertion,
	})
	assert.NoError(t, err)
}

type privateKeyJWTFixture struct {
	key           *rsa.PrivateKey
	auth          *PrivateKeyJWTAuthenticator
	clientID      string
	tokenEndpoint string
}

// newRS256PrivateKeyJWTFixture builds the RS256 private_key_jwt test fixture.
func newRS256PrivateKeyJWTFixture(t *testing.T) privateKeyJWTFixture {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	clientID := "my-client"
	tokenEndpoint := "https://issuer.local/idp/oidc/token"
	verifier := signing.NewRS256Verifier(&key.PublicKey)

	return privateKeyJWTFixture{
		key:           key,
		auth:          NewPrivateKeyJWTAuthenticator(verifier, clientID, tokenEndpoint),
		clientID:      clientID,
		tokenEndpoint: tokenEndpoint,
	}
}

// sign creates a signed RS256 client assertion with default valid claims plus overrides.
func (f privateKeyJWTFixture) sign(overrides jwt.MapClaims) (string, error) {
	claims := jwt.MapClaims{
		"iss": f.clientID,
		"sub": f.clientID,
		"aud": f.tokenEndpoint,
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	}
	for key, value := range overrides {
		claims[key] = value
	}

	return signing.NewRS256Signer(f.key, "test-kid").Sign(claims)
}

// assertRS256PrivateKeyJWTRejected verifies one rejected RS256 private_key_jwt assertion.
func assertRS256PrivateKeyJWTRejected(t *testing.T, fixture privateKeyJWTFixture, overrides jwt.MapClaims, contains string) {
	t.Helper()

	assertion, err := fixture.sign(overrides)
	if !assert.NoError(t, err) {
		return
	}

	err = fixture.auth.Authenticate(&AuthRequest{
		ClientID:            fixture.clientID,
		ClientAssertionType: AssertionTypeJWTBearer,
		ClientAssertion:     assertion,
	})
	assert.Error(t, err)

	if contains != "" {
		assert.Contains(t, err.Error(), contains)
	}
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

		assertPrivateKeyJWTAuthenticates(t, auth, signer, clientID, tokenEndpoint, "unique-id-2")
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
