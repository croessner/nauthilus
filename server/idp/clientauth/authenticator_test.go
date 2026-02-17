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

	"github.com/croessner/nauthilus/server/idp/signing"
	"github.com/croessner/nauthilus/server/secret"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

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
