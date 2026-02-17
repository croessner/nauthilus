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

package config

import (
	"os"
	"testing"

	"github.com/croessner/nauthilus/server/secret"
	"github.com/go-playground/validator/v10"
	"github.com/stretchr/testify/assert"
)

func TestGetIdP(t *testing.T) {
	t.Run("NilFileSettings", func(t *testing.T) {
		var f *FileSettings
		idp := f.GetIdP()
		assert.NotNil(t, idp)
		assert.False(t, idp.OIDC.Enabled)
	})

	t.Run("NilIdPSection", func(t *testing.T) {
		f := &FileSettings{IdP: nil}
		idp := f.GetIdP()
		assert.NotNil(t, idp)
		assert.False(t, idp.OIDC.Enabled)
	})

	t.Run("ValidIdPSection", func(t *testing.T) {
		f := &FileSettings{
			IdP: &IdPSection{
				OIDC: OIDCConfig{
					Enabled: true,
					Issuer:  "https://test.example.com",
				},
			},
		}
		idp := f.GetIdP()
		assert.NotNil(t, idp)
		assert.True(t, idp.OIDC.Enabled)
		assert.Equal(t, "https://test.example.com", idp.OIDC.Issuer)
	})
}

func TestOIDCConfig_GetSigningKey(t *testing.T) {
	t.Run("from list", func(t *testing.T) {
		cfg := OIDCConfig{
			SigningKeys: []OIDCKey{
				{ID: "test-key", Key: secret.New("test-key-content"), Active: true},
			},
		}
		key, err := cfg.GetSigningKey()
		assert.NoError(t, err)
		assert.Equal(t, "test-key-content", key)
	})

	t.Run("from file in list", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "signing_key")
		assert.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		content := "file-key"
		_, err = tmpFile.WriteString(content)
		assert.NoError(t, err)
		tmpFile.Close()

		cfg := OIDCConfig{
			SigningKeys: []OIDCKey{
				{ID: "test-key", KeyFile: tmpFile.Name(), Active: true},
			},
		}
		key, err := cfg.GetSigningKey()
		assert.NoError(t, err)
		assert.Equal(t, content, key)
	})
}

func TestSAML2Config_GetCertAndKey(t *testing.T) {
	t.Run("from string", func(t *testing.T) {
		cfg := SAML2Config{
			Cert: "test-cert",
			Key:  "test-key",
		}
		cert, err := cfg.GetCert()
		assert.NoError(t, err)
		assert.Equal(t, "test-cert", cert)

		key, err := cfg.GetKey()
		assert.NoError(t, err)
		assert.Equal(t, "test-key", key)
	})

	t.Run("from file", func(t *testing.T) {
		tmpCert, err := os.CreateTemp("", "cert")
		assert.NoError(t, err)
		defer os.Remove(tmpCert.Name())
		_, _ = tmpCert.WriteString("file-cert")
		tmpCert.Close()

		tmpKey, err := os.CreateTemp("", "key")
		assert.NoError(t, err)
		defer os.Remove(tmpKey.Name())
		_, _ = tmpKey.WriteString("file-key")
		tmpKey.Close()

		cfg := SAML2Config{
			CertFile: tmpCert.Name(),
			KeyFile:  tmpKey.Name(),
		}

		cert, err := cfg.GetCert()
		assert.NoError(t, err)
		assert.Equal(t, "file-cert", cert)

		key, err := cfg.GetKey()
		assert.NoError(t, err)
		assert.Equal(t, "file-key", key)
	})
}

func TestIdPConfig_Validation(t *testing.T) {
	validate := validator.New(validator.WithRequiredStructEnabled())

	t.Run("DisabledIdP_EmptySAML", func(t *testing.T) {
		cfg := IdPSection{
			OIDC: OIDCConfig{
				Enabled: true,
				Issuer:  "https://auth.example.com",
				SigningKeys: []OIDCKey{
					{ID: "key", Key: secret.New("key-content"), Active: true},
				},
			},
			SAML2: SAML2Config{
				Enabled: false,
			},
		}
		err := validate.Struct(cfg)
		assert.NoError(t, err)
	})

	t.Run("EnabledSAML_MissingCertAndKey", func(t *testing.T) {
		cfg := IdPSection{
			SAML2: SAML2Config{
				Enabled:  true,
				EntityID: "https://auth.example.com/saml",
			},
		}
		err := validate.Struct(cfg)
		assert.Error(t, err)
	})

	t.Run("EnabledSAML_WithCertOnly", func(t *testing.T) {
		cfg := IdPSection{
			SAML2: SAML2Config{
				Enabled:  true,
				EntityID: "https://auth.example.com/saml",
				Cert:     "cert",
				Key:      "key",
			},
		}
		err := validate.Struct(cfg)
		assert.NoError(t, err)
	})

	t.Run("EnabledSAML_WithCertFileOnly", func(t *testing.T) {
		cfg := IdPSection{
			SAML2: SAML2Config{
				Enabled:  true,
				EntityID: "https://auth.example.com/saml",
				CertFile: "cert.crt",
				KeyFile:  "key.pem",
			},
		}
		err := validate.Struct(cfg)
		assert.NoError(t, err)
	})
}

func TestOIDCClient_GetAllowedScopes(t *testing.T) {
	t.Run("NilClient", func(t *testing.T) {
		var c *OIDCClient
		assert.Nil(t, c.GetAllowedScopes())
	})

	t.Run("DefaultScopes", func(t *testing.T) {
		c := &OIDCClient{}
		scopes := c.GetAllowedScopes()
		assert.Contains(t, scopes, "openid")
		assert.Contains(t, scopes, "profile")
		assert.Contains(t, scopes, "email")
		assert.Contains(t, scopes, "groups")
		assert.Contains(t, scopes, "offline_access")
		assert.Equal(t, 5, len(scopes))
	})

	t.Run("ConfiguredScopes", func(t *testing.T) {
		c := &OIDCClient{
			Scopes: []string{"openid", "custom"},
		}
		scopes := c.GetAllowedScopes()
		assert.Equal(t, []string{"openid", "custom"}, scopes)
	})
}

func TestSAML2ServiceProvider_GetAllowedAttributes(t *testing.T) {
	t.Run("NilServiceProvider", func(t *testing.T) {
		var sp *SAML2ServiceProvider

		assert.Nil(t, sp.GetAllowedAttributes())
	})

	t.Run("EmptyAttributes", func(t *testing.T) {
		sp := &SAML2ServiceProvider{}

		assert.Nil(t, sp.GetAllowedAttributes())
	})

	t.Run("ConfiguredAttributes", func(t *testing.T) {
		sp := &SAML2ServiceProvider{
			AllowedAttributes: []string{"email", "displayName", "groups"},
		}
		attrs := sp.GetAllowedAttributes()

		assert.Equal(t, []string{"email", "displayName", "groups"}, attrs)
	})
}

func TestSAML2ServiceProvider_GetCert(t *testing.T) {
	t.Run("NilServiceProvider", func(t *testing.T) {
		var sp *SAML2ServiceProvider

		cert, err := sp.GetCert()

		assert.NoError(t, err)
		assert.Empty(t, cert)
	})

	t.Run("NoCert", func(t *testing.T) {
		sp := &SAML2ServiceProvider{}

		cert, err := sp.GetCert()

		assert.NoError(t, err)
		assert.Empty(t, cert)
	})

	t.Run("InlineCert", func(t *testing.T) {
		sp := &SAML2ServiceProvider{
			Cert: "inline-cert-content",
		}

		cert, err := sp.GetCert()

		assert.NoError(t, err)
		assert.Equal(t, "inline-cert-content", cert)
	})

	t.Run("CertFromFile", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "sp-cert")
		assert.NoError(t, err)

		defer os.Remove(tmpFile.Name())

		_, _ = tmpFile.WriteString("file-cert-content")
		tmpFile.Close()

		sp := &SAML2ServiceProvider{
			CertFile: tmpFile.Name(),
		}

		cert, err := sp.GetCert()

		assert.NoError(t, err)
		assert.Equal(t, "file-cert-content", cert)
	})

	t.Run("CertFromMissingFile", func(t *testing.T) {
		sp := &SAML2ServiceProvider{
			CertFile: "/nonexistent/path/cert.pem",
		}

		_, err := sp.GetCert()

		assert.Error(t, err)
	})

	t.Run("InlineTakesPrecedence", func(t *testing.T) {
		sp := &SAML2ServiceProvider{
			Cert:     "inline-cert",
			CertFile: "/some/file",
		}

		cert, err := sp.GetCert()

		assert.NoError(t, err)
		assert.Equal(t, "inline-cert", cert)
	})
}

func TestIdPConfig_WarnUnsupported(t *testing.T) {
	t.Run("OIDC unsupported", func(t *testing.T) {
		cfg := &OIDCConfig{
			Enabled:                          true,
			ResponseTypesSupported:           []string{"code", "id_token"},
			SubjectTypesSupported:            []string{"public", "pairwise"},
			IDTokenSigningAlgValuesSupported: []string{"RS256", "HS256"},
		}
		sessionSupport := true
		cfg.FrontChannelLogoutSessionSupported = &sessionSupport
		cfg.BackChannelLogoutSessionSupported = &sessionSupport

		warnings := cfg.warnUnsupported()
		assert.Contains(t, warnings, "oidc.response_types_supported: 'id_token' is currently not supported (only 'code' is supported)")
		assert.Contains(t, warnings, "oidc.subject_types_supported: 'pairwise' is currently not supported (only 'public' is supported)")
		assert.Contains(t, warnings, "oidc.id_token_signing_alg_values_supported: 'HS256' is currently not supported (only 'RS256' is supported)")
		assert.Contains(t, warnings, "oidc.front_channel_logout_session_supported: setting to 'true' is currently not supported (no effect)")
		assert.Contains(t, warnings, "oidc.back_channel_logout_session_supported: setting to 'true' is currently not supported (no effect)")
	})

	t.Run("SAML unsupported", func(t *testing.T) {
		cfg := &SAML2Config{
			Enabled:         true,
			SignatureMethod: "invalid",
		}
		warnings := cfg.warnUnsupported()
		assert.Contains(t, warnings, "saml2.signature_method: 'invalid' is currently not supported (only 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256' is supported)")
	})

	t.Run("SAML2 IsMFAManageAllowed", func(t *testing.T) {
		cfg := &SAML2Config{
			Enabled: true,
			ServiceProviders: []SAML2ServiceProvider{
				{EntityID: "https://allowed.example.com", ACSURL: "https://allowed.example.com/acs", AllowMFAManage: true},
				{EntityID: "https://denied.example.com", ACSURL: "https://denied.example.com/acs", AllowMFAManage: false},
			},
		}

		assert.True(t, cfg.IsMFAManageAllowed("https://allowed.example.com"))
		assert.False(t, cfg.IsMFAManageAllowed("https://denied.example.com"))
		assert.False(t, cfg.IsMFAManageAllowed("https://unknown.example.com"))
		assert.False(t, cfg.IsMFAManageAllowed(""))
	})

	t.Run("All supported", func(t *testing.T) {
		cfg := &IdPSection{
			OIDC: OIDCConfig{
				Enabled:                          true,
				ResponseTypesSupported:           []string{"code"},
				SubjectTypesSupported:            []string{"public"},
				IDTokenSigningAlgValuesSupported: []string{"RS256"},
			},
			SAML2: SAML2Config{
				Enabled:         true,
				SignatureMethod: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
			},
		}
		warnings := cfg.warnUnsupported()
		assert.Empty(t, warnings)
	})
}
