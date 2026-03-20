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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/definitions"
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

func TestSAML2Config_SLOSettings(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		cfg := &SAML2Config{}

		assert.True(t, cfg.GetSLOEnabled())
		assert.True(t, cfg.GetSLOFrontChannelEnabled())
		assert.False(t, cfg.GetSLOBackChannelEnabled())
		assert.Equal(t, 3*time.Second, cfg.GetSLORequestTimeout())
		assert.Equal(t, 64, cfg.GetSLOMaxParticipants())
		assert.Equal(t, 1, cfg.GetSLOBackChannelMaxRetries())
	})

	t.Run("nested configured values", func(t *testing.T) {
		sloEnabled := false
		frontChannelEnabled := false
		enabled := true
		cfg := &SAML2Config{
			SLO: SAML2SLOConfig{
				Enabled:               &sloEnabled,
				FrontChannelEnabled:   &frontChannelEnabled,
				BackChannelEnabled:    &enabled,
				RequestTimeout:        7 * time.Second,
				MaxParticipants:       77,
				BackChannelMaxRetries: 3,
			},
		}

		assert.False(t, cfg.GetSLOEnabled())
		assert.False(t, cfg.GetSLOFrontChannelEnabled())
		assert.True(t, cfg.GetSLOBackChannelEnabled())
		assert.Equal(t, 7*time.Second, cfg.GetSLORequestTimeout())
		assert.Equal(t, 77, cfg.GetSLOMaxParticipants())
		assert.Equal(t, 3, cfg.GetSLOBackChannelMaxRetries())
	})

	t.Run("legacy fallback values", func(t *testing.T) {
		sloEnabled := false
		frontChannelEnabled := false
		backChannelEnabled := true
		cfg := &SAML2Config{
			SLOEnabled:               &sloEnabled,
			SLOFrontChannelEnabled:   &frontChannelEnabled,
			SLOBackChannelEnabled:    &backChannelEnabled,
			SLOBackChannelTimeout:    9 * time.Second,
			SLOBackChannelMaxRetries: 4,
		}

		assert.False(t, cfg.GetSLOEnabled())
		assert.False(t, cfg.GetSLOFrontChannelEnabled())
		assert.True(t, cfg.GetSLOBackChannelEnabled())
		assert.Equal(t, 9*time.Second, cfg.GetSLORequestTimeout())
		assert.Equal(t, 4, cfg.GetSLOBackChannelMaxRetries())
	})

	t.Run("negative retries clamp to zero", func(t *testing.T) {
		cfg := &SAML2Config{
			SLO: SAML2SLOConfig{
				BackChannelMaxRetries: -2,
			},
		}

		assert.Equal(t, 0, cfg.GetSLOBackChannelMaxRetries())
	})
}

func TestFileSettings_validateIdPSAML2SLOSettings(t *testing.T) {
	t.Run("accepts defaults and zero values", func(t *testing.T) {
		fileCfg := &FileSettings{
			IdP: &IdPSection{
				SAML2: SAML2Config{
					Enabled: true,
				},
			},
		}

		assert.NoError(t, fileCfg.validateIdPSAML2SLOSettings())
	})

	t.Run("rejects negative nested timeout", func(t *testing.T) {
		fileCfg := &FileSettings{
			IdP: &IdPSection{
				SAML2: SAML2Config{
					Enabled: true,
					SLO: SAML2SLOConfig{
						RequestTimeout: -1 * time.Second,
					},
				},
			},
		}

		err := fileCfg.validateIdPSAML2SLOSettings()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "idp.saml2.slo.request_timeout")
	})

	t.Run("rejects negative max participants", func(t *testing.T) {
		fileCfg := &FileSettings{
			IdP: &IdPSection{
				SAML2: SAML2Config{
					Enabled: true,
					SLO: SAML2SLOConfig{
						MaxParticipants: -5,
					},
				},
			},
		}

		err := fileCfg.validateIdPSAML2SLOSettings()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "idp.saml2.slo.max_participants")
	})

	t.Run("rejects negative legacy timeout", func(t *testing.T) {
		fileCfg := &FileSettings{
			IdP: &IdPSection{
				SAML2: SAML2Config{
					Enabled:               true,
					SLOBackChannelTimeout: -1 * time.Second,
				},
			},
		}

		err := fileCfg.validateIdPSAML2SLOSettings()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "idp.saml2.slo_back_channel_timeout")
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

func TestOIDCClient_GetSupportedMFA(t *testing.T) {
	t.Run("NilClient", func(t *testing.T) {
		var c *OIDCClient
		assert.Nil(t, c.GetSupportedMFA())
	})

	t.Run("ConfiguredSupportedMFA", func(t *testing.T) {
		c := &OIDCClient{SupportedMFA: []string{definitions.MFAMethodTOTP, definitions.MFAMethodWebAuthn}}
		assert.Equal(t, []string{definitions.MFAMethodTOTP, definitions.MFAMethodWebAuthn}, c.GetSupportedMFA())
	})
}

func TestOIDCConsentTTL(t *testing.T) {
	t.Run("OIDCConfig default consent ttl", func(t *testing.T) {
		var cfg *OIDCConfig
		assert.Equal(t, 30*24*time.Hour, cfg.GetConsentTTL())

		cfg = &OIDCConfig{}
		assert.Equal(t, 30*24*time.Hour, cfg.GetConsentTTL())
	})

	t.Run("OIDCConfig configured consent ttl", func(t *testing.T) {
		cfg := &OIDCConfig{ConsentTTL: 12 * time.Hour}
		assert.Equal(t, 12*time.Hour, cfg.GetConsentTTL())
	})

	t.Run("OIDCClient inherits default consent ttl", func(t *testing.T) {
		client := &OIDCClient{}
		assert.Equal(t, 24*time.Hour, client.GetConsentTTL(24*time.Hour))
	})

	t.Run("OIDCClient override consent ttl", func(t *testing.T) {
		client := &OIDCClient{ConsentTTL: 2 * time.Hour}
		assert.Equal(t, 2*time.Hour, client.GetConsentTTL(24*time.Hour))
	})
}

func TestOIDCConsentMode(t *testing.T) {
	t.Run("OIDCConfig default consent mode", func(t *testing.T) {
		var cfg *OIDCConfig
		assert.Equal(t, OIDCConsentModeAllOrNothing, cfg.GetConsentMode())

		cfg = &OIDCConfig{}
		assert.Equal(t, OIDCConsentModeAllOrNothing, cfg.GetConsentMode())
	})

	t.Run("OIDCConfig configured consent mode", func(t *testing.T) {
		cfg := &OIDCConfig{ConsentMode: OIDCConsentModeGranularOptional}
		assert.Equal(t, OIDCConsentModeGranularOptional, cfg.GetConsentMode())
	})

	t.Run("OIDCClient inherits global mode", func(t *testing.T) {
		client := &OIDCClient{}
		assert.Equal(t, OIDCConsentModeGranularOptional, client.GetConsentMode(OIDCConsentModeGranularOptional))
	})

	t.Run("OIDCClient override mode", func(t *testing.T) {
		client := &OIDCClient{ConsentMode: OIDCConsentModeAllOrNothing}
		assert.Equal(t, OIDCConsentModeAllOrNothing, client.GetConsentMode(OIDCConsentModeGranularOptional))
	})
}

func TestOIDCTokenEndpointAllowGET(t *testing.T) {
	t.Run("default is disabled", func(t *testing.T) {
		var cfg *OIDCConfig
		assert.False(t, cfg.IsTokenEndpointGETAllowed())

		cfg = &OIDCConfig{}
		assert.False(t, cfg.IsTokenEndpointGETAllowed())
	})

	t.Run("can be enabled explicitly", func(t *testing.T) {
		cfg := &OIDCConfig{TokenEndpointAllowGET: true}
		assert.True(t, cfg.IsTokenEndpointGETAllowed())
	})
}

func TestOIDCClient_OptionalScopesValidation(t *testing.T) {
	validate := validator.New(validator.WithRequiredStructEnabled())

	t.Run("openid in optional_scopes is rejected", func(t *testing.T) {
		client := OIDCClient{
			ClientID:       "client-1",
			OptionalScopes: []string{"profile", "openid"},
		}

		err := validate.Struct(client)
		assert.Error(t, err)
	})

	t.Run("optional_scopes without openid is valid", func(t *testing.T) {
		client := OIDCClient{
			ClientID:       "client-1",
			OptionalScopes: []string{"profile", "email"},
		}

		err := validate.Struct(client)
		assert.NoError(t, err)
	})
}

func TestValidateIdPMFASettings(t *testing.T) {
	t.Run("oidc require_mfa subset of supported_mfa", func(t *testing.T) {
		cfg := &FileSettings{
			IdP: &IdPSection{
				OIDC: OIDCConfig{
					Clients: []OIDCClient{
						{
							ClientID:     "client-1",
							RequireMFA:   []string{definitions.MFAMethodTOTP},
							SupportedMFA: []string{definitions.MFAMethodTOTP, definitions.MFAMethodWebAuthn},
						},
					},
				},
			},
		}

		assert.NoError(t, cfg.validateIdPMFASettings())
	})

	t.Run("oidc require_mfa outside supported_mfa returns error", func(t *testing.T) {
		cfg := &FileSettings{
			IdP: &IdPSection{
				OIDC: OIDCConfig{
					Clients: []OIDCClient{
						{
							ClientID:     "client-1",
							RequireMFA:   []string{definitions.MFAMethodTOTP},
							SupportedMFA: []string{definitions.MFAMethodWebAuthn},
						},
					},
				},
			},
		}

		assert.Error(t, cfg.validateIdPMFASettings())
	})

	t.Run("saml require_mfa outside supported_mfa returns error", func(t *testing.T) {
		cfg := &FileSettings{
			IdP: &IdPSection{
				SAML2: SAML2Config{
					ServiceProviders: []SAML2ServiceProvider{
						{
							EntityID:     "sp-1",
							ACSURL:       "https://sp.example.com/acs",
							RequireMFA:   []string{definitions.MFAMethodRecoveryCodes},
							SupportedMFA: []string{definitions.MFAMethodWebAuthn},
						},
					},
				},
			},
		}

		assert.Error(t, cfg.validateIdPMFASettings())
	})
}

func TestValidateIdPSAMLSigningSettings(t *testing.T) {
	t.Run("nil config", func(t *testing.T) {
		var cfg *FileSettings
		assert.NoError(t, cfg.validateIdPSAMLSigningSettings())
	})

	t.Run("disabled saml", func(t *testing.T) {
		cfg := &FileSettings{
			IdP: &IdPSection{
				SAML2: SAML2Config{Enabled: false},
			},
		}
		assert.NoError(t, cfg.validateIdPSAMLSigningSettings())
	})

	t.Run("authn request signing disabled does not require cert", func(t *testing.T) {
		cfg := &FileSettings{
			IdP: &IdPSection{
				SAML2: SAML2Config{
					Enabled: true,
					ServiceProviders: []SAML2ServiceProvider{
						{
							EntityID: "https://sp.example.com/metadata",
							ACSURL:   "https://sp.example.com/acs",
						},
					},
				},
			},
		}
		assert.NoError(t, cfg.validateIdPSAMLSigningSettings())
	})

	t.Run("missing cert with authn request signing enabled returns error", func(t *testing.T) {
		cfg := &FileSettings{
			IdP: &IdPSection{
				SAML2: SAML2Config{
					Enabled: true,
					ServiceProviders: []SAML2ServiceProvider{
						{
							EntityID:            "https://sp.example.com/metadata",
							ACSURL:              "https://sp.example.com/acs",
							AuthnRequestsSigned: true,
						},
					},
				},
			},
		}

		err := cfg.validateIdPSAMLSigningSettings()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "authn_requests_signed requires cert or cert_file")
	})

	t.Run("invalid cert with authn request signing enabled returns error", func(t *testing.T) {
		cfg := &FileSettings{
			IdP: &IdPSection{
				SAML2: SAML2Config{
					Enabled: true,
					ServiceProviders: []SAML2ServiceProvider{
						{
							EntityID:            "https://sp.example.com/metadata",
							ACSURL:              "https://sp.example.com/acs",
							AuthnRequestsSigned: true,
							Cert:                "not-a-certificate",
						},
					},
				},
			},
		}

		err := cfg.validateIdPSAMLSigningSettings()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid cert for authn request signature validation")
	})

	t.Run("valid inline cert with authn request signing enabled", func(t *testing.T) {
		cfg := &FileSettings{
			IdP: &IdPSection{
				SAML2: SAML2Config{
					Enabled: true,
					ServiceProviders: []SAML2ServiceProvider{
						{
							EntityID:            "https://sp.example.com/metadata",
							ACSURL:              "https://sp.example.com/acs",
							AuthnRequestsSigned: true,
							Cert:                testCertificatePEM(t),
						},
					},
				},
			},
		}

		assert.NoError(t, cfg.validateIdPSAMLSigningSettings())
	})
}

func testCertificatePEM(t *testing.T) string {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test SP"},
		},
		NotBefore: time.Now().Add(-time.Minute),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	assert.NoError(t, err)

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}))
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

func TestWebAuthn_GetAuthenticatorAttachment(t *testing.T) {
	tests := []struct {
		name string
		w    *WebAuthn
		want string
	}{
		{name: "nil receiver", w: nil, want: ""},
		{name: "empty value", w: &WebAuthn{}, want: ""},
		{name: "platform", w: &WebAuthn{AuthenticatorAttachment: "platform"}, want: "platform"},
		{name: "cross-platform", w: &WebAuthn{AuthenticatorAttachment: "cross-platform"}, want: "cross-platform"},
		{name: "uppercase normalized", w: &WebAuthn{AuthenticatorAttachment: "Platform"}, want: "platform"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.w.GetAuthenticatorAttachment())
		})
	}
}

func TestWebAuthn_GetResidentKey(t *testing.T) {
	tests := []struct {
		name string
		w    *WebAuthn
		want string
	}{
		{name: "nil receiver", w: nil, want: "discouraged"},
		{name: "empty defaults to discouraged", w: &WebAuthn{}, want: "discouraged"},
		{name: "discouraged", w: &WebAuthn{ResidentKey: "discouraged"}, want: "discouraged"},
		{name: "preferred", w: &WebAuthn{ResidentKey: "preferred"}, want: "preferred"},
		{name: "required", w: &WebAuthn{ResidentKey: "required"}, want: "required"},
		{name: "invalid defaults to discouraged", w: &WebAuthn{ResidentKey: "bogus"}, want: "discouraged"},
		{name: "uppercase normalized", w: &WebAuthn{ResidentKey: "Required"}, want: "required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.w.GetResidentKey())
		})
	}
}

func TestWebAuthn_GetUserVerification(t *testing.T) {
	tests := []struct {
		name string
		w    *WebAuthn
		want string
	}{
		{name: "nil receiver", w: nil, want: "preferred"},
		{name: "empty defaults to preferred", w: &WebAuthn{}, want: "preferred"},
		{name: "discouraged", w: &WebAuthn{UserVerification: "discouraged"}, want: "discouraged"},
		{name: "preferred", w: &WebAuthn{UserVerification: "preferred"}, want: "preferred"},
		{name: "required", w: &WebAuthn{UserVerification: "required"}, want: "required"},
		{name: "invalid defaults to preferred", w: &WebAuthn{UserVerification: "bogus"}, want: "preferred"},
		{name: "uppercase normalized", w: &WebAuthn{UserVerification: "Discouraged"}, want: "discouraged"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.w.GetUserVerification())
		})
	}
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
		assert.Contains(t, warnings, "oidc.id_token_signing_alg_values_supported: 'HS256' is currently not supported (only 'RS256' and 'EdDSA' are supported)")
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
