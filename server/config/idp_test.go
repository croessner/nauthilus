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
	t.Run("from string", func(t *testing.T) {
		cfg := OIDCConfig{
			SigningKey: "test-key",
		}
		key, err := cfg.GetSigningKey()
		assert.NoError(t, err)
		assert.Equal(t, "test-key", key)
	})

	t.Run("from file", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "signing_key")
		assert.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		content := "file-key"
		_, err = tmpFile.WriteString(content)
		assert.NoError(t, err)
		tmpFile.Close()

		cfg := OIDCConfig{
			SigningKeyFile: tmpFile.Name(),
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
				Enabled:    true,
				Issuer:     "https://auth.example.com",
				SigningKey: "key",
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
