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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/gin-gonic/gin"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/assert"
)

// TestSAMLHandler_canonicalSAMLRequestFromContext_AuthnRequestSignature covers Redirect AuthnRequest signatures,
// which both the SAML library and the Nauthilus policy verify.
func TestSAMLHandler_canonicalSAMLRequestFromContext_AuthnRequestSignature(t *testing.T) {
	spKey, spCert, spCertPEM := mustGenerateRSACertificate(t, "sp.example.com")
	handler, _, _, _ := newSAMLSSOTestFixture(t, config.SAML2ServiceProvider{
		Cert:                string(spCertPEM),
		AuthnRequestsSigned: true,
	}, nil)
	sp := handler.deps.Cfg.GetIDP().SAML2.ServiceProviders[0]

	testCases := []struct {
		name    string
		sigAlg  string
		mutate  func(string) string
		wantErr bool
	}{
		{name: "valid RSA-SHA256 signature", sigAlg: dsig.RSASHA256SignatureMethod},
		{
			name:   "tampered relay state",
			sigAlg: dsig.RSASHA256SignatureMethod,
			mutate: func(target string) string {
				return strings.Replace(target, "RelayState=relay-state", "RelayState=tampered", 1)
			},
			wantErr: true,
		},
		{name: "SHA-1 signature", sigAlg: dsig.RSASHA1SignatureMethod, wantErr: true},
		{name: "unsigned request", wantErr: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			target := mustBuildSAMLAuthnRedirectTarget(t, sp.EntityID, sp.ACSURL, "https://auth.example.com/saml/sso")
			if tc.sigAlg != "" {
				target = mustBuildSAMLAuthnRedirectTargetWithSigning(
					t, sp.EntityID, sp.ACSURL, "https://auth.example.com/saml/sso", spKey, spCert, tc.sigAlg,
				)
			}

			if tc.mutate != nil {
				target = tc.mutate(target)
			}

			ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
			ctx.Request = httptest.NewRequest(http.MethodGet, target, nil)

			_, request, err := handler.canonicalSAMLRequestFromContext(ctx)
			if tc.wantErr {
				assert.Error(t, err)

				return
			}

			if assert.NoError(t, err) {
				assert.Equal(t, sp.EntityID, samlAuthnRequestIssuer(request))
			}
		})
	}
}
