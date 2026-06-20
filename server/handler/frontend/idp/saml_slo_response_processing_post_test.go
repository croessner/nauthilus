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
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/croessner/nauthilus/v3/server/config"
	slodomain "github.com/croessner/nauthilus/v3/server/idp/slo"
	"github.com/gin-gonic/gin"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/assert"
)

func TestSAMLHandler_SLO_LogoutResponse_CompletesFanout_POST(t *testing.T) {
	gin.SetMode(gin.TestMode)

	const (
		redisPrefix   = "test:"
		transactionID = "tx-slo-end-to-end-post"
		requestID     = "id-slo-request-end-to-end-post"
		entityID      = "https://sp.example.com/saml/metadata"
		destination   = "https://auth.example.com/saml/slo"
	)

	spKey, spCert, spCertPEM := mustGenerateRSACertificate(t, "sp.example.com")

	handler, mock := newSLOFanoutResponseTestHandler(redisPrefix, config.SAML2ServiceProvider{
		EntityID: entityID,
		ACSURL:   "https://sp.example.com/saml/acs",
		Cert:     string(spCertPEM),
	})
	tx := mustIDPFanoutRunningTransaction(t, transactionID, "id-root-end-to-end-post", slodomain.SLOBindingPost, entityID, requestID)
	state := newPendingSLOFanoutState(tx, requestID, time.Date(2026, time.March, 19, 13, 0, 0, 0, time.UTC), 0, 0)
	mustExpectSLOFanoutStateUpdate(t, handler, mock, transactionID, requestID, state, true)

	logoutResponse := mustBuildSignedLogoutResponse(
		t,
		spKey,
		spCert,
		entityID,
		destination,
		requestID,
		dsig.RSASHA256SignatureMethod,
		saml.Status{StatusCode: saml.StatusCode{Value: saml.StatusSuccess}},
	)

	postForm := string(logoutResponse.Post(transactionID))

	responseMatch := regexp.MustCompile(`name="SAMLResponse" value="([^"]+)"`).FindStringSubmatch(postForm)
	if !assert.Len(t, responseMatch, 2) {
		return
	}

	relayMatch := regexp.MustCompile(`name="RelayState" value="([^"]*)"`).FindStringSubmatch(postForm)
	if !assert.Len(t, relayMatch, 2) {
		return
	}

	form := url.Values{}
	form.Set("SAMLResponse", html.UnescapeString(responseMatch[1]))
	form.Set("RelayState", html.UnescapeString(relayMatch[1]))

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/saml/slo", strings.NewReader(form.Encode()))
	ctx.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	handler.SLO(ctx)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "SAML LogoutResponse processed")
	assert.NoError(t, mock.ExpectationsWereMet())
}
