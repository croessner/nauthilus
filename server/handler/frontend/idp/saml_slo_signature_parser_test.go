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
	"bytes"
	"compress/flate"
	"encoding/base64"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	slodomain "github.com/croessner/nauthilus/server/idp/slo"
	"github.com/stretchr/testify/assert"
)

func TestDecodeLogoutRequestXML(t *testing.T) {
	rawXML := mustMarshalTestLogoutRequestXML(t)

	testCases := []struct {
		name    string
		binding slodomain.SLOBinding
		payload string
		wantErr string
	}{
		{
			name:    "post binding keeps xml payload",
			binding: slodomain.SLOBindingPost,
			payload: base64.StdEncoding.EncodeToString(rawXML),
		},
		{
			name:    "redirect binding inflates payload",
			binding: slodomain.SLOBindingRedirect,
			payload: mustDeflateAndBase64Encode(t, rawXML),
		},
		{
			name:    "empty payload rejected",
			binding: slodomain.SLOBindingPost,
			payload: " ",
			wantErr: "logout request payload is empty",
		},
		{
			name:    "invalid base64 rejected",
			binding: slodomain.SLOBindingPost,
			payload: "***",
			wantErr: "cannot decode LogoutRequest payload",
		},
		{
			name:    "unsupported binding rejected",
			binding: slodomain.SLOBinding("soap"),
			payload: base64.StdEncoding.EncodeToString(rawXML),
			wantErr: "unsupported SLO binding",
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			decoded, err := decodeLogoutRequestXML(tc.binding, tc.payload)
			if tc.wantErr != "" {
				assert.Error(t, err)
				assert.ErrorContains(t, err, tc.wantErr)

				return
			}

			if !assert.NoError(t, err) {
				return
			}

			assert.Equal(t, rawXML, decoded)
		})
	}
}

func TestDecodeLogoutRequestPayload(t *testing.T) {
	rawXML := mustMarshalTestLogoutRequestXML(t)
	payload := base64.StdEncoding.EncodeToString(rawXML)

	decodedXML, decodedRequest, err := decodeLogoutRequestPayload(slodomain.SLOBindingPost, payload)
	if !assert.NoError(t, err) {
		return
	}

	if !assert.NotNil(t, decodedRequest) {
		return
	}

	assert.Equal(t, rawXML, decodedXML)
	assert.Equal(t, "id-test-request", decodedRequest.ID)
	if assert.NotNil(t, decodedRequest.Issuer) {
		assert.Equal(t, "https://sp.example.com/saml/metadata", decodedRequest.Issuer.Value)
	}
	if assert.NotNil(t, decodedRequest.NameID) {
		assert.Equal(t, "alice@example.com", decodedRequest.NameID.Value)
	}
}

func TestDecodeLogoutResponsePayload(t *testing.T) {
	rawXML := mustMarshalTestLogoutResponseXML(t)
	payload := base64.StdEncoding.EncodeToString(rawXML)

	decodedXML, decodedResponse, err := decodeLogoutResponsePayload(slodomain.SLOBindingPost, payload)
	if !assert.NoError(t, err) {
		return
	}

	if !assert.NotNil(t, decodedResponse) {
		return
	}

	assert.Equal(t, rawXML, decodedXML)
	assert.Equal(t, "id-test-response", decodedResponse.ID)
	assert.Equal(t, "id-test-request", decodedResponse.InResponseTo)
	if assert.NotNil(t, decodedResponse.Issuer) {
		assert.Equal(t, "https://sp.example.com/saml/metadata", decodedResponse.Issuer.Value)
	}
}

func TestDecodeLogoutPayload_InvalidXMLRejected(t *testing.T) {
	invalidXMLPayload := base64.StdEncoding.EncodeToString([]byte("<LogoutRequest"))

	_, _, err := decodeLogoutRequestPayload(slodomain.SLOBindingPost, invalidXMLPayload)
	assert.Error(t, err)
	assert.ErrorContains(t, err, "invalid LogoutRequest XML")

	_, _, err = decodeLogoutResponsePayload(slodomain.SLOBindingPost, invalidXMLPayload)
	assert.Error(t, err)
	assert.ErrorContains(t, err, "invalid LogoutResponse XML")
}

func TestRawQueryParameterStrictSLO(t *testing.T) {
	testCases := []struct {
		name      string
		rawQuery  string
		key       string
		wantValue string
		wantFound bool
		wantErr   string
	}{
		{
			name:      "single key value",
			rawQuery:  "SAMLRequest=req-1&RelayState=state-1",
			key:       "SAMLRequest",
			wantValue: "req-1",
			wantFound: true,
		},
		{
			name:      "bare key accepted",
			rawQuery:  "RelayState&SAMLRequest=req-1",
			key:       "RelayState",
			wantValue: "",
			wantFound: true,
		},
		{
			name:      "missing key",
			rawQuery:  "SAMLRequest=req-1",
			key:       "SigAlg",
			wantValue: "",
			wantFound: false,
		},
		{
			name:     "duplicate key with values",
			rawQuery: "SAMLRequest=req-1&SAMLRequest=req-2",
			key:      "SAMLRequest",
			wantErr:  "duplicate parameter",
		},
		{
			name:     "duplicate bare and valued key",
			rawQuery: "RelayState&RelayState=state-1",
			key:      "RelayState",
			wantErr:  "duplicate parameter",
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			value, found, err := rawQueryParameterStrictSLO(tc.rawQuery, tc.key)
			if tc.wantErr != "" {
				assert.Error(t, err)
				assert.ErrorContains(t, err, tc.wantErr)

				return
			}

			if !assert.NoError(t, err) {
				return
			}

			assert.Equal(t, tc.wantFound, found)
			assert.Equal(t, tc.wantValue, value)
		})
	}
}

func TestInflateSAMLRedirectPayload_RejectsOversizedContent(t *testing.T) {
	tooLarge := bytes.Repeat([]byte("A"), samlSLOFlateUncompressLimit+1)
	compressed := mustDeflateBytes(t, tooLarge)

	_, err := inflateSAMLRedirectPayload(compressed)
	if !assert.Error(t, err) {
		return
	}

	assert.ErrorContains(t, err, "uncompress limit exceeded")
}

func mustMarshalTestLogoutRequestXML(t *testing.T) []byte {
	t.Helper()

	sessionIndex := "session-1"
	logoutRequest := &saml.LogoutRequest{
		ID:           "id-test-request",
		Version:      "2.0",
		IssueInstant: time.Date(2026, time.March, 19, 11, 0, 0, 0, time.UTC),
		Destination:  "https://auth.example.com/saml/slo",
		Issuer: &saml.Issuer{
			Value: "https://sp.example.com/saml/metadata",
		},
		NameID: &saml.NameID{
			Value: "alice@example.com",
		},
		SessionIndex: &saml.SessionIndex{Value: sessionIndex},
	}

	rawXML, err := logoutRequest.Bytes()
	if err != nil {
		t.Fatalf("failed to marshal test logout request xml: %v", err)
	}

	return rawXML
}

func mustMarshalTestLogoutResponseXML(t *testing.T) []byte {
	t.Helper()

	logoutResponse := &saml.LogoutResponse{
		ID:           "id-test-response",
		InResponseTo: "id-test-request",
		Version:      "2.0",
		IssueInstant: time.Date(2026, time.March, 19, 11, 5, 0, 0, time.UTC),
		Destination:  "https://auth.example.com/saml/slo",
		Issuer: &saml.Issuer{
			Value: "https://sp.example.com/saml/metadata",
		},
		Status: saml.Status{
			StatusCode: saml.StatusCode{Value: saml.StatusSuccess},
		},
	}

	doc := etree.NewDocument()
	doc.SetRoot(logoutResponse.Element())

	rawXML, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("failed to marshal test logout response xml: %v", err)
	}

	return rawXML
}

func mustDeflateAndBase64Encode(t *testing.T, rawXML []byte) string {
	t.Helper()

	compressed := mustDeflateBytes(t, rawXML)

	return base64.StdEncoding.EncodeToString(compressed)
}

func mustDeflateBytes(t *testing.T, content []byte) []byte {
	t.Helper()

	var compressed bytes.Buffer
	writer, err := flate.NewWriter(&compressed, flate.BestCompression)
	if err != nil {
		t.Fatalf("failed to create flate writer: %v", err)
	}

	_, err = writer.Write(content)
	if err != nil {
		t.Fatalf("failed to write deflated content: %v", err)
	}

	if err = writer.Close(); err != nil {
		t.Fatalf("failed to close flate writer: %v", err)
	}

	return compressed.Bytes()
}
