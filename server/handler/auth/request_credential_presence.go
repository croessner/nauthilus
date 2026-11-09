// Copyright (C) 2026 Christian Roessner
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

package auth

import (
	"bytes"
	stdjson "encoding/json"
	"net/http"

	"github.com/croessner/nauthilus/v4/server/encoding/cborcodec"
	"github.com/croessner/nauthilus/v4/server/model/authdto"
)

const (
	httpAuthUsernameKey = "username"
	httpAuthPasswordKey = "password"

	// cborSimpleNull and cborSimpleUndefined are the initial bytes of the CBOR null and undefined simple values.
	cborSimpleNull      = 0xf6
	cborSimpleUndefined = 0xf7
)

var jsonNullLiteral = []byte("null")

// httpAuthCredentialPresence records which credential keys one HTTP auth request carried, independent of their
// values. A missing key makes the request malformed, while an empty value is ordinary authentication input that the
// auth pipeline answers as an invalid login.
type httpAuthCredentialPresence struct {
	username bool
	password bool
}

// completeHTTPAuthCredentialPresence marks both credential keys as carried, for transports whose syntax always
// transports both, such as the HTTP Basic separator.
func completeHTTPAuthCredentialPresence() httpAuthCredentialPresence {
	return httpAuthCredentialPresence{username: true, password: true}
}

// headerHTTPAuthCredentialPresence reports whether the configured credential headers were sent, even with empty values.
func headerHTTPAuthCredentialPresence(header http.Header, usernameHeader string, passwordHeader string) httpAuthCredentialPresence {
	return httpAuthCredentialPresence{
		username: httpAuthHeaderPresent(header, usernameHeader),
		password: httpAuthHeaderPresent(header, passwordHeader),
	}
}

// httpAuthHeaderPresent reports whether a header name was sent at least once, independent of its value.
func httpAuthHeaderPresent(header http.Header, name string) bool {
	if header == nil || name == "" {
		return false
	}

	return len(header.Values(name)) > 0
}

// httpAuthPresenceMarker records whether a structured body carried a non-null value for one key without retaining
// the value, so a password never gets copied by the presence probe.
type httpAuthPresenceMarker bool

// UnmarshalJSON marks every JSON value except null as present.
func (m *httpAuthPresenceMarker) UnmarshalJSON(data []byte) error {
	*m = httpAuthPresenceMarker(!bytes.Equal(bytes.TrimSpace(data), jsonNullLiteral))

	return nil
}

// UnmarshalCBOR marks every CBOR data item except null and undefined as present.
func (m *httpAuthPresenceMarker) UnmarshalCBOR(data []byte) error {
	*m = httpAuthPresenceMarker(len(data) > 0 && data[0] != cborSimpleNull && data[0] != cborSimpleUndefined)

	return nil
}

// httpAuthCredentialProbe indexes the keys of one structured body by presence marker.
type httpAuthCredentialProbe map[string]httpAuthPresenceMarker

// presence converts the probed keys into credential presence.
func (p httpAuthCredentialProbe) presence() httpAuthCredentialPresence {
	return httpAuthCredentialPresence{
		username: bool(p[httpAuthUsernameKey]),
		password: bool(p[httpAuthPasswordKey]),
	}
}

// httpAuthStructuredRequest decodes one JSON or CBOR auth body together with the credential keys it carried.
type httpAuthStructuredRequest struct {
	request  authdto.Request
	presence httpAuthCredentialPresence
}

// UnmarshalJSON decodes the strict auth DTO, rejecting unknown fields, and probes the credential keys.
func (r *httpAuthStructuredRequest) UnmarshalJSON(data []byte) error {
	decoder := stdjson.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&r.request); err != nil {
		return err
	}

	var probe httpAuthCredentialProbe
	if err := stdjson.Unmarshal(data, &probe); err != nil {
		return err
	}

	r.presence = probe.presence()

	return nil
}

// UnmarshalCBOR decodes the auth DTO with the shared CBOR policy and probes the credential keys.
func (r *httpAuthStructuredRequest) UnmarshalCBOR(data []byte) error {
	if err := cborcodec.Unmarshal(data, &r.request); err != nil {
		return err
	}

	var probe httpAuthCredentialProbe
	if err := cborcodec.Unmarshal(data, &probe); err != nil {
		return err
	}

	r.presence = probe.presence()

	return nil
}
