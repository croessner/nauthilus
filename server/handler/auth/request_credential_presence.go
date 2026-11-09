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
	"net/http"

	"github.com/croessner/nauthilus/v4/server/model/authdto"
)

const (
	httpAuthUsernameKey = "username"
	httpAuthPasswordKey = "password"
)

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

// httpAuthStructuredRequest is the JSON and CBOR decoding target of one structured auth body.
//
// The shallower pointer fields shadow the credential fields of the embedded DTO in both encoding/json and the CBOR
// codec, so one decoding pass records whether each credential key carried a non-null value. Unknown fields stay
// rejected because every other key still belongs to the embedded DTO.
type httpAuthStructuredRequest struct {
	Username *string `json:"username"`
	Password *string `json:"password"`
	authdto.Request
}

// takeDTO moves the decoded credentials into the auth DTO, drops the wrapper's password reference, and reports which
// credential keys the body carried.
func (r *httpAuthStructuredRequest) takeDTO() (authdto.Request, httpAuthCredentialPresence) {
	presence := httpAuthCredentialPresence{username: r.Username != nil, password: r.Password != nil}

	request := r.Request
	request.Username = ""
	request.Password = ""

	if r.Username != nil {
		request.Username = *r.Username
	}

	if r.Password != nil {
		request.Password = *r.Password
	}

	r.Request = authdto.Request{}
	r.Username = nil
	r.Password = nil

	return request, presence
}
