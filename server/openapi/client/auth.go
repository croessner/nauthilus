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

package client

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	management "github.com/croessner/nauthilus/v3/server/openapi/generated/management"
)

const (
	authorizationHeader = "Authorization"
	basicAuthScheme     = "basic"
	bearerAuthScheme    = "bearer"
)

// ErrInvalidBackchannelAuth reports an incomplete generated management client
// authentication configuration.
var ErrInvalidBackchannelAuth = errors.New("invalid backchannel auth")

// BackchannelAuth contains the supported authentication material for generated
// management clients.
type BackchannelAuth struct {
	token    string
	username string
	password string
	scheme   string
}

// BearerToken configures Authorization: Bearer authentication for generated
// management clients.
func BearerToken(token string) BackchannelAuth {
	return BackchannelAuth{scheme: bearerAuthScheme, token: token}
}

// BasicCredentials configures Authorization: Basic authentication for generated
// management clients.
func BasicCredentials(username string, password string) BackchannelAuth {
	return BackchannelAuth{
		scheme:   basicAuthScheme,
		username: username,
		password: password,
	}
}

func (auth BackchannelAuth) managementRequestEditor() (management.RequestEditorFn, error) {
	header, err := auth.authorizationHeader()
	if err != nil {
		return nil, err
	}

	return func(_ context.Context, request *http.Request) error {
		request.Header.Set(authorizationHeader, header)

		return nil
	}, nil
}

func (auth BackchannelAuth) authorizationHeader() (string, error) {
	switch auth.scheme {
	case bearerAuthScheme:
		token := strings.TrimSpace(auth.token)
		if token == "" {
			return "", ErrInvalidBackchannelAuth
		}

		return "Bearer " + token, nil
	case basicAuthScheme:
		if auth.username == "" || auth.password == "" {
			return "", ErrInvalidBackchannelAuth
		}

		encodedCredentials := base64.StdEncoding.EncodeToString([]byte(auth.username + ":" + auth.password))

		return "Basic " + encodedCredentials, nil
	default:
		return "", ErrInvalidBackchannelAuth
	}
}
