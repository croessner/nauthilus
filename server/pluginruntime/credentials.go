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

package pluginruntime

import (
	"context"
	"slices"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/secret"
)

var _ pluginapi.CredentialProvider = (*credentialProvider)(nil)
var _ pluginapi.Secret = (*requestSecret)(nil)

// NewCredentialProvider returns a request-bound credential provider for authorized plugin calls.
func NewCredentialProvider(
	requestContext context.Context,
	password secret.Value,
	capabilities []pluginapi.Capability,
) pluginapi.CredentialProvider {
	if requestContext == nil {
		requestContext = context.Background()
	}

	return &credentialProvider{
		requestContext: requestContext,
		password:       password,
		authorized:     slices.Contains(capabilities, pluginapi.CapabilityCredentials),
	}
}

type credentialProvider struct {
	requestContext context.Context
	password       secret.Value
	authorized     bool
}

// Password returns the request password only while the request is active and capability-gated.
func (p *credentialProvider) Password(ctx context.Context) (pluginapi.Secret, bool) {
	if p == nil || !p.authorized || p.password.IsZero() {
		return nil, false
	}

	if ctx != nil && ctx.Err() != nil {
		return nil, false
	}

	if p.requestContext != nil && p.requestContext.Err() != nil {
		return nil, false
	}

	return requestSecret{value: p.password}, true
}

type requestSecret struct {
	value secret.Value
}

// WithBytes exposes temporary secret bytes and propagates callback errors.
func (s requestSecret) WithBytes(fn func([]byte) error) error {
	if fn == nil {
		return nil
	}

	var callbackErr error

	s.value.WithBytes(func(value []byte) {
		callbackErr = fn(value)
	})

	return callbackErr
}

// IsZero reports whether the underlying request secret is empty.
func (s requestSecret) IsZero() bool {
	return s.value.IsZero()
}
