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
	"fmt"
	"io"
	"slices"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/secret"
)

// credentialRedacted is the only rendering of credential-bearing values in diagnostics.
const credentialRedacted = "[redacted credential]"

var _ pluginapi.CredentialProvider = (*credentialProvider)(nil)
var _ pluginapi.Secret = (*requestSecret)(nil)
var _ fmt.Formatter = (*credentialProvider)(nil)
var _ fmt.Formatter = requestSecret{}

// NewCredentialProvider returns a request-bound credential provider for authorized plugin calls.
// Without the credentials capability the provider holds no password material at all.
func NewCredentialProvider(
	requestContext context.Context,
	password secret.Value,
	capabilities []pluginapi.Capability,
) pluginapi.CredentialProvider {
	if requestContext == nil {
		requestContext = context.Background()
	}

	authorized := slices.Contains(capabilities, pluginapi.CapabilityCredentials)
	if !authorized {
		password = secret.Value{}
	}

	return &credentialProvider{
		requestContext: requestContext,
		password:       password,
		authorized:     authorized,
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

// String redacts the provider so request credentials never reach logs through Stringer-aware sinks.
func (*credentialProvider) String() string { return credentialRedacted }

// Format redacts the provider for every fmt verb, including %+v, %#v, and numeric verbs.
func (*credentialProvider) Format(state fmt.State, _ rune) { writeCredentialRedacted(state) }

type requestSecret struct {
	value secret.Value
}

// String redacts the secret so request credentials never reach logs through Stringer-aware sinks.
func (requestSecret) String() string { return credentialRedacted }

// Format redacts the secret for every fmt verb, including %+v, %#v, and numeric verbs.
func (requestSecret) Format(state fmt.State, _ rune) { writeCredentialRedacted(state) }

// writeCredentialRedacted writes the fixed redaction marker to one formatting sink.
func writeCredentialRedacted(writer io.Writer) {
	_, _ = io.WriteString(writer, credentialRedacted)
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
