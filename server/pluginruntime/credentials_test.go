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
	"testing"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/secret"
)

func TestCredentialAccessRequiresCapability(t *testing.T) {
	provider := NewCredentialProvider(context.Background(), secret.New("pw"), nil)

	if _, ok := provider.Password(context.Background()); ok {
		t.Fatal("Password() returned credentials without the credentials capability")
	}
}

func TestCredentialAccessIsRequestScoped(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	provider := NewCredentialProvider(ctx, secret.New("pw"), []pluginapi.Capability{pluginapi.CapabilityCredentials})

	credential, ok := provider.Password(context.Background())
	if !ok {
		t.Fatal("Password() did not return credentials before request context cancellation")
	}

	var got string

	if err := credential.WithBytes(func(value []byte) error {
		got = string(value)

		return nil
	}); err != nil {
		t.Fatalf("WithBytes() error = %v", err)
	}

	if got != "pw" {
		t.Fatalf("Password() bytes = %q, want pw", got)
	}

	cancel()

	if _, ok := provider.Password(context.Background()); ok {
		t.Fatal("Password() returned credentials after request context cancellation")
	}
}
