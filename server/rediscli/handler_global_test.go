// Copyright (C) 2024 Christian Rößner
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

package rediscli

import (
	"testing"

	"github.com/redis/go-redis/v9"
)

func TestGetClientDoesNotConstructAmbientClient(t *testing.T) {
	clientMu.Lock()
	previous := client
	client = nil
	clientMu.Unlock()

	t.Cleanup(func() {
		clientMu.Lock()
		client = previous
		clientMu.Unlock()
	})

	if current := GetClient(); current != nil {
		t.Fatalf("GetClient() = %T, want nil before dependency injection", current)
	}

	injected := NewTestClient(redis.NewClient(&redis.Options{}))
	t.Cleanup(injected.Close)

	if current := GetClient(); current != injected {
		t.Fatalf("GetClient() = %T, want injected %T", current, injected)
	}
}
