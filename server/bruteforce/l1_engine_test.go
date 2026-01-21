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

package bruteforce_test

import (
	"context"
	"testing"
	"time"

	"github.com/croessner/nauthilus/server/bruteforce/l1"
	"github.com/stretchr/testify/assert"
)

func TestL1Engine(t *testing.T) {
	engine := l1.GetEngine()
	ctx := context.Background()

	t.Run("Set and Get Block Decision", func(t *testing.T) {
		key := l1.KeyNetwork("1.2.3.0/24")
		dec := l1.L1Decision{Blocked: true, Rule: "test-rule"}
		engine.Set(ctx, key, dec, 100*time.Millisecond)

		got, ok := engine.Get(ctx, key)
		assert.True(t, ok)
		assert.True(t, got.Blocked)
		assert.Equal(t, "test-rule", got.Rule)
	})

	t.Run("Set and Get Allow Decision", func(t *testing.T) {
		key := l1.KeyWhitelist("1.1.1.1")
		dec := l1.L1Decision{Allowed: true, Reason: "Whitelist"}
		engine.Set(ctx, key, dec, 100*time.Millisecond)

		got, ok := engine.Get(ctx, key)
		assert.True(t, ok)
		assert.True(t, got.Allowed)
		assert.Equal(t, "Whitelist", got.Reason)
	})

	t.Run("Expiration", func(t *testing.T) {
		key := "temp-key"
		engine.Set(ctx, key, l1.L1Decision{Blocked: true}, 10*time.Millisecond)

		_, ok := engine.Get(ctx, key)
		assert.True(t, ok)

		time.Sleep(20 * time.Millisecond)

		_, ok = engine.Get(ctx, key)
		assert.False(t, ok)
	})

	t.Run("Reputation", func(t *testing.T) {
		key := l1.KeyReputation("2.2.2.2")
		rep := l1.L1Reputation{Positive: 50, Negative: 2}
		engine.SetReputation(ctx, key, rep, 100*time.Millisecond)

		got, ok := engine.GetReputation(ctx, key)
		assert.True(t, ok)
		assert.Equal(t, int64(50), got.Positive)
		assert.Equal(t, int64(2), got.Negative)
	})
}
