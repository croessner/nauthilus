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

	"github.com/croessner/nauthilus/v3/server/bruteforce/l1"
	"github.com/stretchr/testify/assert"
)

func TestL1Engine(t *testing.T) {
	engine := l1.GetEngine()
	ctx := context.Background()

	for _, testCase := range l1DecisionCases() {
		t.Run(testCase.name, func(t *testing.T) {
			engine.Set(ctx, testCase.key, testCase.decision, 100*time.Millisecond)

			got, ok := engine.Get(ctx, testCase.key)
			assert.True(t, ok)
			testCase.assertDecision(t, got)
		})
	}

	t.Run("Expiration", func(t *testing.T) {
		key := "temp-key"
		engine.Set(ctx, key, l1.Decision{Blocked: true}, 10*time.Millisecond)

		_, ok := engine.Get(ctx, key)
		assert.True(t, ok)

		time.Sleep(20 * time.Millisecond)

		_, ok = engine.Get(ctx, key)
		assert.False(t, ok)
	})

	t.Run("Reputation", func(t *testing.T) {
		key := l1.KeyReputation("2.2.2.2")
		rep := l1.Reputation{Positive: 50, Negative: 2}
		engine.SetReputation(ctx, key, rep, 100*time.Millisecond)

		got, ok := engine.GetReputation(ctx, key)
		assert.True(t, ok)
		assert.Equal(t, int64(50), got.Positive)
		assert.Equal(t, int64(2), got.Negative)
	})
}

type l1DecisionCase struct {
	name           string
	key            string
	decision       l1.Decision
	assertDecision func(*testing.T, l1.Decision)
}

// l1DecisionCases defines the shared cache round-trip cases for decision values.
func l1DecisionCases() []l1DecisionCase {
	return []l1DecisionCase{
		{
			name:     "Set and Get Block Decision",
			key:      l1.KeyNetwork("1.2.3.0/24"),
			decision: l1.Decision{Blocked: true, Rule: "test-rule"},
			assertDecision: func(t *testing.T, got l1.Decision) {
				t.Helper()

				assert.True(t, got.Blocked)
				assert.Equal(t, "test-rule", got.Rule)
			},
		},
		{
			name:     "Set and Get Allow Decision",
			key:      l1.KeyWhitelist("1.1.1.1"),
			decision: l1.Decision{Allowed: true, Reason: "Whitelist"},
			assertDecision: func(t *testing.T, got l1.Decision) {
				t.Helper()

				assert.True(t, got.Allowed)
				assert.Equal(t, "Whitelist", got.Reason)
			},
		},
	}
}
