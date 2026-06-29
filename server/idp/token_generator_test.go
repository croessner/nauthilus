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
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

type failingRandomReader struct{}

// Read returns a deterministic entropy failure for token generator tests.
func (f failingRandomReader) Read(_ []byte) (int, error) {
	return 0, errors.New("entropy unavailable")
}

func TestDefaultTokenGeneratorEntropyFailureDoesNotReturnFallbackToken(t *testing.T) {
	generator := NewDefaultTokenGeneratorWithReader(failingRandomReader{})
	token, err := generator.GenerateToken("na_test_")

	assert.Error(t, err)
	assert.Empty(t, token)
}

func TestDefaultTokenGeneratorRandomTokensUsePrefixAndDiffer(t *testing.T) {
	generator := NewDefaultTokenGenerator()
	first, firstErr := generator.GenerateToken("na_test_")
	second, secondErr := generator.GenerateToken("na_test_")

	assert.NoError(t, firstErr)
	assert.NoError(t, secondErr)
	assert.True(t, strings.HasPrefix(first, "na_test_"))
	assert.True(t, strings.HasPrefix(second, "na_test_"))
	assert.NotEqual(t, first, second)
	assert.NotEqual(t, "na_test_error-generating-random-string", first)
	assert.NotEqual(t, "na_test_error-generating-random-string", second)
}
