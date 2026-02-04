// Copyright (C) 2025 Christian Rößner
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
	"crypto/rand"
	"encoding/base64"
)

// TokenGenerator defines the interface for generating secure tokens.
type TokenGenerator interface {
	GenerateToken(prefix string) string
}

// DefaultTokenGenerator is the default implementation of the TokenGenerator interface.
type DefaultTokenGenerator struct{}

// NewDefaultTokenGenerator creates a new DefaultTokenGenerator.
func NewDefaultTokenGenerator() *DefaultTokenGenerator {
	return &DefaultTokenGenerator{}
}

// GenerateToken generates a random token with the given prefix.
func (g *DefaultTokenGenerator) GenerateToken(prefix string) string {
	b := make([]byte, 64)
	if _, err := rand.Read(b); err != nil {
		return prefix + "error-generating-random-string"
	}

	return prefix + base64.RawURLEncoding.EncodeToString(b)
}
