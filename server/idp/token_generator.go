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
	"fmt"
	"io"
)

// TokenGenerator defines the interface for generating secure tokens.
type TokenGenerator interface {
	GenerateToken(prefix string) (string, error)
}

// DefaultTokenGenerator is the default implementation of the TokenGenerator interface.
type DefaultTokenGenerator struct {
	reader io.Reader
}

// NewDefaultTokenGenerator creates a new DefaultTokenGenerator.
func NewDefaultTokenGenerator() *DefaultTokenGenerator {
	return NewDefaultTokenGeneratorWithReader(rand.Reader)
}

// NewDefaultTokenGeneratorWithReader creates a generator with an explicit entropy reader.
func NewDefaultTokenGeneratorWithReader(reader io.Reader) *DefaultTokenGenerator {
	if reader == nil {
		reader = rand.Reader
	}

	return &DefaultTokenGenerator{reader: reader}
}

// GenerateToken generates a random token with the given prefix and fails closed on entropy errors.
func (g *DefaultTokenGenerator) GenerateToken(prefix string) (string, error) {
	reader := rand.Reader
	if g != nil && g.reader != nil {
		reader = g.reader
	}

	b := make([]byte, 64)
	if _, err := io.ReadFull(reader, b); err != nil {
		return "", fmt.Errorf("failed to read random token entropy: %w", err)
	}

	return prefix + base64.RawURLEncoding.EncodeToString(b), nil
}
