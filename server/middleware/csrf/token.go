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

package csrf

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"io"
)

const (
	// tokenLength is the length of the raw CSRF token in bytes.
	tokenLength = 32
)

// TokenGenerator defines the interface for generating CSRF tokens.
type TokenGenerator interface {
	// Generate creates a new random CSRF token.
	Generate() ([]byte, error)
}

// TokenMasker defines the interface for masking and unmasking tokens.
type TokenMasker interface {
	// Mask applies one-time-pad masking to a token.
	Mask(token []byte) ([]byte, error)
	// Unmask removes the one-time-pad masking from a token.
	Unmask(maskedToken []byte) []byte
}

// TokenValidator defines the interface for validating CSRF tokens.
type TokenValidator interface {
	// Validate checks if the sent token matches the real token.
	Validate(realToken, sentToken []byte) bool
}

// TokenEncoder defines the interface for encoding and decoding tokens.
type TokenEncoder interface {
	// Encode converts bytes to a string representation.
	Encode(data []byte) string
	// Decode converts a string representation back to bytes.
	Decode(data string) ([]byte, error)
}

// DefaultTokenGenerator implements TokenGenerator using crypto/rand.
type DefaultTokenGenerator struct{}

// NewTokenGenerator creates a new DefaultTokenGenerator.
func NewTokenGenerator() *DefaultTokenGenerator {
	return &DefaultTokenGenerator{}
}

// Generate creates a new 32-byte random token.
func (g *DefaultTokenGenerator) Generate() ([]byte, error) {
	token := make([]byte, tokenLength)

	if _, err := io.ReadFull(rand.Reader, token); err != nil {
		return nil, err
	}

	return token, nil
}

// DefaultTokenMasker implements TokenMasker using one-time-pad (XOR).
type DefaultTokenMasker struct{}

// NewTokenMasker creates a new DefaultTokenMasker.
func NewTokenMasker() *DefaultTokenMasker {
	return &DefaultTokenMasker{}
}

// Mask applies one-time-pad masking to a token.
// The result is 64 bytes: first 32 bytes are the random key,
// last 32 bytes are the XOR of the key and original token.
func (m *DefaultTokenMasker) Mask(token []byte) ([]byte, error) {
	if len(token) != tokenLength {
		return nil, ErrInvalidTokenLength
	}

	result := make([]byte, 2*tokenLength)
	key := result[:tokenLength]
	maskedToken := result[tokenLength:]

	// Generate random key
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}

	// XOR token with key
	copy(maskedToken, token)
	xorBytes(maskedToken, key)

	return result, nil
}

// Unmask removes the one-time-pad masking from a token.
// Returns nil if the input is not 64 bytes.
func (m *DefaultTokenMasker) Unmask(maskedToken []byte) []byte {
	if len(maskedToken) != tokenLength*2 {
		return nil
	}

	key := maskedToken[:tokenLength]
	token := make([]byte, tokenLength)
	copy(token, maskedToken[tokenLength:])
	xorBytes(token, key)

	return token
}

// xorBytes XORs the data slice with the key slice in place.
func xorBytes(data, key []byte) {
	for i := range data {
		data[i] ^= key[i]
	}
}

// DefaultTokenValidator implements TokenValidator.
type DefaultTokenValidator struct {
	masker TokenMasker
}

// NewTokenValidator creates a new DefaultTokenValidator.
func NewTokenValidator() *DefaultTokenValidator {
	return &DefaultTokenValidator{
		masker: NewTokenMasker(),
	}
}

// Validate checks if the sent token (masked, 64 bytes) matches the real token (unmasked, 32 bytes).
func (v *DefaultTokenValidator) Validate(realToken, sentToken []byte) bool {
	// Real token must be 32 bytes, sent token must be 64 bytes (masked)
	if len(realToken) != tokenLength || len(sentToken) != tokenLength*2 {
		return false
	}

	unmasked := v.masker.Unmask(sentToken)
	if unmasked == nil || len(unmasked) != tokenLength {
		return false
	}

	return subtle.ConstantTimeCompare(realToken, unmasked) == 1
}

// Base64Encoder implements TokenEncoder using URL-safe base64 encoding.
// URL-safe encoding avoids `+` and `/` characters which can cause issues
// when used in cookies or form fields.
type Base64Encoder struct{}

// NewTokenEncoder creates a new Base64Encoder.
func NewTokenEncoder() *Base64Encoder {
	return &Base64Encoder{}
}

// Encode converts bytes to URL-safe base64 string.
func (e *Base64Encoder) Encode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// Decode converts a URL-safe base64 string back to bytes.
func (e *Base64Encoder) Decode(data string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(data)
}
