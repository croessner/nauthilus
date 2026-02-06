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
	"testing"
)

func TestDefaultTokenGenerator_Generate(t *testing.T) {
	generator := NewTokenGenerator()

	token1, err := generator.Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if len(token1) != tokenLength {
		t.Errorf("Generate() token length = %d, want %d", len(token1), tokenLength)
	}

	// Generate a second token and ensure they're different
	token2, err := generator.Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if string(token1) == string(token2) {
		t.Error("Generate() produced identical tokens")
	}
}

func TestDefaultTokenMasker_MaskUnmask(t *testing.T) {
	masker := NewTokenMasker()
	generator := NewTokenGenerator()

	originalToken, err := generator.Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Mask the token
	masked, err := masker.Mask(originalToken)
	if err != nil {
		t.Fatalf("Mask() error = %v", err)
	}

	if len(masked) != tokenLength*2 {
		t.Errorf("Mask() result length = %d, want %d", len(masked), tokenLength*2)
	}

	// Unmask and verify
	unmasked := masker.Unmask(masked)
	if string(unmasked) != string(originalToken) {
		t.Error("Unmask() did not return original token")
	}
}

func TestDefaultTokenMasker_MaskInvalidLength(t *testing.T) {
	masker := NewTokenMasker()

	// Try to mask a token with invalid length
	_, err := masker.Mask([]byte("short"))
	if err != ErrInvalidTokenLength {
		t.Errorf("Mask() error = %v, want %v", err, ErrInvalidTokenLength)
	}
}

func TestDefaultTokenMasker_UnmaskInvalidLength(t *testing.T) {
	masker := NewTokenMasker()

	// Try to unmask with invalid length
	result := masker.Unmask([]byte("short"))
	if result != nil {
		t.Error("Unmask() should return nil for invalid length")
	}
}

func TestDefaultTokenMasker_MaskProducesDifferentResults(t *testing.T) {
	masker := NewTokenMasker()
	generator := NewTokenGenerator()

	token, err := generator.Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Mask the same token twice - should produce different results due to random key
	masked1, err := masker.Mask(token)
	if err != nil {
		t.Fatalf("Mask() error = %v", err)
	}

	masked2, err := masker.Mask(token)
	if err != nil {
		t.Fatalf("Mask() error = %v", err)
	}

	if string(masked1) == string(masked2) {
		t.Error("Mask() should produce different results each time")
	}

	// But both should unmask to the same original token
	unmasked1 := masker.Unmask(masked1)
	unmasked2 := masker.Unmask(masked2)

	if string(unmasked1) != string(token) || string(unmasked2) != string(token) {
		t.Error("Different masked tokens should unmask to same original")
	}
}

func TestDefaultTokenValidator_Validate(t *testing.T) {
	validator := NewTokenValidator()
	masker := NewTokenMasker()
	generator := NewTokenGenerator()

	realToken, err := generator.Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	maskedToken, err := masker.Mask(realToken)
	if err != nil {
		t.Fatalf("Mask() error = %v", err)
	}

	// Should validate correctly
	if !validator.Validate(realToken, maskedToken) {
		t.Error("Validate() should return true for matching tokens")
	}
}

func TestDefaultTokenValidator_ValidateInvalidToken(t *testing.T) {
	validator := NewTokenValidator()
	generator := NewTokenGenerator()
	masker := NewTokenMasker()

	realToken, _ := generator.Generate()
	differentToken, _ := generator.Generate()

	maskedDifferent, _ := masker.Mask(differentToken)

	// Should fail for mismatched tokens
	if validator.Validate(realToken, maskedDifferent) {
		t.Error("Validate() should return false for mismatched tokens")
	}
}

func TestDefaultTokenValidator_ValidateInvalidLengths(t *testing.T) {
	validator := NewTokenValidator()

	tests := []struct {
		name      string
		realToken []byte
		sentToken []byte
	}{
		{
			name:      "short real token",
			realToken: []byte("short"),
			sentToken: make([]byte, tokenLength*2),
		},
		{
			name:      "short sent token",
			realToken: make([]byte, tokenLength),
			sentToken: []byte("short"),
		},
		{
			name:      "nil real token",
			realToken: nil,
			sentToken: make([]byte, tokenLength*2),
		},
		{
			name:      "nil sent token",
			realToken: make([]byte, tokenLength),
			sentToken: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if validator.Validate(tt.realToken, tt.sentToken) {
				t.Error("Validate() should return false for invalid lengths")
			}
		})
	}
}

func TestBase64Encoder_EncodeDecode(t *testing.T) {
	encoder := NewTokenEncoder()
	generator := NewTokenGenerator()

	original, err := generator.Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	encoded := encoder.Encode(original)
	if encoded == "" {
		t.Error("Encode() should not return empty string")
	}

	decoded, err := encoder.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}

	if string(decoded) != string(original) {
		t.Error("Decode(Encode(x)) should equal x")
	}
}

func TestBase64Encoder_DecodeInvalid(t *testing.T) {
	encoder := NewTokenEncoder()

	_, err := encoder.Decode("not-valid-base64!!!")
	if err == nil {
		t.Error("Decode() should return error for invalid base64")
	}
}

func TestXorBytes(t *testing.T) {
	data := []byte{0x12, 0x34, 0x56, 0x78}
	key := []byte{0xFF, 0xFF, 0xFF, 0xFF}
	expected := []byte{0xED, 0xCB, 0xA9, 0x87}

	xorBytes(data, key)

	for i := range data {
		if data[i] != expected[i] {
			t.Errorf("xorBytes()[%d] = %x, want %x", i, data[i], expected[i])
		}
	}

	// XOR again should restore original
	xorBytes(data, key)
	original := []byte{0x12, 0x34, 0x56, 0x78}

	for i := range data {
		if data[i] != original[i] {
			t.Errorf("double xorBytes()[%d] = %x, want %x", i, data[i], original[i])
		}
	}
}
