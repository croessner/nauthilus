// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package sessionstate

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

const handleBytes = 32

// EncodedHandleLength is the unpadded base64url length of a 256-bit handle.
const EncodedHandleLength = 43

// RandomHandleGenerator creates 256-bit opaque handles from a supplied entropy source.
type RandomHandleGenerator struct {
	reader io.Reader
}

// NewRandomHandleGenerator creates a handle generator and defaults nil entropy to crypto/rand.Reader.
func NewRandomHandleGenerator(reader io.Reader) *RandomHandleGenerator {
	if reader == nil {
		reader = rand.Reader
	}

	return &RandomHandleGenerator{reader: reader}
}

// NewHandle returns one URL-safe 256-bit opaque handle.
func (g *RandomHandleGenerator) NewHandle() (Handle, error) {
	if g == nil || g.reader == nil {
		return "", fmt.Errorf("session handle generator: missing entropy source")
	}

	raw := make([]byte, handleBytes)
	if _, err := io.ReadFull(g.reader, raw); err != nil {
		return "", fmt.Errorf("session handle generator: %w", err)
	}

	return Handle(base64.RawURLEncoding.EncodeToString(raw)), nil
}

// validateHandle rejects empty, truncated, oversized, or non-canonical handles.
func validateHandle(handle Handle) error {
	if len(handle) != EncodedHandleLength {
		return fmt.Errorf("session handle: invalid encoded length")
	}

	raw, err := base64.RawURLEncoding.DecodeString(string(handle))
	if err != nil || len(raw) != handleBytes {
		return fmt.Errorf("session handle: invalid encoding")
	}

	return nil
}

// ParseHandle validates and returns one canonical 256-bit opaque handle.
func ParseHandle(value string) (Handle, error) {
	handle := Handle(value)
	if err := validateHandle(handle); err != nil {
		return "", err
	}

	return handle, nil
}
