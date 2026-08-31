// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package cookie

import (
	"errors"
	"fmt"

	"github.com/croessner/nauthilus/v4/server/sessionstate"
)

const (
	// CurrentEnvelopeVersion is the sole browser format accepted by this binary.
	CurrentEnvelopeVersion uint8 = 1
	// EnvelopeTargetBytes is the preferred maximum encoded envelope size.
	EnvelopeTargetBytes = 256
	// EnvelopeHardLimitBytes is the absolute encoded envelope ceiling.
	EnvelopeHardLimitBytes     = 512
	minimumEnvelopeSecretBytes = 32
)

var (
	// ErrEnvelopeRejected classifies malformed, legacy, tampered, or inconsistent browser formats.
	ErrEnvelopeRejected = errors.New("cookie: canonical envelope rejected")
	// ErrEnvelopeConfiguration classifies startup configuration that cannot safely encode the canonical format.
	ErrEnvelopeConfiguration = errors.New("cookie: invalid canonical envelope configuration")
)

// Envelope is the complete browser-held session representation.
type Envelope struct {
	Version  uint8
	Session  sessionstate.Handle
	KeyEpoch uint16
	Flags    uint8
}

// EnvelopeCodec authenticates, encrypts, and strictly validates one envelope version.
type EnvelopeCodec struct {
	secure   *SecureCodec
	keyEpoch uint16
}

// NewEnvelopeCodec creates the sole-version codec for one configured key epoch.
func NewEnvelopeCodec(secret []byte, keyEpoch uint16) (*EnvelopeCodec, error) {
	if len(secret) < minimumEnvelopeSecretBytes || keyEpoch == 0 {
		return nil, ErrEnvelopeConfiguration
	}

	return &EnvelopeCodec{secure: NewSecureCodec(secret), keyEpoch: keyEpoch}, nil
}

// Encode validates and encrypts the canonical browser envelope.
func (c *EnvelopeCodec) Encode(name string, envelope Envelope) (string, error) {
	if err := c.validate(envelope); err != nil {
		return "", err
	}

	encoded, err := c.secure.Encode(name, envelope)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrEnvelopeRejected, err)
	}

	if len(encoded) >= EnvelopeHardLimitBytes {
		return "", fmt.Errorf("%w: encoded size %d", ErrEnvelopeRejected, len(encoded))
	}

	return encoded, nil
}

// Decode accepts only the current version, configured epoch, and canonical handle format.
func (c *EnvelopeCodec) Decode(name string, encoded string) (Envelope, error) {
	var envelope Envelope
	if c == nil || c.secure == nil || encoded == "" {
		return envelope, ErrEnvelopeRejected
	}

	if err := c.secure.Decode(name, encoded, &envelope); err != nil {
		return Envelope{}, fmt.Errorf("%w: %v", ErrEnvelopeRejected, err)
	}

	if err := c.validate(envelope); err != nil {
		return Envelope{}, err
	}

	return envelope, nil
}

func (c *EnvelopeCodec) validate(envelope Envelope) error {
	if c == nil || c.secure == nil || envelope.Version != CurrentEnvelopeVersion || envelope.KeyEpoch != c.keyEpoch {
		return ErrEnvelopeRejected
	}

	if _, err := sessionstate.ParseHandle(string(envelope.Session)); err != nil {
		return fmt.Errorf("%w: %v", ErrEnvelopeRejected, err)
	}

	return nil
}
