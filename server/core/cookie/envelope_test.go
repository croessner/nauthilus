// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

package cookie

import (
	"errors"
	"testing"

	"github.com/croessner/nauthilus/v4/server/definitions"
	"github.com/croessner/nauthilus/v4/server/sessionstate"
)

func TestEnvelopeCodecAcceptsOnlyCanonicalVersionAndEpoch(t *testing.T) {
	t.Parallel()

	secret := []byte("canonical-envelope-test-secret-32-bytes")

	codec, err := NewEnvelopeCodec(secret, 7)
	if err != nil {
		t.Fatalf("create envelope codec: %v", err)
	}

	envelope := Envelope{
		Version:  CurrentEnvelopeVersion,
		Session:  sessionstate.Handle("MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM"),
		KeyEpoch: 7,
	}

	encoded, err := codec.Encode(definitions.SecureDataCookieName, envelope)
	if err != nil {
		t.Fatalf("encode envelope: %v", err)
	}

	if len(encoded) >= EnvelopeTargetBytes || len(encoded) >= EnvelopeHardLimitBytes {
		t.Fatalf("encoded envelope bytes = %d, want below target %d and hard limit %d", len(encoded), EnvelopeTargetBytes, EnvelopeHardLimitBytes)
	}

	decoded, err := codec.Decode(definitions.SecureDataCookieName, encoded)
	if err != nil || decoded != envelope {
		t.Fatalf("decode envelope: value=%#v err=%v", decoded, err)
	}

	wrongEpoch, err := NewEnvelopeCodec(secret, 8)
	if err != nil {
		t.Fatalf("create wrong-epoch codec: %v", err)
	}

	if _, err = wrongEpoch.Decode(definitions.SecureDataCookieName, encoded); !errors.Is(err, ErrEnvelopeRejected) {
		t.Fatalf("wrong epoch error = %v, want envelope rejected", err)
	}

	legacy := NewSecureCodec(secret)

	legacyValue, err := legacy.Encode(definitions.SecureDataCookieName, map[string]any{"username": "legacy"})
	if err != nil {
		t.Fatalf("encode legacy cookie: %v", err)
	}

	if _, err = codec.Decode(definitions.SecureDataCookieName, legacyValue); !errors.Is(err, ErrEnvelopeRejected) {
		t.Fatalf("legacy map error = %v, want envelope rejected", err)
	}
}

func TestEnvelopeCodecRejectsMalformedAndInvalidConfiguration(t *testing.T) {
	t.Parallel()

	if _, err := NewEnvelopeCodec([]byte("short"), 1); !errors.Is(err, ErrEnvelopeConfiguration) {
		t.Fatalf("short secret error = %v, want configuration error", err)
	}

	if _, err := NewEnvelopeCodec([]byte("canonical-envelope-test-secret-32-bytes"), 0); !errors.Is(err, ErrEnvelopeConfiguration) {
		t.Fatalf("zero epoch error = %v, want configuration error", err)
	}

	codec, err := NewEnvelopeCodec([]byte("canonical-envelope-test-secret-32-bytes"), 1)
	if err != nil {
		t.Fatalf("create envelope codec: %v", err)
	}

	for _, encoded := range []string{"", "legacy-cookie", "AAAA"} {
		if _, err = codec.Decode(definitions.SecureDataCookieName, encoded); !errors.Is(err, ErrEnvelopeRejected) {
			t.Fatalf("malformed %q error = %v, want envelope rejected", encoded, err)
		}
	}
}
