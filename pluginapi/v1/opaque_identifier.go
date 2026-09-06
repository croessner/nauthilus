package pluginapi

import (
	"context"
	"encoding/base64"
	"errors"
	"unicode/utf8"
)

const (
	// MaximumOpaqueIdentifierLabelLength bounds generic scopes and kinds.
	MaximumOpaqueIdentifierLabelLength = 64
	// MaximumOpaqueIdentifierVersionLength bounds rotation identifiers.
	MaximumOpaqueIdentifierVersionLength = 32
	// MaximumOpaqueIdentifierValueLength bounds input bytes before keyed processing.
	MaximumOpaqueIdentifierValueLength = 65536
)

var (
	// ErrOpaqueIdentifierInput identifies invalid bounded tagging input.
	ErrOpaqueIdentifierInput = errors.New("invalid opaque identifier input")
	// ErrOpaqueIdentifierTaggerUnavailable identifies an unconfigured required host service.
	ErrOpaqueIdentifierTaggerUnavailable = errors.New("opaque identifier tagger unavailable")
	// ErrOpaqueIdentifierVersion identifies an unsupported scope or key version.
	ErrOpaqueIdentifierVersion = errors.New("opaque identifier scope or version unavailable")
)

// OpaqueIdentifierInput carries a generic typed identifier into the host boundary.
type OpaqueIdentifierInput struct{ Scope, Kind, Value string }

// OpaqueIdentifierTag is an immutable versioned opaque value without secret material.
type OpaqueIdentifierTag struct{ version, value string }

// OpaqueIdentifierTagger offers active writes and explicit rotation candidates.
type OpaqueIdentifierTagger interface {
	Tag(context.Context, OpaqueIdentifierInput) (OpaqueIdentifierTag, error)
	TagVersion(context.Context, OpaqueIdentifierInput, string) (OpaqueIdentifierTag, error)
	Candidates(context.Context, OpaqueIdentifierInput) ([]OpaqueIdentifierTag, error)
}

// ValidateOpaqueIdentifierLabel validates bounded canonical scope, kind, or version text.
func ValidateOpaqueIdentifierLabel(value string, maximum int) error {
	if value == "" || len(value) > maximum || maximum > MaximumOpaqueIdentifierLabelLength || maximum < 1 {
		return ErrOpaqueIdentifierInput
	}

	for index, character := range []byte(value) {
		if !validOpaqueIdentifierLabelByte(character, index == 0) {
			return ErrOpaqueIdentifierInput
		}
	}

	return nil
}

// validOpaqueIdentifierLabelByte admits canonical ASCII with punctuation only after the first byte.
func validOpaqueIdentifierLabelByte(character byte, first bool) bool {
	return character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
		!first && (character == '_' || character == '-' || character == '.')
}

// ValidateOpaqueIdentifierInput rejects malformed input without including its value in errors.
func ValidateOpaqueIdentifierInput(input OpaqueIdentifierInput) error {
	if ValidateOpaqueIdentifierLabel(input.Scope, MaximumOpaqueIdentifierLabelLength) != nil ||
		ValidateOpaqueIdentifierLabel(input.Kind, MaximumOpaqueIdentifierLabelLength) != nil ||
		len(input.Value) == 0 || len(input.Value) > MaximumOpaqueIdentifierValueLength || !utf8.ValidString(input.Value) {
		return ErrOpaqueIdentifierInput
	}

	return nil
}

// NewOpaqueIdentifierTag captures a canonical SHA-256-sized host-generated authenticator.
func NewOpaqueIdentifierTag(version, authenticator string) (OpaqueIdentifierTag, error) {
	if ValidateOpaqueIdentifierLabel(version, MaximumOpaqueIdentifierVersionLength) != nil {
		return OpaqueIdentifierTag{}, ErrOpaqueIdentifierInput
	}

	decoded, err := base64.RawURLEncoding.DecodeString(authenticator)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != authenticator {
		return OpaqueIdentifierTag{}, ErrOpaqueIdentifierInput
	}

	return OpaqueIdentifierTag{version: version, value: "hmac-sha256-v1:" + version + ":" + authenticator}, nil
}

// Version returns the explicit key version used for this tag.
func (t OpaqueIdentifierTag) Version() string { return t.version }

// String returns the canonical storage-safe opaque value.
func (t OpaqueIdentifierTag) String() string { return t.value }
