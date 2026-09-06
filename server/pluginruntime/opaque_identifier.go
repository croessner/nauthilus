package pluginruntime

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/secret"
)

const (
	opaqueIdentifierKeySize  = config.OpaqueIdentifierKeySize
	opaqueIdentifierRedacted = "[opaque identifier tagger]"
)

// OpaqueIdentifierKey is host-only rotation material supplied by a typed secret reference.
type OpaqueIdentifierKey struct {
	Secret  secret.Value
	Version string
}

// OpaqueIdentifierScopeKeys binds one admitted generic scope to active and previous keys.
type OpaqueIdentifierScopeKeys struct {
	Previous *OpaqueIdentifierKey
	Active   OpaqueIdentifierKey
	Scope    string
}

type opaqueIdentifierTagger struct {
	scopes map[string][]OpaqueIdentifierKey
}

// NewOpaqueIdentifierTagger validates and owns a closed immutable set of rotation keys.
func NewOpaqueIdentifierTagger(scopes []OpaqueIdentifierScopeKeys) (pluginapi.OpaqueIdentifierTagger, error) {
	if len(scopes) == 0 || len(scopes) > 32 {
		return nil, pluginapi.ErrOpaqueIdentifierTaggerUnavailable
	}

	owned := make(map[string][]OpaqueIdentifierKey, len(scopes))
	for _, scope := range scopes {
		if pluginapi.ValidateOpaqueIdentifierLabel(scope.Scope, pluginapi.MaximumOpaqueIdentifierLabelLength) != nil {
			return nil, pluginapi.ErrOpaqueIdentifierInput
		}

		if _, exists := owned[scope.Scope]; exists {
			return nil, pluginapi.ErrOpaqueIdentifierInput
		}

		keys, err := ownOpaqueIdentifierKeys(scope)
		if err != nil {
			return nil, err
		}

		owned[scope.Scope] = keys
	}

	return &opaqueIdentifierTagger{scopes: owned}, nil
}

// ownOpaqueIdentifierKeys validates key lengths and versions while detaching host secret storage.
func ownOpaqueIdentifierKeys(scope OpaqueIdentifierScopeKeys) ([]OpaqueIdentifierKey, error) {
	inputs := []OpaqueIdentifierKey{scope.Active}
	if scope.Previous != nil {
		inputs = append(inputs, *scope.Previous)
	}

	keys := make([]OpaqueIdentifierKey, 0, len(inputs))
	for index, input := range inputs {
		if input.Secret.Len() != opaqueIdentifierKeySize || pluginapi.ValidateOpaqueIdentifierLabel(input.Version, pluginapi.MaximumOpaqueIdentifierVersionLength) != nil {
			return nil, pluginapi.ErrOpaqueIdentifierInput
		}

		if index > 0 && input.Version == inputs[0].Version {
			return nil, pluginapi.ErrOpaqueIdentifierInput
		}

		var owned secret.Value

		input.Secret.WithBytes(func(value []byte) { owned = secret.FromBytes(value) })
		keys = append(keys, OpaqueIdentifierKey{Version: input.Version, Secret: owned})
	}

	return keys, nil
}

// Tag uses only the active key for new identifiers.
func (t *opaqueIdentifierTagger) Tag(ctx context.Context, input pluginapi.OpaqueIdentifierInput) (pluginapi.OpaqueIdentifierTag, error) {
	keys, err := t.keysForInput(ctx, input)
	if err != nil {
		return pluginapi.OpaqueIdentifierTag{}, err
	}

	return tagOpaqueIdentifier(input, keys[0])
}

// TagVersion resolves an explicitly admitted rotation version without an implicit fallback.
func (t *opaqueIdentifierTagger) TagVersion(ctx context.Context, input pluginapi.OpaqueIdentifierInput, version string) (pluginapi.OpaqueIdentifierTag, error) {
	if pluginapi.ValidateOpaqueIdentifierLabel(version, pluginapi.MaximumOpaqueIdentifierVersionLength) != nil {
		return pluginapi.OpaqueIdentifierTag{}, pluginapi.ErrOpaqueIdentifierInput
	}

	keys, err := t.keysForInput(ctx, input)
	if err != nil {
		return pluginapi.OpaqueIdentifierTag{}, err
	}

	for _, key := range keys {
		if key.Version == version {
			return tagOpaqueIdentifier(input, key)
		}
	}

	return pluginapi.OpaqueIdentifierTag{}, pluginapi.ErrOpaqueIdentifierVersion
}

// Candidates explicitly returns the active and optional previous tag in rotation order.
func (t *opaqueIdentifierTagger) Candidates(ctx context.Context, input pluginapi.OpaqueIdentifierInput) ([]pluginapi.OpaqueIdentifierTag, error) {
	keys, err := t.keysForInput(ctx, input)
	if err != nil {
		return nil, err
	}

	tags := make([]pluginapi.OpaqueIdentifierTag, 0, len(keys))
	for _, key := range keys {
		tag, err := tagOpaqueIdentifier(input, key)
		if err != nil {
			return nil, err
		}

		tags = append(tags, tag)
	}

	return tags, nil
}

// keysForInput rejects cancellation, malformed input, and unconfigured scopes before processing values.
func (t *opaqueIdentifierTagger) keysForInput(ctx context.Context, input pluginapi.OpaqueIdentifierInput) ([]OpaqueIdentifierKey, error) {
	if ctx == nil {
		return nil, pluginapi.ErrOpaqueIdentifierInput
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if err := pluginapi.ValidateOpaqueIdentifierInput(input); err != nil {
		return nil, err
	}

	if t == nil {
		return nil, pluginapi.ErrOpaqueIdentifierTaggerUnavailable
	}

	keys, exists := t.scopes[input.Scope]
	if !exists {
		return nil, pluginapi.ErrOpaqueIdentifierVersion
	}

	return keys, nil
}

// tagOpaqueIdentifier uses length-prefixed type separation under a host-owned HMAC key.
func tagOpaqueIdentifier(input pluginapi.OpaqueIdentifierInput, key OpaqueIdentifierKey) (pluginapi.OpaqueIdentifierTag, error) {
	var digest []byte

	key.Secret.WithBytes(func(material []byte) {
		mac := hmac.New(sha256.New, material)
		_, _ = mac.Write([]byte("nauthilus.opaque_identifier.v1\x00"))

		for _, value := range []string{key.Version, input.Scope, input.Kind, input.Value} {
			frame := binary.BigEndian.AppendUint32(nil, uint32(len(value)))
			frame = append(frame, []byte(value)...)
			_, _ = mac.Write(frame)
			clear(frame)
		}

		digest = mac.Sum(nil)
	})

	if len(digest) != sha256.Size {
		return pluginapi.OpaqueIdentifierTag{}, errors.New("opaque identifier computation failed")
	}

	return pluginapi.NewOpaqueIdentifierTag(key.Version, base64.RawURLEncoding.EncodeToString(digest))
}

// String redacts all key-bearing state from ordinary formatting.
func (*opaqueIdentifierTagger) String() string { return opaqueIdentifierRedacted }

// GoString redacts all key-bearing state from diagnostic formatting.
func (*opaqueIdentifierTagger) GoString() string { return opaqueIdentifierRedacted }
