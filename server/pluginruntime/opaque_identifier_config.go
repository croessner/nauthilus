package pluginruntime

import (
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/secret"
)

// OpaqueIdentifierTaggerFromConfig resolves host-only keys from the sealed candidate snapshot.
func OpaqueIdentifierTaggerFromConfig(cfg config.File) (pluginapi.OpaqueIdentifierTagger, error) {
	if cfg == nil || cfg.GetPlugins() == nil || cfg.GetPlugins().OpaqueIdentifierTagger == nil {
		return nil, nil
	}

	configured := cfg.GetPlugins().OpaqueIdentifierTagger
	if err := config.ValidateOpaqueIdentifierTaggerConfig(configured); err != nil {
		return nil, err
	}

	snapshot, err := config.ArtifactSnapshotFor(cfg)
	if err != nil {
		return nil, pluginapi.ErrOpaqueIdentifierTaggerUnavailable
	}

	scopes := make([]OpaqueIdentifierScopeKeys, 0, len(configured.Scopes))
	for _, scope := range configured.Scopes {
		active, err := readOpaqueIdentifierKey(snapshot, scope.Active)
		if err != nil {
			return nil, err
		}

		keys := OpaqueIdentifierScopeKeys{Scope: scope.Scope, Active: active}
		if scope.Previous != nil {
			previous, err := readOpaqueIdentifierKey(snapshot, *scope.Previous)
			if err != nil {
				return nil, err
			}

			keys.Previous = &previous
		}

		scopes = append(scopes, keys)
	}

	return NewOpaqueIdentifierTagger(scopes)
}

// readOpaqueIdentifierKey never reads mutable live paths or includes key bytes in errors.
func readOpaqueIdentifierKey(snapshot *config.ArtifactSnapshot, reference config.OpaqueIdentifierKeyReference) (OpaqueIdentifierKey, error) {
	content, err := snapshot.ReadFile(reference.SecretRef.File)
	if err != nil {
		return OpaqueIdentifierKey{}, pluginapi.ErrOpaqueIdentifierTaggerUnavailable
	}
	defer clear(content)

	if len(content) != opaqueIdentifierKeySize {
		return OpaqueIdentifierKey{}, pluginapi.ErrOpaqueIdentifierInput
	}

	return OpaqueIdentifierKey{Version: reference.Version, Secret: secret.FromBytes(content)}, nil
}
