package pluginloader

import (
	"errors"
	"os"
	"regexp"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

var (
	// ErrNativeArtifactCompatibility identifies an unbound, stale, or mixed host/plugin build set.
	ErrNativeArtifactCompatibility = errors.New("native artifact does not match the host build identity")
	nativeArtifactIdentityPattern  = regexp.MustCompile(`nauthilus-native-artifact-v1:[a-f0-9]{64}:end-native-artifact`)
)

// VerifyNativeArtifactCompatibility checks a private verified artifact before any native code is opened.
func VerifyNativeArtifactCompatibility(path string) error {
	artifact, err := os.ReadFile(path)
	if err != nil {
		return ErrNativeArtifactCompatibility
	}
	defer clear(artifact)

	return validateNativeArtifactIdentity(artifact, pluginapi.NativeArtifactIdentity())
}

// validateNativeArtifactIdentity requires one exact well-formed host identity throughout the artifact.
func validateNativeArtifactIdentity(artifact []byte, expected string) error {
	if nativeArtifactIdentityPattern.FindString(expected) != expected || expected == "" {
		return ErrNativeArtifactCompatibility
	}

	identities := nativeArtifactIdentityPattern.FindAll(artifact, -1)
	if len(identities) == 0 {
		return ErrNativeArtifactCompatibility
	}

	for _, identity := range identities {
		if string(identity) != expected {
			return ErrNativeArtifactCompatibility
		}
	}

	return nil
}
