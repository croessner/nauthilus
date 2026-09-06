package pluginapi

// nativeArtifactIdentity is supplied by the coherent native build workflow.
var nativeArtifactIdentity string

// NativeArtifactIdentity returns the diagnostic identity shared by one host/plugin build set.
// An empty identity cannot pass native loader preflight.
func NativeArtifactIdentity() string { return nativeArtifactIdentity }
