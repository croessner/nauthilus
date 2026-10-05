package pluginruntime

import (
	"encoding/json"
	"reflect"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/core"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
)

// PositivePasswordCacheEnabled returns the registration-time joint plugin/operator admission.
func (m *BackendManager) PositivePasswordCacheEnabled() bool {
	if m == nil || m.runner == nil || !m.runner.Ready() {
		return false
	}

	component, ok := m.runner.registry.Lookup(m.qualifiedName)

	return ok && component.Kind == pluginregistry.ComponentKindBackend && component.PositivePasswordCache
}

// encodePositivePasswordCache admits only complete successful results with lossless JSON values.
func (m *BackendManager) encodePositivePasswordCache(auth *core.AuthState, result pluginapi.BackendResult) string {
	if !m.PositivePasswordCacheEnabled() || !result.Authenticated || !result.UserFound {
		return ""
	}

	data, err := json.Marshal(result)
	if err != nil {
		return ""
	}

	var restored pluginapi.BackendResult
	if json.Unmarshal(data, &restored) != nil || !reflect.DeepEqual(result, restored) {
		return ""
	}

	envelope, err := json.Marshal(pluginPasswordCacheEnvelope{
		Version: 1, Username: auth.Request.Username, Protocol: auth.Request.Protocol.Get(), OIDCClientID: auth.Request.OIDCCID, Result: restored,
	})
	if err != nil {
		return ""
	}

	return string(envelope)
}

// RestorePositivePasswordCache reuses the live adapter to reconstruct identity, status and typed facts.
func (m *BackendManager) RestorePositivePasswordCache(auth *core.AuthState, payload string) (*core.PassDBResult, error) {
	if !m.PositivePasswordCacheEnabled() || payload == "" {
		return nil, nil
	}

	var envelope pluginPasswordCacheEnvelope
	if err := json.Unmarshal([]byte(payload), &envelope); err != nil {
		return nil, m.temporaryError()
	}

	if !envelope.matches(auth) {
		return nil, nil
	}

	result := envelope.Result
	if !result.Authenticated || !result.UserFound || (result.Status != nil && result.Status.Temporary) {
		return nil, nil
	}

	mapped, err := m.passDBResult(auth, result)
	if err != nil {
		return nil, err
	}

	applyPluginStatus(auth, result.Status)

	return mapped, nil
}

// pluginPasswordCacheEnvelope binds a stable result to its request identity scope.
type pluginPasswordCacheEnvelope struct {
	Result       pluginapi.BackendResult
	Username     string
	Protocol     string
	OIDCClientID string
	Version      int
}

// matches prevents reuse across payload versions or request identity scopes.
func (e pluginPasswordCacheEnvelope) matches(auth *core.AuthState) bool {
	return e.Version == 1 && e.Username == auth.Request.Username && e.Protocol == auth.Request.Protocol.Get() && e.OIDCClientID == auth.Request.OIDCCID
}
