package pluginruntime

import (
	"context"
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

	scope, allowed := m.positivePasswordCacheScope(auth)
	if !allowed {
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
		Version: 1, Scope: scope, Username: auth.Request.Username, Protocol: auth.Request.Protocol.Get(), OIDCClientID: auth.Request.OIDCCID, Result: restored,
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

	scope, allowed := m.positivePasswordCacheScope(auth)
	if !allowed || !envelope.matches(auth) || envelope.Scope != scope {
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
	Scope        string
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

// positivePasswordCacheScope evaluates optional identity scoping behind the host panic boundary.
func (m *BackendManager) positivePasswordCacheScope(auth *core.AuthState) (string, bool) {
	snapshot := NewRequestSnapshotFromAuthState(auth, WithSnapshotConfig(auth.Cfg()))
	result, err := invokeTypedComponent(auth.Ctx(), m.runner, m.qualifiedName, pluginregistry.ComponentKindBackend,
		"PositivePasswordCacheScope", func(_ context.Context, backend pluginapi.Backend) (passwordCacheScope, error) {
			scoped, ok := backend.(pluginapi.PositivePasswordCacheScopeBackend)
			if !ok {
				return passwordCacheScope{allowed: true}, nil
			}

			scope, allowed := scoped.PositivePasswordCacheScope(snapshot)

			return passwordCacheScope{value: scope, allowed: allowed}, nil
		})

	return result.value, err == nil && result.allowed
}

// passwordCacheScope carries one pure identity scope through the invocation boundary.
type passwordCacheScope struct {
	value   string
	allowed bool
}

// PasswordCacheScopeMatches protects local cache reuse before cached evidence mutates the request.
func (m *BackendManager) PasswordCacheScopeMatches(auth *core.AuthState, payload string) bool {
	if m == nil || m.runner == nil || !m.runner.Ready() {
		return false
	}

	component, found := m.runner.registry.Lookup(m.qualifiedName)
	if !found {
		return false
	}

	if _, scoped := component.Value.(pluginapi.PositivePasswordCacheScopeBackend); !scoped {
		return true
	}

	if !m.PositivePasswordCacheEnabled() {
		return false
	}

	var envelope pluginPasswordCacheEnvelope
	if json.Unmarshal([]byte(payload), &envelope) != nil || !envelope.matches(auth) {
		return false
	}

	scope, allowed := m.positivePasswordCacheScope(auth)

	return allowed && envelope.Scope == scope
}
