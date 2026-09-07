package main

import (
	"context"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

const (
	managementLookup       = "lookup"
	managementPut          = "override_put"
	managementDelete       = "override_delete"
	managementSchema       = "reputation-management.v1"
	managementOverridePath = "/reputation/override"
	managementJSON         = "application/json"
	managementPrevious     = "previous"
)

type managementHook struct {
	plugin    *Plugin
	operation string
}

// Descriptor binds exact administrative endpoints without exposing caller-selected authority.
func (h managementHook) Descriptor() pluginapi.HookDescriptor {
	method, path := http.MethodPost, "/reputation/lookup"

	switch h.operation {
	case managementAllocation:
		path = "/reputation/allocation"
	case managementPut:
		method, path = http.MethodPut, managementOverridePath
	case managementDelete:
		method, path = http.MethodDelete, managementOverridePath
	}

	return pluginapi.HookDescriptor{Name: "manage_" + h.operation, Method: method, Path: path,
		Scope: pluginapi.HookScopeAdmin, Auth: pluginapi.HookAuthAdmin, MaxBodyBytes: 4096, Timeout: 5 * time.Second}
}

// Serve accepts only host-authenticated actors and returns sanitized primary-backed results.
func (h managementHook) Serve(ctx context.Context, request pluginapi.HookRequest) (pluginapi.HookResponse, error) {
	actor := managementActor(request.Snapshot)
	if actor == "" {
		return managementError(http.StatusForbidden), nil
	}

	contentType, _, err := mime.ParseMediaType(http.Header(request.Headers).Get("Content-Type"))
	if err != nil || contentType != managementJSON {
		return managementError(http.StatusUnsupportedMediaType), nil
	}

	if h.plugin == nil || h.plugin.config == nil {
		return managementError(http.StatusServiceUnavailable), nil
	}

	if len(request.Query) != 0 {
		return managementError(http.StatusBadRequest), nil
	}

	if h.operation == managementAllocation {
		value, status := h.serveAllocation(ctx, request.Body, actor)
		if status != http.StatusOK {
			return managementError(status), nil
		}

		return managementResponse(status, value)
	}

	return h.serveSubject(ctx, request, actor)
}

// serveSubject handles exact-subject requests only while the state owner is ready.
func (h managementHook) serveSubject(ctx context.Context, request pluginapi.HookRequest, actor string) (pluginapi.HookResponse, error) {
	input, err := decodeManagementInput(request.Body, h.operation, h.plugin.config)
	if err != nil {
		return managementError(http.StatusBadRequest), nil
	}

	state, _ := h.plugin.observedState()
	if state == nil || !state.ready.Load() {
		return managementError(http.StatusServiceUnavailable), nil
	}

	value, err := state.manage(ctx, h.operation, input, actor)
	if errors.Is(err, errOverrideConflict) {
		return managementError(http.StatusConflict), nil
	}

	if err != nil {
		return managementError(http.StatusServiceUnavailable), nil
	}

	return managementResponse(http.StatusOK, value)
}

// managementActor selects only an authenticated, bounded host identity; body fields never participate.
func managementActor(snapshot pluginapi.RequestSnapshot) string {
	actor := snapshot.Username
	if actor == "" {
		actor = snapshot.OIDCCID
	}

	if !snapshot.Runtime.Authenticated || !safeAuditText(actor) {
		return ""
	}

	return actor
}

// managementResponse keeps sensitive exact-subject views out of caches and headers.
func managementResponse(status int, value any) (pluginapi.HookResponse, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return pluginapi.HookResponse{}, err
	}

	return pluginapi.HookResponse{StatusCode: status, Body: body, Headers: map[string][]string{
		"Content-Type": {managementJSON}, "Cache-Control": {"no-store"}}}, nil
}

// managementError returns only closed failure classes, never raw subjects or storage errors.
func managementError(status int) pluginapi.HookResponse {
	response, _ := managementResponse(status, map[string]string{"error": http.StatusText(status)})
	return response
}

// registerManagement exposes only the chosen administrative API, with no local command or public alias.
func (p *Plugin) registerManagement(registrar pluginapi.Registrar) error {
	for _, operation := range []string{managementLookup, managementPut, managementDelete, managementAllocation} {
		if err := registrar.RegisterHook(managementHook{plugin: p, operation: operation}); err != nil {
			return err
		}
	}

	return nil
}
