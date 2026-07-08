// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/pluginapi/v1/password"
)

const (
	sampleEnvironmentFact = "plugin.environment.sample.present"
	sampleBackendFact     = "plugin.backend.sample.authenticated"
	sampleObligationFact  = "plugin.resource.sample.applied"
)

var (
	_ pluginapi.Plugin            = samplePlugin{}
	_ pluginapi.RuntimePlugin     = samplePlugin{}
	_ pluginapi.Backend           = sampleBackend{}
	_ pluginapi.EnvironmentSource = sampleEnvironmentSource{}
	_ pluginapi.SubjectSource     = sampleSubjectSource{}
	_ pluginapi.ObligationTarget  = sampleObligationTarget{}
	_ pluginapi.Hook              = sampleHook{}
	_ pluginapi.Hook              = sampleTextmapHook{}
)

// NauthilusPlugin returns a new plugin instance for one configured module.
func NauthilusPlugin() (pluginapi.Plugin, error) {
	return samplePlugin{}, nil
}

type samplePlugin struct{}

// Metadata returns static plugin metadata for the compile-only fixture.
func (samplePlugin) Metadata() pluginapi.Metadata {
	return pluginapi.Metadata{
		Name:        "sample",
		Version:     "v0.0.0",
		APIVersion:  pluginapi.APIVersion,
		Description: "Compile-only contract fixture.",
		Features: []pluginapi.Feature{
			"environment",
			"subject",
			"backend",
			"obligation",
			"hook",
		},
		Capabilities: []pluginapi.Capability{
			pluginapi.CapabilityCredentials,
			pluginapi.CapabilityMail,
		},
		Build: pluginapi.BuildInfo{
			GoVersion: "test",
		},
	}
}

// Register declares fixture components through the public registrar.
func (samplePlugin) Register(registrar pluginapi.Registrar) error {
	if err := registrar.RequireCapability(pluginapi.CapabilityCredentials); err != nil {
		return err
	}

	if err := registrar.RegisterPolicyAttribute(pluginapi.AttributeDefinition{
		ID:          sampleEnvironmentFact,
		Description: "Sample plugin emitted a pre-auth fact.",
		Stage:       pluginapi.PolicyStagePreAuth,
		Operations:  []pluginapi.PolicyOperation{pluginapi.PolicyOperationAuthenticate},
		ProducerTypes: []string{
			"plugin.environment",
		},
		Category: pluginapi.AttributeCategoryEnvironment,
		Type:     pluginapi.AttributeTypeBool,
	}); err != nil {
		return err
	}

	if err := registrar.RegisterPolicyAttribute(pluginapi.AttributeDefinition{
		ID:          sampleBackendFact,
		Description: "Sample plugin backend authentication result.",
		Stage:       pluginapi.PolicyStageAuthBackend,
		Operations:  []pluginapi.PolicyOperation{pluginapi.PolicyOperationAuthenticate},
		ProducerTypes: []string{
			"backend.plugin",
		},
		Category: pluginapi.AttributeCategorySubject,
		Type:     pluginapi.AttributeTypeBool,
	}); err != nil {
		return err
	}

	if err := registrar.RegisterPolicyAttribute(pluginapi.AttributeDefinition{
		ID:          sampleObligationFact,
		Description: "Sample policy-selected obligation was applied.",
		Stage:       pluginapi.PolicyStageAuthDecision,
		Operations:  []pluginapi.PolicyOperation{pluginapi.PolicyOperationAuthenticate},
		Category:    pluginapi.AttributeCategoryResource,
		Type:        pluginapi.AttributeTypeBool,
	}); err != nil {
		return err
	}

	if err := registrar.RegisterEnvironmentSource(sampleEnvironmentSource{}); err != nil {
		return err
	}

	if err := registrar.RegisterBackend(sampleBackend{}); err != nil {
		return err
	}

	if err := registrar.RegisterSubjectSource(sampleSubjectSource{}); err != nil {
		return err
	}

	if err := registrar.RegisterObligationTarget(sampleObligationTarget{}); err != nil {
		return err
	}

	if err := registrar.RegisterHook(sampleHook{}); err != nil {
		return err
	}

	if err := registrar.RegisterHook(sampleTextmapHook{name: "textmap_get", method: http.MethodGet}); err != nil {
		return err
	}

	return registrar.RegisterHook(sampleTextmapHook{name: "textmap_head", method: http.MethodHead})
}

// Start demonstrates access to host-provided immutable backend candidates.
func (samplePlugin) Start(ctx context.Context, host pluginapi.Host) error {
	_ = host.BackendServers().List(ctx)
	_ = host.Helpers().AccountTag("sample")
	_ = host.HTTP("sample")
	_ = host.Mail("sample")
	_ = pluginapi.MailMessage{
		Server:   "localhost",
		HeloName: "localhost",
		From:     "postmaster@localhost",
		To:       []string{"sample@example.test"},
		Subject:  "sample",
		Body:     "sample",
		Port:     25,
	}

	if err := host.ConnectionTargets("sample").Register(ctx, pluginapi.ConnectionTarget{
		Name:        "sample",
		Address:     "127.0.0.1:2525",
		Direction:   pluginapi.ConnectionTargetDirectionRemote,
		Description: "Sample SMTP target",
		Labels:      map[string]string{"service": "sample"},
	}); err != nil {
		return err
	}

	cache, err := host.Cache("sample")
	if err != nil {
		return err
	}

	cache.Set(ctx, "ready", true, time.Minute)

	if redis := host.Redis(); redis != nil {
		_ = redis.Keys().Key("sample:ready")
	}

	return nil
}

// Stop has no resources to release in the compile-only fixture.
func (samplePlugin) Stop(context.Context) error {
	return nil
}

type sampleBackend struct{}

// Name returns the backend component name for the compile-only fixture.
func (sampleBackend) Name() string {
	return "backend"
}

// VerifyPassword demonstrates credential-gated password verification through the public helper package.
func (sampleBackend) VerifyPassword(ctx context.Context, request pluginapi.BackendAuthRequest) (pluginapi.BackendResult, error) {
	if request.Credentials == nil {
		return pluginapi.BackendResult{UserFound: true, Account: request.Snapshot.Account, AccountField: request.Snapshot.AccountField}, nil
	}

	secret, ok := request.Credentials.Password(ctx)
	if !ok {
		return pluginapi.BackendResult{UserFound: true, Account: request.Snapshot.Account, AccountField: request.Snapshot.AccountField}, nil
	}

	matched, err := password.CompareHash("{SSHA256}9BT0VNzrkTp51/skOYDjOEFoYPN9FoGx/Gd+njZv5tEOgtl6TvODXg==", secret)
	if err != nil {
		return pluginapi.BackendResult{}, err
	}

	return pluginapi.BackendResult{
		Account:       request.Username,
		AccountField:  "uid",
		UserFound:     true,
		Authenticated: matched,
		Attributes: map[string][]string{
			"uid":             {request.Username},
			"auth_login_try":  {fmt.Sprint(request.Snapshot.AuthLoginAttempt)},
			"client_network":  {request.Snapshot.ClientNet},
			"listener_socket": {net.JoinHostPort(request.Snapshot.LocalIP, request.Snapshot.LocalPort)},
		},
		Facts: []pluginapi.PolicyFact{
			{Attribute: sampleBackendFact, Value: matched},
		},
	}, nil
}

// ListAccounts returns a deterministic account list for the compile-only fixture.
func (sampleBackend) ListAccounts(context.Context, pluginapi.AccountListRequest) (pluginapi.AccountListResult, error) {
	return pluginapi.AccountListResult{Accounts: []string{"sample"}}, nil
}

type sampleEnvironmentSource struct{}

// Descriptor returns the dependency-scheduler metadata for the source.
func (sampleEnvironmentSource) Descriptor() pluginapi.SourceDescriptor {
	return pluginapi.SourceDescriptor{
		Name:        "environment",
		Timeout:     time.Second,
		AbortPolicy: pluginapi.AbortPolicyNone,
	}
}

// Evaluate emits a sample fact and runtime delta through API-level values.
func (sampleEnvironmentSource) Evaluate(ctx context.Context, request pluginapi.EnvironmentRequest) (pluginapi.EnvironmentResult, error) {
	result := pluginapi.EnvironmentResult{
		Facts: []pluginapi.PolicyFact{
			{Attribute: sampleEnvironmentFact, Value: true},
		},
		RuntimeDelta: pluginapi.RuntimeDelta{
			Set: map[string]any{
				"plugin.environment.sample": map[string]any{
					"client_ip":      request.Snapshot.ClientIP,
					"idp_client":     request.Snapshot.IDP.ClientName,
					"mfa_completed":  request.Snapshot.IDP.MFACompleted,
					"auth_attempt":   request.Snapshot.AuthLoginAttempt,
					"tls_legacy_sni": request.Snapshot.TLS.ServerName,
				},
			},
		},
	}

	if request.Credentials != nil {
		secret, ok := request.Credentials.Password(ctx)
		result.Triggered = ok && !secret.IsZero()
	}

	return result, nil
}

type sampleSubjectSource struct{}

// Descriptor returns the dependency-scheduler metadata for the subject source.
func (sampleSubjectSource) Descriptor() pluginapi.SourceDescriptor {
	return pluginapi.SourceDescriptor{Name: "subject"}
}

// Evaluate demonstrates backend-result patching and response mutation through request-time result values.
func (sampleSubjectSource) Evaluate(_ context.Context, request pluginapi.SubjectRequest) (pluginapi.SubjectResult, error) {
	account := request.BackendResult.Account
	if account == "" {
		account = request.Snapshot.Account
	}

	accountField := request.BackendResult.AccountField
	if accountField == "" && account != "" {
		accountField = "uid"
	}

	authenticated := request.BackendResult.Authenticated

	return pluginapi.SubjectResult{
		BackendResultPatch: &pluginapi.BackendResultPatch{
			Account:       account,
			AccountField:  accountField,
			Authenticated: &authenticated,
			Attributes: pluginapi.AttributePatch{
				Set: map[string][]string{
					"sample_subject": {"seen"},
				},
			},
		},
		Logs: []pluginapi.LogField{
			{Key: "sample_subject_user_found", Value: request.BackendResult.UserFound},
		},
		Response: pluginapi.ResponseMutation{
			Headers: pluginapi.ResponseHeaderMutation{
				Set: map[string][]string{
					"X-Nauthilus-Sample": {"subject"},
				},
			},
		},
	}, nil
}

type sampleObligationTarget struct{}

// Name returns the obligation target component name.
func (sampleObligationTarget) Name() string {
	return "obligation"
}

// Execute demonstrates effect args, effect facts, status, logs, and synchronous response mutation.
func (sampleObligationTarget) Execute(_ context.Context, request pluginapi.ObligationRequest) (pluginapi.ObligationResult, error) {
	return pluginapi.ObligationResult{
		Applied: true,
		Facts: []pluginapi.PolicyFact{
			{Attribute: sampleObligationFact, Value: true},
		},
		Logs: []pluginapi.LogField{
			{Key: "sample_effect_args_empty", Value: request.Args == nil || request.Args.IsZero()},
			{Key: "sample_effect_fact_count", Value: len(request.Facts)},
		},
		Status: &pluginapi.StatusMessage{DefaultText: "sample obligation applied"},
		Response: pluginapi.ResponseMutation{
			Headers: pluginapi.ResponseHeaderMutation{
				Set: map[string][]string{
					"X-Nauthilus-Sample-Obligation": {"applied"},
				},
			},
		},
	}, nil
}

type sampleHook struct{}

// Descriptor returns the route metadata for the sample hook.
func (sampleHook) Descriptor() pluginapi.HookDescriptor {
	return pluginapi.HookDescriptor{
		Name:         "status",
		Method:       "GET",
		Path:         "/sample/status",
		Scope:        pluginapi.HookScopeInternal,
		Auth:         pluginapi.HookAuthToken,
		Timeout:      time.Second,
		MaxBodyBytes: 1024,
	}
}

// Serve returns a small API-level response without receiving server internals.
func (sampleHook) Serve(context.Context, pluginapi.HookRequest) (pluginapi.HookResponse, error) {
	return pluginapi.HookResponse{
		StatusCode: http.StatusOK,
		Headers: map[string][]string{
			"Content-Type": {"text/plain; charset=utf-8"},
		},
		Body: []byte("ok\n"),
	}, nil
}

type sampleTextmapHook struct {
	name   string
	method string
}

// Descriptor returns route metadata for the dynamic textmap-style hook.
func (h sampleTextmapHook) Descriptor() pluginapi.HookDescriptor {
	name := h.name
	if name == "" {
		name = "textmap_get"
	}

	method := h.method
	if method == "" {
		method = http.MethodGet
	}

	return pluginapi.HookDescriptor{
		Name:         name,
		Method:       method,
		Path:         "/sample/textmap",
		Alias:        "/maps/sample-textmap",
		Scope:        pluginapi.HookScopeInternal,
		Auth:         pluginapi.HookAuthToken,
		Timeout:      time.Second,
		MaxBodyBytes: 1024,
	}
}

// Serve returns textmap content through HookResponse, mirroring Lua response helpers.
func (sampleTextmapHook) Serve(_ context.Context, request pluginapi.HookRequest) (pluginapi.HookResponse, error) {
	body := sampleTextmapContent(request)
	headers := sampleTextmapHeaders(body)

	switch request.Method {
	case http.MethodGet:
		return pluginapi.HookResponse{
			StatusCode: http.StatusOK,
			Headers:    headers,
			Body:       body,
		}, nil
	case http.MethodHead:
		return pluginapi.HookResponse{
			StatusCode: http.StatusOK,
			Headers:    headers,
		}, nil
	default:
		headers["Allow"] = []string{http.MethodGet + ", " + http.MethodHead}

		return pluginapi.HookResponse{
			StatusCode: http.StatusMethodNotAllowed,
			Headers:    headers,
			Body:       []byte("Method Not Allowed\n"),
		}, nil
	}
}

// sampleTextmapContent builds deterministic newline-delimited map content.
func sampleTextmapContent(request pluginapi.HookRequest) []byte {
	version := sampleHookQueryValue(request.Query, "version", "1")
	lines := []string{
		"# sample-dynamic-textmap",
		"# version: " + version,
		"# path: " + request.Path,
		"example.com",
		fmt.Sprintf("rotate-%s.example", version),
	}

	return []byte(strings.Join(lines, "\n") + "\n")
}

// sampleTextmapHeaders builds cache-friendly headers without host-owned fields.
func sampleTextmapHeaders(body []byte) map[string][]string {
	return map[string][]string{
		"Content-Type":  {"text/plain; charset=utf-8"},
		"Cache-Control": {"no-cache"},
		"ETag":          {fmt.Sprintf("W/\"sample-%d\"", len(body))},
		"Last-Modified": {time.Now().UTC().Format(http.TimeFormat)},
	}
}

// sampleHookQueryValue returns the first query value or a fallback.
func sampleHookQueryValue(query map[string][]string, key string, fallback string) string {
	values := query[key]
	if len(values) == 0 || values[0] == "" {
		return fallback
	}

	return values[0]
}
