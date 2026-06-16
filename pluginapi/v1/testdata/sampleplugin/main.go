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
	"time"

	pluginapi "github.com/croessner/nauthilus/pluginapi/v1"
)

var (
	_ pluginapi.Plugin            = samplePlugin{}
	_ pluginapi.EnvironmentSource = sampleEnvironmentSource{}
	_ pluginapi.Hook              = sampleHook{}
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
			"hook",
		},
		Capabilities: []pluginapi.Capability{
			pluginapi.CapabilityCredentials,
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
		ID:          "plugin.sample.present",
		Description: "Sample plugin emitted a pre-auth fact.",
		Stage:       pluginapi.PolicyStagePreAuth,
		Operations:  []pluginapi.PolicyOperation{pluginapi.PolicyOperationAuthenticate},
		Category:    pluginapi.AttributeCategoryEnvironment,
		Type:        pluginapi.AttributeTypeBool,
	}); err != nil {
		return err
	}

	if err := registrar.RegisterEnvironmentSource(sampleEnvironmentSource{}); err != nil {
		return err
	}

	return registrar.RegisterHook(sampleHook{})
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
			{Attribute: "plugin.sample.present", Value: true},
		},
		RuntimeDelta: pluginapi.RuntimeDelta{
			Set: map[string]any{
				"sample.present": true,
			},
		},
	}

	if request.Credentials != nil {
		secret, ok := request.Credentials.Password(ctx)
		result.Triggered = ok && !secret.IsZero()
	}

	return result, nil
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
		StatusCode: 200,
		Headers: map[string][]string{
			"Content-Type": {"text/plain; charset=utf-8"},
		},
		Body: []byte("ok\n"),
	}, nil
}
