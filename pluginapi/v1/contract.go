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

package pluginapi

import "context"

// Capability names a host-controlled permission a plugin may request.
type Capability string

// CapabilityCredentials allows a module instance to access request-scoped credentials.
const CapabilityCredentials Capability = "credentials"

// Feature names optional behavior inside a compatible API version.
type Feature string

// BuildInfo describes diagnostic build metadata for a plugin artifact.
type BuildInfo struct {
	BuildTags []string
	GoVersion string
	GitCommit string
	BuildTime string
}

// Metadata describes the plugin product before instance registration.
type Metadata struct {
	Build        BuildInfo
	Name         string
	Version      string
	APIVersion   string
	Description  string
	DocsURL      string
	Features     []Feature
	Capabilities []Capability
}

// Plugin is implemented by every native Go plugin factory result.
type Plugin interface {
	Metadata() Metadata
	Register(Registrar) error
}

// RuntimePlugin is implemented by plugins that need host services or lifecycle hooks.
type RuntimePlugin interface {
	Start(context.Context, Host) error
	Stop(context.Context) error
}

// ReloadablePlugin is implemented by plugins that support config-only reloads.
type ReloadablePlugin interface {
	Reconfigure(context.Context, ConfigView) error
}

// ConfigView exposes a read-only, format-neutral plugin configuration subtree.
type ConfigView interface {
	Get(path string) (any, bool)
	GetPath(path []string) (any, bool)
	Sub(path string) ConfigView
	SubPath(path []string) ConfigView
	Decode(target any) error
	IsZero() bool
}

// ArgsView exposes read-only, format-neutral policy effect arguments.
type ArgsView interface {
	Get(path string) (any, bool)
	GetPath(path []string) (any, bool)
	Sub(path string) ArgsView
	SubPath(path []string) ArgsView
	Decode(target any) error
	IsZero() bool
}

// Registrar records the components declared by one configured plugin module instance.
type Registrar interface {
	Config() ConfigView
	RequireCapability(Capability) error
	RegisterInitTask(InitTask) error
	RegisterEnvironmentSource(EnvironmentSource) error
	RegisterSubjectSource(SubjectSource) error
	RegisterBackend(Backend) error
	RegisterObligationTarget(ObligationTarget) error
	RegisterPostActionTarget(PostActionTarget) error
	RegisterHook(Hook) error
	RegisterPolicyAttribute(AttributeDefinition) error
}

// Host exposes runtime services through narrow facades managed by Nauthilus.
type Host interface {
	ServiceContext() context.Context
	Logger(scope string) Logger
	Tracer(scope string) Tracer
	Metrics(scope string) Metrics
	Redis() Redis
	LDAP() LDAP
	Policy() Policy
	Config() ConfigView
	Go(ctx context.Context, name string, fn func(context.Context) error)
}

// Logger records structured plugin log messages through the host logger.
type Logger interface {
	Debug(context.Context, string, ...LogField)
	Info(context.Context, string, ...LogField)
	Warn(context.Context, string, ...LogField)
	Error(context.Context, string, ...LogField)
}
