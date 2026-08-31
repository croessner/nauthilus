// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package config

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/croessner/nauthilus/v4/server/definitions"
)

// ProductionArtifactManifest groups file material by its live process owner.
type ProductionArtifactManifest struct {
	RedisTLS           []string `mapstructure:"-"`
	LDAP               []string `mapstructure:"-"`
	Lua                []string `mapstructure:"-"`
	LuaPackagePatterns []string `mapstructure:"-"`
	StartupLua         []string `mapstructure:"-"`
	PolicyLua          []string `mapstructure:"-"`
	HTTPClientTLS      []string `mapstructure:"-"`
	Identity           []string `mapstructure:"-"`
	RemoteAuthority    []string `mapstructure:"-"`
	Hooks              []string `mapstructure:"-"`
	Transport          []string `mapstructure:"-"`
	Plugins            []string `mapstructure:"-"`
	OptionalPlugins    []string `mapstructure:"-"`
	FrontendGlobs      []string `mapstructure:"-"`
	FrontendTrees      []string `mapstructure:"-"`
}

// SnapshotSpec flattens the owner groups into one atomic exact-byte capture.
func (m ProductionArtifactManifest) SnapshotSpec() ArtifactSnapshotSpec {
	paths := make([]string, 0)
	paths = append(paths, m.RedisTLS...)
	paths = append(paths, m.LDAP...)
	paths = append(paths, m.Lua...)
	paths = append(paths, m.StartupLua...)
	paths = append(paths, m.PolicyLua...)
	paths = append(paths, m.HTTPClientTLS...)
	paths = append(paths, m.Identity...)
	paths = append(paths, m.RemoteAuthority...)
	paths = append(paths, m.Hooks...)
	paths = append(paths, m.Transport...)
	paths = append(paths, m.Plugins...)

	return ArtifactSnapshotSpec{
		Paths:              paths,
		OptionalPaths:      append([]string(nil), m.OptionalPlugins...),
		Globs:              append([]string(nil), m.FrontendGlobs...),
		Trees:              append([]string(nil), m.FrontendTrees...),
		LuaPackagePatterns: append([]string(nil), m.LuaPackagePatterns...),
	}
}

// ProductionArtifactSnapshotSpec returns every file or directory pattern consumed by live process owners.
func ProductionArtifactSnapshotSpec(configured File) ArtifactSnapshotSpec {
	return ProductionArtifactManifestFor(configured).SnapshotSpec()
}

// ProductionArtifactManifestFor projects exact file inputs without opening them.
func ProductionArtifactManifestFor(configured File) ProductionArtifactManifest {
	if configured == nil {
		return ProductionArtifactManifest{}
	}

	server := configured.GetServer()
	lua := configured.GetLua()
	luaPackagePatterns := EffectiveLuaPackagePatterns(configured)
	manifest := ProductionArtifactManifest{
		RedisTLS:           artifactTLSPaths(*server.GetRedis().GetTLS()),
		LDAP:               artifactLDAPPaths(configured.GetLDAP()),
		Lua:                artifactLuaProcessPaths(lua),
		LuaPackagePatterns: luaPackagePatterns,
		StartupLua:         artifactLuaStartupPaths(lua),
		PolicyLua:          artifactPolicyLuaPaths(configured),
		HTTPClientTLS:      artifactHTTPClientTLSPaths(server.GetHTTPClient()),
		Identity:           artifactIdentityPaths(configured.GetIDP()),
		RemoteAuthority:    artifactRemoteAuthorityPaths(configured),
		Hooks:              artifactHookPaths(lua.GetHooks()),
		Transport:          artifactTransportPaths(configured, server),
		Plugins:            artifactRequiredPluginPaths(configured.GetPlugins()),
		OptionalPlugins:    artifactOptionalPluginPaths(configured.GetPlugins()),
	}

	if frontend := server.GetFrontend(); frontend != nil && frontend.HTMLStaticContentPath != "" {
		manifest.FrontendGlobs = []string{filepath.Join(frontend.HTMLStaticContentPath, "*.html")}

		assetBase := filepath.Clean(frontend.HTMLStaticContentPath)
		if filepath.Base(assetBase) == "templates" {
			assetBase = filepath.Dir(assetBase)
		}

		for _, directory := range []string{"css", "js", "img", "fonts"} {
			manifest.FrontendTrees = append(manifest.FrontendTrees, filepath.Join(assetBase, directory))
		}
	}

	return manifest
}

// EffectiveLuaPackagePatterns returns the one ordered module search authority used by every Lua runtime.
func EffectiveLuaPackagePatterns(configured File) []string {
	patterns := make([]string, 0, 4)

	seen := make(map[string]struct{}, 4)
	for _, pattern := range [...]string{
		definitions.LuaPackagePathLocal,
		definitions.LuaPackagePathDistribution,
		definitions.LuaPackagePathApplication,
	} {
		patterns = appendUniqueLuaPackagePattern(patterns, seen, pattern)
	}

	if configured == nil {
		return patterns
	}

	for _, pattern := range strings.Split(configured.GetLuaPackagePath(), ";") {
		patterns = appendUniqueLuaPackagePattern(patterns, seen, pattern)
	}

	return patterns
}

// LuaModuleTreeRoot derives the exact directory membership root for one Lua package pattern.
func LuaModuleTreeRoot(pattern string) (string, error) {
	pattern = strings.TrimSpace(pattern)
	if strings.Count(pattern, "?") != 1 {
		return "", fmt.Errorf("lua module pattern %q must contain exactly one placeholder", pattern)
	}

	marker := strings.IndexByte(pattern, '?')
	prefix := pattern[:marker]

	root := filepath.Clean(prefix)
	if !strings.HasSuffix(prefix, string(filepath.Separator)) {
		root = filepath.Dir(prefix)
	}

	return root, nil
}

// appendUniqueLuaPackagePattern retains first-match precedence while removing duplicate patterns.
func appendUniqueLuaPackagePattern(patterns []string, seen map[string]struct{}, raw string) []string {
	pattern := strings.TrimSpace(raw)
	if pattern == "" {
		return patterns
	}

	if _, exists := seen[pattern]; exists {
		return patterns
	}

	seen[pattern] = struct{}{}

	return append(patterns, pattern)
}

// artifactPolicyLuaPaths returns every top-level Policy provider and effect program deterministically.
func artifactPolicyLuaPaths(configured File) []string {
	policy := configured.GetPolicy()

	namespaceNames := make([]string, 0, len(policy.Namespaces))
	for namespaceName := range policy.Namespaces {
		namespaceNames = append(namespaceNames, namespaceName)
	}

	sort.Strings(namespaceNames)

	paths := make([]string, 0)

	for _, namespaceName := range namespaceNames {
		namespace := policy.Namespaces[namespaceName]
		for _, path := range namespace.SchemaContributions.Lua.RegistryScripts {
			if path != "" {
				paths = append(paths, path)
			}
		}

		providerNames := make([]string, 0, len(namespace.Providers))
		for providerName := range namespace.Providers {
			providerNames = append(providerNames, providerName)
		}

		sort.Strings(providerNames)

		for _, providerName := range providerNames {
			if path := namespace.Providers[providerName].ScriptPath; path != "" {
				paths = append(paths, path)
			}
		}

		effectNames := make([]string, 0, len(namespace.Effects))
		for effectName := range namespace.Effects {
			effectNames = append(effectNames, effectName)
		}

		sort.Strings(effectNames)

		for _, effectName := range effectNames {
			if path := namespace.Effects[effectName].ScriptPath; path != "" {
				paths = append(paths, path)
			}
		}
	}

	return paths
}

// artifactTLSPaths returns one TLS owner's trust and identity paths.
func artifactTLSPaths(configured TLS) []string {
	return []string{configured.CAFile, configured.Cert, configured.Key}
}

// artifactHTTPClientTLSPaths returns Lua HTTP VM trust and identity paths.
func artifactHTTPClientTLSPaths(client *HTTPClient) []string {
	if client == nil {
		return nil
	}

	return []string{client.TLS.CAFile, client.TLS.Cert, client.TLS.Key}
}

// artifactLDAPPaths returns every default and named LDAP TLS input.
func artifactLDAPPaths(ldap *LDAPSection) []string {
	if ldap == nil {
		return nil
	}

	paths := appendLDAPArtifactPaths(nil, ldap.Config)
	for _, optional := range ldap.OptionalLDAPPools {
		paths = appendLDAPArtifactPaths(paths, optional)
	}

	return paths
}

// appendLDAPArtifactPaths adds one LDAP pool's trust and client identity.
func appendLDAPArtifactPaths(paths []string, configured *LDAPConf) []string {
	if configured == nil {
		return paths
	}

	return append(paths, configured.TLSCAFile, configured.TLSClientCert, configured.TLSClientKey)
}

// artifactLuaProcessPaths returns backend and cache-flush programs owned by process runtimes.
func artifactLuaProcessPaths(lua *LuaSection) []string {
	if lua == nil {
		return nil
	}

	paths := appendLuaProcessPaths(nil, lua.Config)
	for _, optional := range lua.OptionalLuaBackends {
		paths = appendLuaProcessPaths(paths, optional)
	}

	return paths
}

// appendLuaProcessPaths adds one Lua backend's process-owned programs.
func appendLuaProcessPaths(paths []string, configured *LuaConf) []string {
	if configured == nil {
		return paths
	}

	return append(paths, configured.BackendScriptPath, configured.CacheFlushScriptPath)
}

// artifactLuaStartupPaths returns initialization programs owned by StartupCatalog.
func artifactLuaStartupPaths(lua *LuaSection) []string {
	if lua == nil {
		return nil
	}

	paths := appendLuaStartupPaths(nil, lua.Config)
	for _, optional := range lua.OptionalLuaBackends {
		paths = appendLuaStartupPaths(paths, optional)
	}

	return paths
}

// appendLuaStartupPaths adds one Lua backend's startup initialization programs.
func appendLuaStartupPaths(paths []string, configured *LuaConf) []string {
	if configured == nil {
		return paths
	}

	paths = append(paths, configured.InitScriptPath)

	return append(paths, configured.InitScriptPaths...)
}

// artifactHookPaths returns every request-hook program.
func artifactHookPaths(hooks []LuaHooks) []string {
	paths := make([]string, 0, len(hooks))
	for _, hook := range hooks {
		paths = append(paths, hook.ScriptPath)
	}

	return paths
}

// artifactIdentityPaths returns OIDC and SAML key or certificate files.
func artifactIdentityPaths(identity *IDPSection) []string {
	if identity == nil {
		return nil
	}

	paths := []string{identity.SAML2.CertFile, identity.SAML2.KeyFile}
	for _, key := range identity.OIDC.SigningKeys {
		paths = append(paths, key.KeyFile)
	}

	for _, client := range identity.OIDC.Clients {
		paths = append(paths, client.ClientPublicKeyFile)
	}

	for _, provider := range identity.SAML2.ServiceProviders {
		paths = append(paths, provider.CertFile)
	}

	return paths
}

type artifactAuthorityProvider interface {
	GetNauthilusAuthorityClients() map[string]*NauthilusAuthorityClientSection
}

// artifactRemoteAuthorityPaths returns outbound trust, caller token, and assertion-key files.
func artifactRemoteAuthorityPaths(configured File) []string {
	provider, ok := configured.(artifactAuthorityProvider)
	if !ok {
		return nil
	}

	paths := make([]string, 0)

	for _, client := range provider.GetNauthilusAuthorityClients() {
		if client == nil {
			continue
		}

		paths = append(paths, client.TLS.CA, client.TLS.Cert, client.TLS.Key)
		paths = append(paths, client.CallerAuth.OIDCBearer.StaticTokenFile)
		paths = append(paths, client.CallerAuth.OIDCBearer.ClientPrivateKeyFile)
	}

	return paths
}

// artifactTransportPaths returns HTTP, tracing, and gRPC listener TLS inputs.
func artifactTransportPaths(configured File, server *ServerSection) []string {
	paths := artifactTLSPaths(*server.GetTLS())
	paths = append(paths, artifactTLSPaths(server.GetInsights().Tracing.TLS)...)
	security := server.GetSecurityTxt()
	paths = append(paths, security.GetEncryptionFile(), security.GetPolicyFile())

	provider, ok := configured.(RuntimeGRPCAuthServerProvider)
	if !ok {
		return paths
	}

	tls := provider.GetRuntimeGRPCAuthServer().GetTLS()

	return append(paths, tls.Cert, tls.Key, tls.ClientCA)
}

// artifactRequiredPluginPaths returns signer and mandatory module inputs verified at boot.
func artifactRequiredPluginPaths(plugins *PluginsSection) []string {
	if plugins == nil {
		return nil
	}

	paths := make([]string, 0, len(plugins.Trust.Signers)+(2*len(plugins.Modules)))
	for _, signer := range plugins.Trust.Signers {
		paths = append(paths, signer.PublicKeyFile)
	}

	for _, module := range plugins.Modules {
		if module.Optional {
			continue
		}

		paths = append(paths, module.Path)
		if module.Signature == "" {
			continue
		}

		reference, err := ParsePluginSignatureRef(module.Signature)
		if err == nil {
			paths = append(paths, reference.Path)
		}
	}

	return paths
}

// artifactOptionalPluginPaths records both present and expected-absent optional module inputs.
func artifactOptionalPluginPaths(plugins *PluginsSection) []string {
	if plugins == nil {
		return nil
	}

	paths := make([]string, 0, 2*len(plugins.Modules))
	for _, module := range plugins.Modules {
		if !module.Optional {
			continue
		}

		paths = append(paths, module.Path)
		if module.Signature == "" {
			continue
		}

		reference, err := ParsePluginSignatureRef(module.Signature)
		if err == nil {
			paths = append(paths, reference.Path)
		}
	}

	return paths
}
