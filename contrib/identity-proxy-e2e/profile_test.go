// Copyright (C) 2026 Christian Rößner
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

package identityproxye2e

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	configDir          = "config"
	authorityConfig    = "authority.yml"
	edgeAConfig        = "edge-a.yml"
	edgeBConfig        = "edge-b.yml"
	composeFile        = "docker-compose.yml"
	browserScript      = "scripts/browser-e2e.js"
	runScript          = "scripts/run.sh"
	smokePlanFile      = "smoke-plan.yml"
	authorityName      = "authority"
	authorityData      = "authority-data"
	authorityGRPC      = "authority-grpc"
	authorityRedisAddr = "authority-redis:6379"
	edgeData           = "edge-data"
	edgeRedisAddr      = "edge-redis:6379"
	edgeClusterID      = "edge-e2e"
	privateKeyJWT      = "private_key_jwt"
	redisBackend       = "redis"
	storageSection     = "storage"
	identitySection    = "identity"
	tls13Version       = "TLS1.3"
)

var requiredAuthorityScopes = []string{
	"nauthilus:authenticate",
	"nauthilus:lookup_identity",
	"nauthilus:list_accounts",
	"nauthilus:mfa_read",
	"nauthilus:mfa_verify",
	"nauthilus:mfa_write",
	"nauthilus:webauthn_read",
	"nauthilus:webauthn_write",
	"nauthilus:attribute_read",
}

var requiredRemoteOperations = []string{
	"auth",
	"lookup_identity",
	"list_accounts",
	"mfa_read",
	"mfa_verify",
	"mfa_write",
	"webauthn_read",
	"webauthn_write",
	"attribute_read",
}

func TestSplitDeploymentProfileKeepsAuthorityAndEdgeSeparated(t *testing.T) {
	root := fixtureRoot(t)
	authority := loadYAML(t, filepath.Join(root, configDir, authorityConfig))
	edgeA := loadYAML(t, filepath.Join(root, configDir, edgeAConfig))
	edgeB := loadYAML(t, filepath.Join(root, configDir, edgeBConfig))

	assertRedisEndpoint(t, authority, authorityRedisAddr)
	assertRedisEndpoint(t, edgeA, edgeRedisAddr)
	assertRedisEndpoint(t, edgeB, edgeRedisAddr)
	assertEdgeRemoteOnly(t, edgeA, "edge-a")
	assertEdgeRemoteOnly(t, edgeB, "edge-b")
	assertAuthorityLocalOnly(t, authority)
	assertAuthorityCallerTokenProfile(t, authority)
	assertEdgeBackchannelAuth(t, edgeA, "edge-a")
	assertEdgeBackchannelAuth(t, edgeB, "edge-b")
	assertEdgeHTTPProfile(t, edgeA, "edge-a")
	assertEdgeHTTPProfile(t, edgeB, "edge-b")
	assertEdgeAuthorityClient(t, edgeA, "edge-a")
	assertEdgeAuthorityClient(t, edgeB, "edge-b")
	assertWebAuthnProfile(t, authority, "authority", "authority.example.test")
	assertWebAuthnProfile(t, edgeA, "edge-a", "split.example.test")
	assertWebAuthnProfile(t, edgeB, "edge-b", "split.example.test")
	assertEdgeWebAuthnOrigins(t, edgeA, "edge-a")
	assertEdgeWebAuthnOrigins(t, edgeB, "edge-b")
	assertSharedEdgeState(t, edgeA, edgeB)
	assertOIDCTokenLifetimes(t, authority, "authority")
	assertOIDCTokenLifetimes(t, edgeA, "edge-a")
	assertOIDCTokenLifetimes(t, edgeB, "edge-b")
}

func TestComposeNetworksPreventDirectCrossRedisAccess(t *testing.T) {
	root := fixtureRoot(t)
	compose := loadYAML(t, filepath.Join(root, composeFile))

	assertServiceNetworks(t, compose, "authority-redis", []string{authorityData})
	assertServiceNetworks(t, compose, "edge-redis", []string{edgeData})
	assertServiceNetworks(t, compose, "authority", []string{authorityData, authorityGRPC})
	assertServiceNetworks(t, compose, "edge-a", []string{edgeData, authorityGRPC})
	assertServiceNetworks(t, compose, "edge-b", []string{edgeData, authorityGRPC})
	assertServicePorts(t, compose, "authority", []string{"127.0.0.1:18081:18081", "127.0.0.1:19444:19444"})
}

func TestSmokePlanCoversPositiveNegativeAndContinuityChecks(t *testing.T) {
	root := fixtureRoot(t)
	plan := loadYAML(t, filepath.Join(root, smokePlanFile))

	got := stringSet(sequence(plan, "scenarios"))
	for _, scenario := range []string{
		"grpc-authenticate",
		"grpc-lookup-identity",
		"grpc-list-accounts",
		"grpc-resolve-user",
		"oidc-authorization-code",
		"oidc-device-code",
		"saml-sso",
		"totp-registration-login",
		"recovery-code-generation-consumption",
		"webauthn-registration-login",
		"authority-webauthn-sign-count",
		"multi-edge-oidc-continuity",
		"multi-edge-webauthn-continuity",
		"edge-no-local-credentials",
		"redis-network-separation",
		"missing-caller-auth",
		"missing-scope",
		"expired-backend-ref",
		"authority-unavailable",
		"idempotency-replay",
	} {
		if !got[scenario] {
			t.Fatalf("smoke plan missing scenario %q; got %v", scenario, sortedKeys(got))
		}
	}
}

func TestBrowserAutomationUsesCDPVirtualAuthenticator(t *testing.T) {
	root := fixtureRoot(t)

	raw, err := os.ReadFile(filepath.Join(root, browserScript))
	if err != nil {
		t.Fatalf("read browser script: %v", err)
	}

	script := string(raw)
	for _, marker := range []string{
		"WebAuthn.enable",
		"WebAuthn.addVirtualAuthenticator",
		"ctap2",
		"hasUserVerification",
		"completeRecoveryRegistration",
		"completeRecoveryLogin",
		"host-resolver-rules",
		"runMultiEdgeWebAuthnContinuity",
		"https://split.example.test",
		"OIDC callback timed out",
	} {
		if !strings.Contains(script, marker) {
			t.Fatalf("browser script missing %q marker", marker)
		}
	}
}

func assertEdgeBackchannelAuth(t *testing.T, cfg map[string]any, edgeName string) {
	t.Helper()

	bearer := mapping(cfg, "auth", "backchannel", "oidc_bearer")
	if !boolValue(bearer, "enabled") {
		t.Fatalf("%s backchannel OIDC bearer auth must be enabled", edgeName)
	}
}

func assertEdgeHTTPProfile(t *testing.T, cfg map[string]any, edgeName string) {
	t.Helper()

	tls := mapping(cfg, "runtime", "servers", "http", "tls")
	if !boolValue(tls, "enabled") {
		t.Fatalf("%s HTTP TLS must be enabled for secure browser WebAuthn flows", edgeName)
	}

	if scalar(tls, "cert") == "" || scalar(tls, "key") == "" {
		t.Fatalf("%s HTTP TLS certificate material is incomplete", edgeName)
	}

	if scalar(tls, "min_tls_version") != tls13Version {
		t.Fatalf("%s HTTP TLS min_tls_version = %q, want %s", edgeName, scalar(tls, "min_tls_version"), tls13Version)
	}
}

func assertWebAuthnProfile(t *testing.T, cfg map[string]any, label string, wantRPID string) {
	t.Helper()

	webauthn := mapping(cfg, "identity", "mfa", "webauthn")
	if scalar(webauthn, "rp_id") != wantRPID {
		t.Fatalf("%s WebAuthn rp_id = %q, want %q", label, scalar(webauthn, "rp_id"), wantRPID)
	}
}

func assertEdgeWebAuthnOrigins(t *testing.T, cfg map[string]any, label string) {
	t.Helper()

	origins := sequence(cfg, "identity", "mfa", "webauthn", "rp_origins")
	want := []string{
		"https://split.example.test:18080",
		"https://split.example.test:18082",
	}

	sort.Strings(origins)
	sort.Strings(want)

	if !reflect.DeepEqual(origins, want) {
		t.Fatalf("%s WebAuthn rp_origins = %v, want %v", label, origins, want)
	}
}

func TestRunScriptIncludesExecutablePositiveNegativeAndTopologyChecks(t *testing.T) {
	root := fixtureRoot(t)

	raw, err := os.ReadFile(filepath.Join(root, runScript))
	if err != nil {
		t.Fatalf("read run script: %v", err)
	}

	script := string(raw)
	for _, marker := range []string{
		"go run ./contrib/identity-proxy-e2e/cmd/smoke --mode pre-browser",
		"go run ./contrib/identity-proxy-e2e/cmd/smoke --mode post-browser",
		"redis-cli -h edge-redis",
		"redis-cli -h authority-redis",
	} {
		if !strings.Contains(script, marker) {
			t.Fatalf("run script missing %q marker", marker)
		}
	}
}

func fixtureRoot(t *testing.T) string {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}

	return wd
}

func loadYAML(t *testing.T, path string) map[string]any {
	t.Helper()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	var value map[string]any
	if err = yaml.Unmarshal(raw, &value); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}

	return value
}

func assertRedisEndpoint(t *testing.T, cfg map[string]any, want string) {
	t.Helper()

	got := scalar(cfg, storageSection, redisBackend, "primary", "address")
	if got != want {
		t.Fatalf("redis endpoint = %q, want %q", got, want)
	}
}

func assertEdgeRemoteOnly(t *testing.T, cfg map[string]any, edgeName string) {
	t.Helper()

	order := sequence(cfg, "auth", "backends", "order")
	if !reflect.DeepEqual(order, []string{"remote"}) {
		t.Fatalf("%s backend order = %v, want [remote]", edgeName, order)
	}

	backends := mapping(cfg, "auth", "backends")
	for _, forbidden := range []string{"ldap", "lua"} {
		if _, exists := backends[forbidden]; exists {
			t.Fatalf("%s contains forbidden local %s backend config", edgeName, forbidden)
		}
	}
}

func assertAuthorityLocalOnly(t *testing.T, cfg map[string]any) {
	t.Helper()

	order := sequence(cfg, "auth", "backends", "order")
	if !reflect.DeepEqual(order, []string{"test"}) {
		t.Fatalf("authority backend order = %v, want [test]", order)
	}

	if _, exists := mapping(cfg, "auth", "backends")["remote"]; exists {
		t.Fatal("authority must not configure an outbound remote backend")
	}

	grpc := mapping(cfg, "runtime", "servers", "grpc", "authority")
	if !boolValue(grpc, "enabled") {
		t.Fatal("authority gRPC listener is not enabled")
	}

	tls := mapping(cfg, "runtime", "servers", "grpc", "authority", "tls")
	if !boolValue(tls, "enabled") || !boolValue(tls, "require_client_cert") {
		t.Fatal("authority gRPC listener must enable TLS and require client certs")
	}

	if scalar(tls, "min_tls_version") != tls13Version {
		t.Fatalf("authority gRPC min_tls_version = %q, want %s", scalar(tls, "min_tls_version"), tls13Version)
	}
}

func assertAuthorityCallerTokenProfile(t *testing.T, cfg map[string]any) {
	t.Helper()

	bearer := mapping(cfg, "auth", "backchannel", "oidc_bearer")
	if !boolValue(bearer, "enabled") {
		t.Fatal("authority backchannel OIDC bearer auth must be enabled")
	}

	oidc := mapping(cfg, "identity", "oidc")
	if !boolValue(oidc, "enabled") {
		t.Fatal("authority OIDC must be enabled to issue caller tokens")
	}

	if scalar(oidc, "access_token_type") != "opaque" {
		t.Fatalf("authority OIDC access_token_type = %q, want opaque", scalar(oidc, "access_token_type"))
	}

	client := findClient(t, sequenceMaps(oidc, "clients"), "nauthilus-edge-e2e")
	if scalar(client, "token_endpoint_auth_method") != privateKeyJWT {
		t.Fatalf("authority caller client auth method = %q, want %s", scalar(client, "token_endpoint_auth_method"), privateKeyJWT)
	}

	if !containsAll(sequence(client, "scopes"), requiredAuthorityScopes) {
		t.Fatalf("authority caller client scopes = %v, want at least %v", sequence(client, "scopes"), requiredAuthorityScopes)
	}
}

func assertEdgeAuthorityClient(t *testing.T, cfg map[string]any, edgeName string) {
	t.Helper()

	client := mapping(cfg, "runtime", "clients", "grpc", "nauthilus_authorities", authorityName)
	if scalar(client, "edge_cluster_id") != edgeClusterID {
		t.Fatalf("%s edge_cluster_id = %q, want %q", edgeName, scalar(client, "edge_cluster_id"), edgeClusterID)
	}

	if scalar(client, "edge_instance_id") != edgeName {
		t.Fatalf("%s edge_instance_id = %q", edgeName, scalar(client, "edge_instance_id"))
	}

	assertAuthorityClientTLS(t, client, edgeName)
	assertAuthorityClientBearer(t, client, edgeName)
	assertRemoteBackendOperations(t, cfg, edgeName)
}

func assertAuthorityClientTLS(t *testing.T, client map[string]any, edgeName string) {
	t.Helper()

	tls := mapping(client, "tls")
	if !boolValue(tls, "enabled") || scalar(tls, "min_tls_version") != tls13Version {
		t.Fatalf("%s authority client TLS profile is incomplete: %v", edgeName, tls)
	}

	for _, key := range []string{"ca", "cert", "key"} {
		if scalar(tls, key) == "" {
			t.Fatalf("%s authority client TLS missing %s", edgeName, key)
		}
	}
}

func assertAuthorityClientBearer(t *testing.T, client map[string]any, edgeName string) {
	t.Helper()

	bearer := mapping(client, "caller_auth", "oidc_bearer")
	if !boolValue(bearer, "enabled") {
		t.Fatalf("%s authority bearer auth is not enabled", edgeName)
	}

	if scalar(bearer, "token_endpoint_auth_method") != privateKeyJWT {
		t.Fatalf("%s token endpoint auth method = %q, want %s", edgeName, scalar(bearer, "token_endpoint_auth_method"), privateKeyJWT)
	}

	if scalar(mapping(bearer, "token_cache"), "backend") != redisBackend {
		t.Fatalf("%s authority token cache must use edge Redis", edgeName)
	}

	if !containsAll(sequence(bearer, "scopes"), requiredAuthorityScopes) {
		t.Fatalf("%s caller scopes = %v, want at least %v", edgeName, sequence(bearer, "scopes"), requiredAuthorityScopes)
	}
}

func assertRemoteBackendOperations(t *testing.T, cfg map[string]any, edgeName string) {
	t.Helper()

	remote := mapping(cfg, "auth", "backends", "remote", "default")
	if scalar(remote, "authority") != authorityName {
		t.Fatalf("%s remote authority = %q, want %q", edgeName, scalar(remote, "authority"), authorityName)
	}

	if !containsAll(sequence(remote, "allowed_operations"), requiredRemoteOperations) {
		t.Fatalf("%s remote operations = %v, want at least %v", edgeName, sequence(remote, "allowed_operations"), requiredRemoteOperations)
	}
}

func assertSharedEdgeState(t *testing.T, edgeA map[string]any, edgeB map[string]any) {
	t.Helper()

	sharedScalars := [][]string{
		{storageSection, redisBackend, "primary", "address"},
		{storageSection, redisBackend, "prefix"},
		{identitySection, "frontend", "encryption_secret"},
		{identitySection, "oidc", "issuer"},
	}
	for _, path := range sharedScalars {
		gotA, gotB := sharedScalarValues(edgeA, edgeB, path)

		if gotA == "" || gotA != gotB {
			t.Fatalf("edge shared scalar %s differs: %q != %q", strings.Join(path, "."), gotA, gotB)
		}
	}
}

func sharedScalarValues(edgeA map[string]any, edgeB map[string]any, path []string) (string, string) {
	return scalar(edgeA, path...), scalar(edgeB, path...)
}

func assertOIDCTokenLifetimes(t *testing.T, cfg map[string]any, label string) {
	t.Helper()

	tokens := mapping(cfg, "identity", "oidc", "tokens")
	if scalar(tokens, "default_access_token_lifetime") == "" {
		t.Fatalf("%s OIDC tokens.default_access_token_lifetime is missing", label)
	}

	if scalar(tokens, "default_refresh_token_lifetime") == "" {
		t.Fatalf("%s OIDC tokens.default_refresh_token_lifetime is missing", label)
	}
}

func assertServiceNetworks(t *testing.T, compose map[string]any, service string, want []string) {
	t.Helper()

	got := sequence(compose, "services", service, "networks")
	if len(got) == 0 {
		got = sortedMapKeys(mapping(compose, "services", service, "networks"))
	}

	sort.Strings(got)
	sort.Strings(want)

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("service %s networks = %v, want %v", service, got, want)
	}
}

func assertServicePorts(t *testing.T, compose map[string]any, service string, want []string) {
	t.Helper()

	got := sequence(compose, "services", service, "ports")
	sort.Strings(got)
	sort.Strings(want)

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("service %s ports = %v, want %v", service, got, want)
	}
}

func mapping(root map[string]any, path ...string) map[string]any {
	var current any = root
	for _, part := range path {
		node, ok := current.(map[string]any)
		if !ok {
			return nil
		}

		current = node[part]
	}

	result, _ := current.(map[string]any)

	return result
}

func scalar(root map[string]any, path ...string) string {
	var current any = root
	for _, part := range path {
		node, ok := current.(map[string]any)
		if !ok {
			return ""
		}

		current = node[part]
	}

	switch value := current.(type) {
	case string:
		return value
	default:
		return ""
	}
}

func sequence(root map[string]any, path ...string) []string {
	var current any = root
	for _, part := range path {
		node, ok := current.(map[string]any)
		if !ok {
			return nil
		}

		current = node[part]
	}

	values, ok := current.([]any)
	if !ok {
		return nil
	}

	result := make([]string, 0, len(values))
	for _, value := range values {
		if text, ok := value.(string); ok {
			result = append(result, text)
		}
	}

	return result
}

func sequenceMaps(root map[string]any, path ...string) []map[string]any {
	var current any = root
	for _, part := range path {
		node, ok := current.(map[string]any)
		if !ok {
			return nil
		}

		current = node[part]
	}

	values, ok := current.([]any)
	if !ok {
		return nil
	}

	result := make([]map[string]any, 0, len(values))
	for _, value := range values {
		if node, ok := value.(map[string]any); ok {
			result = append(result, node)
		}
	}

	return result
}

func boolValue(root map[string]any, key string) bool {
	if root == nil {
		return false
	}

	value, _ := root[key].(bool)

	return value
}

func findClient(t *testing.T, clients []map[string]any, clientID string) map[string]any {
	t.Helper()

	for _, client := range clients {
		if scalar(client, "client_id") == clientID {
			return client
		}
	}

	t.Fatalf("client %q not found", clientID)

	return nil
}

func containsAll(got []string, want []string) bool {
	index := stringSet(got)
	for _, value := range want {
		if !index[value] {
			return false
		}
	}

	return true
}

func stringSet(values []string) map[string]bool {
	result := make(map[string]bool, len(values))
	for _, value := range values {
		result[value] = true
	}

	return result
}

func sortedKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	return keys
}

func sortedMapKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	return keys
}
