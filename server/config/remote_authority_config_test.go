package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
)

const (
	remoteAuthorityTestName             = "edge"
	remoteAuthorityTestBackendName      = RemoteBackendDefaultName
	remoteAuthorityAddressPath          = "runtime.clients.grpc.nauthilus_authorities.edge.address"
	remoteAuthorityOIDCEnabledPath      = "runtime.clients.grpc.nauthilus_authorities.edge.caller_auth.oidc_bearer.enabled"
	remoteAuthorityAllowedOperationsKey = "allowed_operations"
	remoteAuthorityEnabledKey           = "enabled"
	remoteAuthorityAddressKey           = "address"
	remoteAuthorityClientIDKey          = "client_id"
	remoteAuthorityClientSecretKey      = "client_secret"
	remoteAuthorityAuthorityKey         = "authority"
	remoteAuthorityModeKey              = "mode"
	remoteAuthorityStaticTokenFilePath  = "runtime.clients.grpc.nauthilus_authorities.edge.caller_auth.oidc_bearer.static_token_file"
	remoteAuthorityClientID             = "edge-client"
	remoteAuthorityClientSecret         = "edge-secret"
	remoteAuthorityTokenEndpoint        = "https://authority.example.test/oidc/token"
	remoteAuthorityLoopbackAddress      = "127.0.0.1:9444"
	remoteAuthoritySplitAddress         = "192.0.2.10:9444"
	remoteAuthorityEnvClusterID         = "cluster-from-env"
)

func TestRemoteAuthorityConfigLoadsValidatesDumpsAndBindsEnv(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)

	setDefaultEnvVars()
	setRemoteAuthorityStorage(t)
	setRemoteAuthorityConfig(t, remoteAuthorityLoopbackAddress)

	t.Setenv("NAUTHILUS_RUNTIME_CLIENTS_GRPC_NAUTHILUS_AUTHORITIES_EDGE_EDGE_CLUSTER_ID", remoteAuthorityEnvClusterID)

	if err := bindEnvs(&FileSettings{}); err != nil {
		t.Fatalf("bindEnvs() error = %v", err)
	}

	cfg := &FileSettings{}
	if err := cfg.HandleFile(); err != nil {
		t.Fatalf("HandleFile() error = %v", err)
	}

	authority, ok := cfg.GetNauthilusAuthorityClient(remoteAuthorityTestName)
	if !ok {
		t.Fatal("authority edge not loaded")
	}

	assertRemoteAuthorityLoaded(t, cfg, authority)

	defaultDump, err := RenderDefaultConfigDump()
	if err != nil {
		t.Fatalf("RenderDefaultConfigDump() error = %v", err)
	}

	assertContainsAll(t, defaultDump, []string{
		`runtime.clients.grpc.nauthilus_authorities = {}`,
		`auth.backends.remote = {}`,
	})

	settings := viper.AllSettings()

	nonDefaultDump, err := RenderNonDefaultConfigDump(settings)
	if err != nil {
		t.Fatalf("RenderNonDefaultConfigDump() error = %v", err)
	}

	assertContainsAll(t, nonDefaultDump, []string{
		`runtime.clients.grpc.nauthilus_authorities.edge.address = "127.0.0.1:9444"`,
		`runtime.clients.grpc.nauthilus_authorities.edge.caller_auth.oidc_bearer.client_secret = "***REDACTED***"`,
		`auth.backends.remote.default.authority = "edge"`,
		`auth.backends.remote.default.allowed_operations = ["auth", "lookup_identity", "list_accounts"]`,
	})

	if strings.Contains(nonDefaultDump, remoteAuthorityClientSecret) {
		t.Fatalf("dump exposed caller secret: %q", nonDefaultDump)
	}
}

func TestRemoteAuthorityConfigValidation(t *testing.T) {
	for _, testCase := range remoteAuthorityValidationCases(t) {
		t.Run(testCase.name, func(t *testing.T) {
			viper.Reset()
			t.Cleanup(viper.Reset)

			setDefaultEnvVars()
			setRemoteAuthorityStorage(t)
			setRemoteAuthorityConfig(t, remoteAuthorityLoopbackAddress)
			testCase.mutate()

			cfg := &FileSettings{}

			err := cfg.HandleFile()
			if err == nil {
				t.Fatal("HandleFile() error = nil, want validation error")
			}

			if !strings.Contains(err.Error(), testCase.wantErr) {
				t.Fatalf("HandleFile() error = %q, want substring %q", err, testCase.wantErr)
			}
		})
	}
}

func assertRemoteAuthorityLoaded(t *testing.T, cfg *FileSettings, authority *NauthilusAuthorityClientSection) {
	t.Helper()

	if authority.GetTimeout() != 5*time.Second {
		t.Fatalf("authority timeout = %s, want 5s default", authority.GetTimeout())
	}

	if authority.GetEdgeClusterID() != remoteAuthorityEnvClusterID {
		t.Fatalf("edge_cluster_id = %q, want env override", authority.GetEdgeClusterID())
	}

	backend, ok := cfg.GetRemoteBackend(remoteAuthorityTestBackendName)
	if !ok {
		t.Fatal("remote backend default not loaded")
	}

	if backend.GetAuthority() != remoteAuthorityTestName {
		t.Fatalf("remote authority = %q, want edge", backend.GetAuthority())
	}

	if !backend.AllowsOperation(RemoteBackendOperationAuth) || !backend.AllowsOperation(RemoteBackendOperationLookupIdentity) {
		t.Fatalf("allowed operations = %#v, want auth and lookup_identity", backend.GetAllowedOperations())
	}
}

type remoteAuthorityValidationCase struct {
	name    string
	mutate  func()
	wantErr string
}

type remoteAuthorityTLSFiles struct {
	ca   string
	cert string
	key  string
}

func remoteAuthorityValidationCases(t *testing.T) []remoteAuthorityValidationCase {
	t.Helper()

	tlsFiles := remoteAuthorityTLSFiles{
		ca:   writeRemoteAuthorityTempFile(t, "ca.pem"),
		cert: writeRemoteAuthorityTempFile(t, "client.pem"),
		key:  writeRemoteAuthorityTempFile(t, "client.key"),
	}

	cases := remoteAuthorityReferenceValidationCases()
	cases = append(cases, remoteAuthorityTLSValidationCases(tlsFiles)...)
	cases = append(cases, remoteAuthorityStaticTokenValidationCase(t))

	return cases
}

func remoteAuthorityReferenceValidationCases() []remoteAuthorityValidationCase {
	return []remoteAuthorityValidationCase{
		{
			name: "missing authority reference",
			mutate: func() {
				viper.Set("auth.backends.remote.default.authority", "missing")
			},
			wantErr: "auth.backends.remote.default.authority",
		},
		{
			name: "invalid operation",
			mutate: func() {
				viper.Set("auth.backends.remote.default.allowed_operations", []string{RemoteBackendOperationAuth, "delete_everything"})
			},
			wantErr: remoteAuthorityAllowedOperationsKey,
		},
		{
			name: "non loopback requires tls",
			mutate: func() {
				viper.Set(remoteAuthorityAddressPath, remoteAuthoritySplitAddress)
			},
			wantErr: "requires TLS",
		},
	}
}

func remoteAuthorityTLSValidationCases(tlsFiles remoteAuthorityTLSFiles) []remoteAuthorityValidationCase {
	return []remoteAuthorityValidationCase{
		{
			name: "split target requires mtls",
			mutate: func() {
				viper.Set(remoteAuthorityAddressPath, remoteAuthoritySplitAddress)
				viper.Set("runtime.clients.grpc.nauthilus_authorities.edge.tls.enabled", true)
				viper.Set("runtime.clients.grpc.nauthilus_authorities.edge.tls.ca", tlsFiles.ca)
			},
			wantErr: "requires mTLS",
		},
		{
			name: "caller auth remains mandatory with mtls",
			mutate: func() {
				viper.Set(remoteAuthorityAddressPath, remoteAuthoritySplitAddress)
				viper.Set("runtime.clients.grpc.nauthilus_authorities.edge.tls.enabled", true)
				viper.Set("runtime.clients.grpc.nauthilus_authorities.edge.tls.ca", tlsFiles.ca)
				viper.Set("runtime.clients.grpc.nauthilus_authorities.edge.tls.cert", tlsFiles.cert)
				viper.Set("runtime.clients.grpc.nauthilus_authorities.edge.tls.key", tlsFiles.key)
				viper.Set(remoteAuthorityOIDCEnabledPath, false)
			},
			wantErr: "caller auth",
		},
	}
}

func remoteAuthorityStaticTokenValidationCase(t *testing.T) remoteAuthorityValidationCase {
	t.Helper()

	return remoteAuthorityValidationCase{
		name: "static token file requires explicit development mode",
		mutate: func() {
			tokenFile := writeRemoteAuthorityTempFile(t, "token")

			viper.Set(remoteAuthorityOIDCEnabledPath, false)
			viper.Set(remoteAuthorityStaticTokenFilePath, tokenFile)
		},
		wantErr: "static_token_file",
	}
}

func setRemoteAuthorityStorage(t *testing.T) {
	t.Helper()

	viper.Set("storage.redis.primary.address", "localhost:6379")
	viper.Set("storage.redis.password_nonce", testRedisPasswordNonce)
	viper.Set("storage.redis.encryption_secret", testRedisEncryptionSecret)
}

func setRemoteAuthorityConfig(t *testing.T, address string) {
	t.Helper()

	viper.Set("runtime.clients.grpc.nauthilus_authorities.edge", map[string]any{
		remoteAuthorityAddressKey: address,
		"caller_auth": map[string]any{
			"oidc_bearer": map[string]any{
				remoteAuthorityEnabledKey:      true,
				remoteAuthorityModeKey:         AuthorityClientCredentialsMode,
				"token_endpoint":               remoteAuthorityTokenEndpoint,
				remoteAuthorityClientIDKey:     remoteAuthorityClientID,
				remoteAuthorityClientSecretKey: remoteAuthorityClientSecret,
				"token_endpoint_auth_method":   AuthorityClientSecretPostAuth,
			},
		},
	})
	viper.Set("auth.backends.order", []string{"remote"})
	viper.Set("auth.backends.remote.default", map[string]any{
		remoteAuthorityAuthorityKey:         remoteAuthorityTestName,
		remoteAuthorityModeKey:              RemoteBackendModeNauthilus,
		remoteAuthorityAllowedOperationsKey: []string{RemoteBackendOperationAuth, RemoteBackendOperationLookupIdentity, RemoteBackendOperationListAccounts},
	})
}

func writeRemoteAuthorityTempFile(t *testing.T, name string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	return path
}
