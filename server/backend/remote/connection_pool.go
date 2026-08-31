// Package remote implements edge-side backends backed by a Nauthilus authority.
package remote

import (
	"encoding/hex"
	stderrors "errors"
	"strconv"
	"strings"
	"sync"

	"github.com/croessner/nauthilus/v4/server/config"
	authorityclient "github.com/croessner/nauthilus/v4/server/grpcclient/authority"
)

var (
	authorityClientOverrides sync.Map
	authorityConnections     sync.Map
)

const authorityArtifactUncaptured = "uncaptured"

type authorityConnection interface {
	Client() authorityclient.Client
	Close() error
}

func authorityClientFor(
	authorityName string,
	cfg *config.NauthilusAuthorityClientSection,
	artifacts *config.ArtifactSnapshot,
	tokenSource authorityclient.BearerTokenSource,
) (authorityclient.Client, error) {
	if client, ok := authorityClientOverrides.Load(authorityName); ok {
		return client.(authorityclient.Client), nil
	}

	key := authorityConnectionKey(authorityName, cfg, artifacts)
	if existing, ok := authorityConnections.Load(key); ok {
		return existing.(authorityConnection).Client(), nil
	}

	manager, err := authorityclient.NewConnectionManager(authorityclient.ConnectionManagerOptions{
		AuthorityName: authorityName,
		Artifacts:     artifacts,
		Config:        cfg,
		TokenSource:   tokenSource,
	})
	if err != nil {
		return nil, err
	}

	actual, loaded := authorityConnections.LoadOrStore(key, manager)
	if loaded {
		_ = manager.Close()

		return actual.(authorityConnection).Client(), nil
	}

	return manager.Client(), nil
}

// SetAuthorityClientForTest installs a static authority client for focused integration tests.
func SetAuthorityClientForTest(authorityName string, client authorityclient.Client) func() {
	authorityClientOverrides.Store(authorityName, client)

	return func() {
		authorityClientOverrides.Delete(authorityName)
	}
}

func authorityConnectionKey(
	authorityName string,
	cfg *config.NauthilusAuthorityClientSection,
	artifacts *config.ArtifactSnapshot,
) string {
	tlsConfig := cfg.GetTLS()
	callerAuth := cfg.GetCallerAuth()
	oidc := callerAuth.OIDCBearer

	parts := []string{
		authorityName,
		cfg.GetAddress(),
		cfg.GetTimeout().String(),
		strconv.FormatBool(tlsConfig.IsEnabled()),
		tlsConfig.CA,
		tlsConfig.Cert,
		tlsConfig.Key,
		tlsConfig.ServerName,
		tlsConfig.GetMinTLSVersion(),
		authorityArtifactDigest(artifacts, tlsConfig.CA),
		authorityArtifactDigest(artifacts, tlsConfig.Cert),
		authorityArtifactDigest(artifacts, tlsConfig.Key),
		strconv.FormatBool(callerAuth.BasicAuth.IsEnabled()),
		strconv.FormatBool(oidc.IsEnabled()),
		oidc.GetMode(),
		oidc.GetTokenEndpoint(),
		oidc.GetClientID(),
		oidc.GetTokenEndpointAuthMethod(),
		oidc.GetStaticTokenFile(),
		oidc.ClientPrivateKeyFile,
		authorityArtifactDigest(artifacts, oidc.GetStaticTokenFile()),
		authorityArtifactDigest(artifacts, oidc.ClientPrivateKeyFile),
	}

	return strings.Join(parts, "\x00")
}

// authorityArtifactDigest maps one sealed credential into a non-secret cache identity.
func authorityArtifactDigest(artifacts *config.ArtifactSnapshot, path string) string {
	if path == "" {
		return ""
	}

	if artifacts == nil {
		return authorityArtifactUncaptured
	}

	digest, err := artifacts.Digest(path)
	if err != nil {
		return authorityArtifactUncaptured
	}

	return hex.EncodeToString(digest[:])
}

// CloseConnectionManagers closes cached authority connections during shutdown.
func CloseConnectionManagers() error {
	var result error

	authorityConnections.Range(func(key any, value any) bool {
		if connection, ok := value.(authorityConnection); ok {
			result = stderrors.Join(result, connection.Close())
		}

		authorityConnections.Delete(key)

		return true
	})

	return result
}
