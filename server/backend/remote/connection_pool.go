// Package remote implements edge-side backends backed by a Nauthilus authority.
package remote

import (
	stderrors "errors"
	"strconv"
	"strings"
	"sync"

	"github.com/croessner/nauthilus/v3/server/config"
	authorityclient "github.com/croessner/nauthilus/v3/server/grpcclient/authority"
)

var (
	authorityClientOverrides sync.Map
	authorityConnections     sync.Map
)

type authorityConnection interface {
	Client() authorityclient.Client
	Close() error
}

func authorityClientFor(
	authorityName string,
	cfg *config.NauthilusAuthorityClientSection,
	tokenSource authorityclient.BearerTokenSource,
) (authorityclient.Client, error) {
	if client, ok := authorityClientOverrides.Load(authorityName); ok {
		return client.(authorityclient.Client), nil
	}

	key := authorityConnectionKey(authorityName, cfg)
	if existing, ok := authorityConnections.Load(key); ok {
		return existing.(authorityConnection).Client(), nil
	}

	manager, err := authorityclient.NewConnectionManager(authorityclient.ConnectionManagerOptions{
		AuthorityName: authorityName,
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

func authorityConnectionKey(authorityName string, cfg *config.NauthilusAuthorityClientSection) string {
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
		strconv.FormatBool(callerAuth.BasicAuth.IsEnabled()),
		strconv.FormatBool(oidc.IsEnabled()),
		oidc.GetMode(),
		oidc.GetTokenEndpoint(),
		oidc.GetClientID(),
		oidc.GetTokenEndpointAuthMethod(),
		oidc.GetStaticTokenFile(),
	}

	return strings.Join(parts, "\x00")
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
