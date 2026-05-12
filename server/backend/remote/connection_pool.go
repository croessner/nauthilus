// Package remote implements edge-side backends backed by a Nauthilus authority.
package remote

import (
	stderrors "errors"
	"strconv"
	"strings"
	"sync"

	"github.com/croessner/nauthilus/server/config"
	authorityclient "github.com/croessner/nauthilus/server/grpcclient/authority"
)

var authorityConnections sync.Map

func authorityClientFor(
	authorityName string,
	cfg *config.NauthilusAuthorityClientSection,
	tokenSource authorityclient.BearerTokenSource,
) (authorityclient.Client, error) {
	key := authorityConnectionKey(authorityName, cfg)
	if existing, ok := authorityConnections.Load(key); ok {
		return existing.(*authorityclient.ConnectionManager).Client(), nil
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

		return actual.(*authorityclient.ConnectionManager).Client(), nil
	}

	return manager.Client(), nil
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
		if manager, ok := value.(*authorityclient.ConnectionManager); ok {
			result = stderrors.Join(result, manager.Close())
		}

		authorityConnections.Delete(key)

		return true
	})

	return result
}
