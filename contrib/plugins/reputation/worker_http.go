//go:build reputation_worker

package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	serverconfig "github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/middleware/auth"
)

// newWorkerHTTPServer requires sealed TLS credentials and explicit metrics authentication before binding a listener.
func newWorkerHTTPServer(file serverconfig.File, state *stateOwner, registry *prometheus.Registry) (*http.Server, net.Listener, error) {
	basic := file.GetServer().GetMetricsEndpointAuth().GetBasicAuth()

	configuredTLS := file.GetServer().GetTLS()
	if !basic.IsEnabled() || basic.GetUsername() == "" || basic.GetPassword().IsZero() || !configuredTLS.IsEnabled() {
		return nil, nil, errConfiguration
	}

	parsedTLS, err := serverconfig.BuildClientTLSConfig(file, configuredTLS)
	if err != nil || parsedTLS == nil || len(parsedTLS.Certificates) != 1 {
		return nil, nil, errConfiguration
	}

	listener, err := net.Listen("tcp", file.GetServer().GetListenAddress())
	if err != nil {
		return nil, nil, errStateUnavailable
	}

	server := &http.Server{Handler: workerHandler(state, promhttp.HandlerFor(registry, promhttp.HandlerOpts{}), basic),
		TLSConfig:         &tls.Config{MinVersion: parsedTLS.MinVersion, CipherSuites: parsedTLS.CipherSuites, Certificates: parsedTLS.Certificates},
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}

	return server, listener, nil
}

// workerHandler registers only health and authenticated metrics; no identity or authentication routes exist.
func workerHandler(state *stateOwner, metrics http.Handler, basic *serverconfig.BasicAuth) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if !state.ready.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"down"}`))

			return
		}

		_, _ = w.Write([]byte(`{"status":"up"}`))
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, request *http.Request) {
		if !workerMetricsAuthorized(request, basic) {
			w.Header().Set("WWW-Authenticate", `Basic realm="reputation-metrics"`)
			w.WriteHeader(http.StatusUnauthorized)

			return
		}

		metrics.ServeHTTP(w, request)
	})

	return mux
}

// workerMetricsAuthorized compares deployment-owned Basic credentials without retaining or logging them.
func workerMetricsAuthorized(request *http.Request, basic *serverconfig.BasicAuth) bool {
	username, password, present := request.BasicAuth()
	return present && auth.ValidateBasicAuthCredentials(basic, username, password)
}
