// Copyright (C) 2024 Christian Rößner
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

package core

import (
	"context"
	"crypto/tls"
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/pires/go-proxyproto"
)

// HTTPApplication is a high-level façade to start the HTTP stack with injected route setup callbacks.
// It encapsulates bootstrapping, engine composition, server creation and transport serving.
type HTTPApplication interface {
	Start(ctx context.Context,
		setupHealth func(*gin.Engine),
		setupMetrics func(*gin.Engine),
		setupHydra func(*gin.Engine),
		setup2FA func(*gin.Engine),
		setupWebAuthn func(*gin.Engine),
		setupNotify func(*gin.Engine),
		setupIdP func(*gin.Engine),
		setupBackchannel func(*gin.Engine),
		signals ServerSignals,
	)
}

// RouterComposer builds/configures the Gin engine and registers routes in the exact order as before.
type RouterComposer interface {
	ComposeEngine() *gin.Engine
	ApplyEarlyMiddlewares(*gin.Engine) // pprof, limit, logger
	ApplyCoreMiddlewares(*gin.Engine)  // recovery, proxies, compression, metrics
	RegisterRoutes(r *gin.Engine,
		setupHealth func(*gin.Engine),
		setupMetrics func(*gin.Engine),
		setupHydra func(*gin.Engine),
		setup2FA func(*gin.Engine),
		setupWebAuthn func(*gin.Engine),
		setupNotify func(*gin.Engine),
		setupIdP func(*gin.Engine),
		setupBackchannel func(*gin.Engine),
	)
}

// HTTPServerFactory creates a configured http.Server (incl. HTTP/2 settings).
type HTTPServerFactory interface {
	New(*gin.Engine) *http.Server
}

// ProxyListenerProvider optionally supplies an HAProxy PROXY v2 listener.
type ProxyListenerProvider interface {
	Get() *proxyproto.Listener // nil if disabled
}

// TLSConfigurator encapsulates TLS parameters (CA, suites, min version, NextProtos...).
type TLSConfigurator interface {
	Build() *tls.Config // nil if TLS disabled
}

// ServerSignals encapsulates server lifecycle signaling channels used to
// coordinate graceful shutdown. Implementations may return nil for HTTP/3 when
// HTTP/3 is disabled.
type ServerSignals interface {
	// HTTPDone returns a channel that is signaled when the HTTP/1.1+2 server
	// has terminated gracefully.
	HTTPDone() chan Done
	// HTTP3Done returns a channel that is signaled when the HTTP/3 server
	// has terminated gracefully. It may be nil if HTTP/3 is disabled.
	HTTP3Done() chan Done
}

// TransportRunner starts the network listeners for HTTP/1.1+2 and optionally
// HTTP/3, and manages graceful shutdown and error handling.
// Parameters:
//   - ctx: lifecycle context; cancellation triggers graceful shutdown
//   - srv: configured net/http server (HTTP/1.1+2)
//   - certFile, keyFile: TLS certificate and key file paths (only used if TLS enabled)
//   - proxy: optional HAProxy PROXY v2 listener (nil if disabled)
//   - signals: channels to signal server termination events
type TransportRunner interface {
	Serve(ctx context.Context, srv *http.Server, certFile, keyFile string, proxy *proxyproto.Listener, signals ServerSignals)
}

// Bootstrap initializes cross-cutting HTTP dependencies such as WebAuthn,
// the session store, and Gin logging, before the router is built.
type Bootstrap interface {
	// InitWebAuthn initializes the global WebAuthn configuration from environment/config.
	// Returns an error if the configuration is invalid.
	InitWebAuthn() error
	// InitSessionStore constructs and returns the Gin session store with secure defaults.
	InitSessionStore() sessions.Store
	// InitGinLogging wires Gin log writers and sets Gin mode based on configuration.
	InitGinLogging()
}
