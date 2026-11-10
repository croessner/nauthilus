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

package core

import (
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/conncause"

	"github.com/gin-gonic/gin"
	"github.com/pires/go-proxyproto"
	"github.com/stretchr/testify/assert"
)

// TestHTTPBaseListenerPrefersProxyListener pins that a configured PROXY protocol listener is used
// as the base below the cause listener, and that a TCP listener is opened otherwise.
func TestHTTPBaseListenerPrefersProxyListener(t *testing.T) {
	proxy := &proxyproto.Listener{}

	listener, err := httpBaseListener("127.0.0.1:0", proxy, false)
	assert.NoError(t, err)
	assert.Same(t, proxy, listener)

	listener, err = httpBaseListener("127.0.0.1:0", nil, true)
	if !assert.NoError(t, err) {
		return
	}

	t.Cleanup(func() { _ = listener.Close() })

	_, isTCP := listener.(*net.TCPListener)
	assert.True(t, isTCP)
}

// TestHTTPServerAnchorsRequestContext pins that the HTTP server anchors each request context, so failure logs below
// the transport can classify a cancellation against the own request.
func TestHTTPServerAnchorsRequestContext(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var anchored bool

	router := gin.New()
	router.GET("/anchor", func(ctx *gin.Context) {
		_, anchored = conncause.RequestContext(ctx.Request.Context())
	})

	factory := NewDefaultHTTPServerFactory(HTTPDeps{
		Cfg:    &config.FileSettings{Server: &config.ServerSection{}},
		Logger: slog.New(slog.DiscardHandler),
	})
	server := factory.New(router)

	server.Handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/anchor", nil))

	assert.True(t, anchored)
}
