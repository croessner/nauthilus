package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/secret"
	"github.com/gin-gonic/gin"
)

const (
	testMetricsUsername     = "prometheus"
	testMetricsPassword     = "metrics-password"
	testBackchannelUsername = "api-client"
	testBackchannelPassword = "backchannel-password"
)

type metricsRequestCase struct {
	name                  string
	cfg                   config.File
	prepare               func(*http.Request)
	wantStatus            int
	wantAuthenticateBasic bool
}

func TestMetricsEndpointAllowsOpenAccessWhenBasicAuthIsDisabled(t *testing.T) {
	gin.SetMode(gin.TestMode)

	recorder := serveMetricsRequest(t, newMetricsHandlerConfig(config.BasicAuth{}, config.BasicAuth{}), nil)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
}

func TestMetricsEndpointRequiresDedicatedBasicAuthOnly(t *testing.T) {
	gin.SetMode(gin.TestMode)

	metricsBasic := metricsBasicAuth()
	tests := []metricsRequestCase{
		{
			name:       "open when metrics basic auth is disabled",
			cfg:        newMetricsHandlerConfig(config.BasicAuth{}, config.BasicAuth{}),
			wantStatus: http.StatusOK,
		},
		{
			name:                  "rejects missing basic auth when metrics auth is enabled",
			cfg:                   newMetricsHandlerConfig(metricsBasic, config.BasicAuth{}),
			wantStatus:            http.StatusUnauthorized,
			wantAuthenticateBasic: true,
		},
		{
			name: "accepts dedicated metrics basic auth",
			cfg:  newMetricsHandlerConfig(metricsBasic, config.BasicAuth{}),
			prepare: func(req *http.Request) {
				req.SetBasicAuth(testMetricsUsername, testMetricsPassword)
			},
			wantStatus: http.StatusOK,
		},
		{
			name: "rejects backchannel basic auth credentials",
			cfg:  newMetricsHandlerConfig(metricsBasic, backchannelBasicAuth()),
			prepare: func(req *http.Request) {
				req.SetBasicAuth(testBackchannelUsername, testBackchannelPassword)
			},
			wantStatus:            http.StatusUnauthorized,
			wantAuthenticateBasic: true,
		},
		{
			name: "rejects bearer auth even when metrics basic auth is enabled",
			cfg:  newMetricsHandlerConfig(metricsBasic, config.BasicAuth{}),
			prepare: func(req *http.Request) {
				req.Header.Set("Authorization", "Bearer token")
			},
			wantStatus:            http.StatusUnauthorized,
			wantAuthenticateBasic: true,
		},
	}

	runMetricsRequestCases(t, tests)
}

func runMetricsRequestCases(t *testing.T, tests []metricsRequestCase) {
	t.Helper()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := serveMetricsRequest(t, tt.cfg, tt.prepare)
			if recorder.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", recorder.Code, tt.wantStatus)
			}

			if tt.wantAuthenticateBasic {
				header := recorder.Header().Get("WWW-Authenticate")
				if !strings.HasPrefix(header, "Basic ") {
					t.Fatalf("WWW-Authenticate = %q, want Basic challenge", header)
				}
			}
		})
	}
}

func serveMetricsRequest(t *testing.T, cfg config.File, prepare func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()

	recorder := httptest.NewRecorder()
	router := gin.New()
	New(cfg, nil, nil).Register(router)

	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	if prepare != nil {
		prepare(request)
	}

	router.ServeHTTP(recorder, request)

	return recorder
}

func metricsBasicAuth() config.BasicAuth {
	return config.BasicAuth{
		Enabled:  true,
		Username: testMetricsUsername,
		Password: secret.New(testMetricsPassword),
	}
}

func backchannelBasicAuth() config.BasicAuth {
	return config.BasicAuth{
		Enabled:  true,
		Username: testBackchannelUsername,
		Password: secret.New(testBackchannelPassword),
	}
}

func newMetricsHandlerConfig(metricsBasic config.BasicAuth, backchannelBasic config.BasicAuth) *config.FileSettings {
	return &config.FileSettings{
		Server: &config.ServerSection{
			MetricsEndpointAuth: config.MetricsEndpointAuth{
				Basic: metricsBasic,
			},
			BasicAuth: backchannelBasic,
		},
	}
}
