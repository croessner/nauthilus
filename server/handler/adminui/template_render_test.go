package adminui

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	handlerdeps "github.com/croessner/nauthilus/server/handler/deps"
	"github.com/gin-gonic/gin"
)

func TestAdminTemplateRenderingRoutes(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.SetHTMLTemplate(buildAdminTestTemplates(t))
	New(nil, AuthModeIDPSession, false, nil, nil, nil, nil).Register(router)

	tests := []struct {
		name        string
		path        string
		wantContain string
	}{
		{name: "admin index", path: "/admin", wantContain: "layout Nauthilus Admin bruteforce clickhouse hooktester"},
		{name: "dashboard partial", path: "/admin/partial/dashboard", wantContain: "dashboard 3"},
		{name: "bruteforce partial", path: "/admin/partial/bruteforce", wantContain: "bruteforce"},
		{name: "clickhouse partial", path: "/admin/partial/clickhouse", wantContain: "clickhouse"},
		{name: "hooktester partial", path: "/admin/partial/hooktester", wantContain: "hooktester"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			router.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s status = %d, want %d", tt.path, rec.Code, http.StatusOK)
			}

			if !strings.Contains(rec.Body.String(), tt.wantContain) {
				t.Fatalf("GET %s body = %q, expected to contain %q", tt.path, rec.Body.String(), tt.wantContain)
			}
		})
	}
}

func TestAdminTemplateRendering_LocalAdminLoginPage(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.SetHTMLTemplate(buildAdminTestTemplates(t))
	New(&handlerdeps.Deps{
		Cfg: &config.FileSettings{
			Server: &config.ServerSection{
				AdminUI: config.AdminUI{
					Enabled:  true,
					AuthMode: "local_admin",
					Network: config.AdminUINetwork{
						EnforceForLocalAdmin: true,
						SourceIPAllowlist:    []string{"127.0.0.1/32"},
					},
				},
			},
		},
	}, AuthModeLocalAdmin, false, nil, nil, nil, nil).Register(router)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/login", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/login status = %d, want %d", rec.Code, http.StatusOK)
	}

	if !strings.Contains(rec.Body.String(), "admin-login Login") {
		t.Fatalf("GET /admin/login body = %q, expected login template marker", rec.Body.String())
	}
}

func buildAdminTestTemplates(t *testing.T) *template.Template {
	t.Helper()

	tmpl, err := template.New("admin_layout.html").Parse(`
{{ define "admin_layout.html" }}layout {{ .Title }} {{ range .Modules }}{{ .ID }} {{ end }}{{ end }}
{{ define "admin_login.html" }}admin-login {{ .AdminLoginTitle }}{{ end }}
{{ define "admin_dashboard.html" }}dashboard {{ len .Modules }}{{ end }}
{{ define "partials_bruteforce.html" }}bruteforce{{ end }}
{{ define "partials_clickhouse.html" }}clickhouse{{ end }}
{{ define "partials_hooktester.html" }}hooktester{{ end }}
`)
	if err != nil {
		t.Fatalf("unable to parse templates: %v", err)
	}

	return tmpl
}
