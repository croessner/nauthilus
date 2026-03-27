package frontend

import (
	"bytes"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/gin-gonic/gin"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"golang.org/x/text/language"
)

func TestGetLocalized_MessageNotFound_DoesNotLogError(t *testing.T) {
	t.Helper()

	gin.SetMode(gin.TestMode)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest("GET", "/", nil)
	ctx.Set(definitions.CtxGUIDKey, "session-guid")

	bundle := i18n.NewBundle(language.English)
	bundle.MustAddMessages(language.English, &i18n.Message{
		ID:    "Known",
		Other: "Known",
	})

	localizer := i18n.NewLocalizer(bundle, "de")
	ctx.Set(definitions.CtxLocalizedKey, localizer)

	cfg := newFrontendDebugAuthConfig(t)

	var logBuffer bytes.Buffer

	logger := slog.New(slog.NewTextHandler(&logBuffer, &slog.HandlerOptions{Level: slog.LevelDebug}))
	messageID := "ABCD-EFGH"

	localized := GetLocalized(ctx, cfg, logger, messageID)
	if localized != messageID {
		t.Fatalf("expected fallback message ID %q, got %q", messageID, localized)
	}

	logged := logBuffer.String()
	if strings.Contains(logged, "Failed to get localized message") {
		t.Fatalf("unexpected localization error log for missing message ID: %s", logged)
	}
}

func newFrontendDebugAuthConfig(t *testing.T) config.File {
	t.Helper()

	definitions.SetDbgModuleMapping(definitions.NewDbgModuleMapping())

	var verbosity config.Verbosity
	if err := verbosity.Set(definitions.LogLevelNameDebug); err != nil {
		t.Fatalf("set debug log level: %v", err)
	}

	debugModule := &config.DbgModule{}
	if err := debugModule.Set(definitions.DbgAuthName); err != nil {
		t.Fatalf("set auth debug module: %v", err)
	}

	return &config.FileSettings{
		Server: &config.ServerSection{
			Log: config.Log{
				Level:      verbosity,
				DbgModules: []*config.DbgModule{debugModule},
			},
		},
	}
}
