package core

import (
	"bytes"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/secret"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestAuthState_String_HidesPassword(t *testing.T) {
	SetDefaultEnvironment(&config.EnvironmentSettings{DevMode: false})

	auth := &AuthState{
		Request: AuthRequest{
			Username: "alice",
			Password: secret.New("s3cret"),
			ClientIP: "10.0.0.1",
			Protocol: &config.Protocol{},
		},
	}

	result := auth.String()

	assert.Contains(t, result, "Username='alice'")
	assert.Contains(t, result, "ClientIP='10.0.0.1'")
	assert.Contains(t, result, "Password='<hidden>'")
	assert.NotContains(t, result, "s3cret")
	// GUID must not appear
	assert.NotContains(t, result, "GUID")
}

func TestAuthState_String_ShowsPasswordInDevMode(t *testing.T) {
	SetDefaultEnvironment(&config.EnvironmentSettings{DevMode: true})

	auth := &AuthState{
		Request: AuthRequest{
			Username: "alice",
			Password: secret.New("s3cret"),
			Protocol: &config.Protocol{},
		},
	}

	result := auth.String()

	assert.Contains(t, result, "Password='s3cret'")
}

func TestAuthState_String_ExcludesGUID(t *testing.T) {
	SetDefaultEnvironment(&config.EnvironmentSettings{DevMode: false})

	auth := &AuthState{
		Request: AuthRequest{
			Protocol: &config.Protocol{},
		},
		Runtime: AuthRuntime{
			GUID: "test-guid-123",
		},
	}

	result := auth.String()

	assert.NotContains(t, result, "GUID")
	assert.NotContains(t, result, "test-guid-123")
}

func TestAuthState_String_IncludesRuntimeAndSecurity(t *testing.T) {
	SetDefaultEnvironment(&config.EnvironmentSettings{DevMode: false})

	auth := &AuthState{
		Request: AuthRequest{
			Protocol: &config.Protocol{},
		},
		Runtime: AuthRuntime{
			AccountName: "testaccount",
			UserFound:   true,
		},
		Security: AuthSecurity{
			BruteForceName: "rule1",
			LoginAttempts:  3,
		},
	}

	result := auth.String()

	assert.Contains(t, result, "AccountName='testaccount'")
	assert.Contains(t, result, "UserFound='true'")
	assert.Contains(t, result, "BruteForceName='rule1'")
	assert.Contains(t, result, "LoginAttempts='3'")
}

func TestAuthState_String_NoLeadingSpace(t *testing.T) {
	SetDefaultEnvironment(&config.EnvironmentSettings{DevMode: false})

	auth := &AuthState{
		Request: AuthRequest{
			Protocol: &config.Protocol{},
		},
	}

	result := auth.String()

	assert.NotEmpty(t, result)
	assert.False(t, strings.HasPrefix(result, " "))
}

func TestPassDBResult_String(t *testing.T) {
	p := &PassDBResult{
		BackendName:   "ldap",
		Account:       "bob",
		Authenticated: true,
		UserFound:     true,
	}

	result := p.String()

	assert.Contains(t, result, "BackendName='ldap'")
	assert.Contains(t, result, "Account='bob'")
	assert.Contains(t, result, "Authenticated='true'")
	assert.Contains(t, result, "UserFound='true'")
	assert.False(t, strings.HasPrefix(result, " "))
}

func TestPassDBResult_String_RedactsSensitiveMFAValues(t *testing.T) {
	p := &PassDBResult{
		BackendName:       "ldap",
		TOTPSecretField:   "totp_secret",
		TOTPRecoveryField: "totp_recovery",
		Attributes: bktype.AttributeMapping{
			"totp_secret":   {"GO4YFE3A3AIG4FMPGY76M4ZKYON25DW6"},
			"totp_recovery": {"recovery-one", "recovery-two"},
			"uid":           {"alice"},
		},
	}

	result := p.String()

	assert.Contains(t, result, "uid:[alice]")
	assert.Contains(t, result, logRedactedValue)
	assert.NotContains(t, result, "GO4YFE3A3AIG4FMPGY76M4ZKYON25DW6")
	assert.NotContains(t, result, "recovery-one")
	assert.NotContains(t, result, "recovery-two")
}

func TestProcessPassDBResult_DebugLogRedactsSensitiveMFAValues(t *testing.T) {
	gin.SetMode(gin.TestMode)

	ctx, auth, logBuf := newAuthDebugLogFixture(t)

	passDBResult := &PassDBResult{
		BackendName:       "cache",
		TOTPSecretField:   "totp_secret",
		TOTPRecoveryField: "totp_recovery",
		Attributes: bktype.AttributeMapping{
			"uid":           {"alice"},
			"totp_secret":   {"GO4YFE3A3AIG4FMPGY76M4ZKYON25DW6"},
			"totp_recovery": {"recovery-one", "recovery-two"},
		},
		Backend: definitions.BackendLDAP,
	}

	err := ProcessPassDBResult(ctx, passDBResult, auth, &PassDBMap{backend: definitions.BackendCache})
	if err != nil {
		t.Fatalf("process passdb result: %v", err)
	}

	logOutput := logBuf.String()

	assert.Contains(t, logOutput, logRedactedValue)
	assert.NotContains(t, logOutput, "GO4YFE3A3AIG4FMPGY76M4ZKYON25DW6")
	assert.NotContains(t, logOutput, "recovery-one")
	assert.NotContains(t, logOutput, "recovery-two")
}

func newAuthDebugLogFixture(t *testing.T) (*gin.Context, *AuthState, *bytes.Buffer) {
	t.Helper()

	var logBuf bytes.Buffer

	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	definitions.SetDbgModuleMapping(definitions.NewDbgModuleMapping())

	verbosity := config.Verbosity{}
	if err := verbosity.Set(definitions.LogLevelNameDebug); err != nil {
		t.Fatalf("set verbosity: %v", err)
	}

	authDebugModule := &config.DbgModule{}
	if err := authDebugModule.Set(definitions.DbgAuthName); err != nil {
		t.Fatalf("set debug module: %v", err)
	}

	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Log: config.Log{
				Level:      verbosity,
				DbgModules: []*config.DbgModule{authDebugModule},
			},
		},
	}

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest("POST", "/login/totp", nil)

	auth := &AuthState{
		deps: AuthDeps{
			Cfg:    cfg,
			Logger: logger,
		},
		Request: AuthRequest{
			Username:          "alice",
			HTTPClientContext: ctx,
			HTTPClientRequest: ctx.Request,
		},
		Runtime: AuthRuntime{
			GUID: "guid-1",
		},
	}

	return ctx, auth, &logBuf
}
