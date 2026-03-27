package idp

import (
	"net/http/httptest"
	"testing"

	coreauth "github.com/croessner/nauthilus/server/core/auth"

	"github.com/croessner/nauthilus/server/backend/accountcache"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/handler/deps"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
)

type capturePasswordVerifier struct {
	method string
}

func (v *capturePasswordVerifier) Verify(_ *gin.Context, auth *core.AuthState, _ []*core.PassDBMap) (*core.PassDBResult, error) {
	v.method = auth.Request.Method

	result := core.GetPassDBResultFromPool()
	result.Authenticated = true
	result.UserFound = false
	result.Account = "user1"
	result.AccountField = definitions.MetaUserAccount
	result.DisplayNameField = "User One"
	result.UniqueUserIDField = "uid-1"
	result.Backend = definitions.BackendLDAP

	return result, nil
}

func TestNauthilusIdPAuthenticateSetsPasswordMethodForIdPLogin(t *testing.T) {
	gin.SetMode(gin.TestMode)

	verifier := &capturePasswordVerifier{}

	core.RegisterPasswordVerifier(verifier)
	defer core.RegisterPasswordVerifier(coreauth.DefaultPasswordVerifier{})

	db, _ := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)
	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			Redis: config.Redis{
				Prefix: "test:",
			},
		},
	}

	d := &deps.Deps{
		Cfg:          cfg,
		Redis:        redisClient,
		AccountCache: accountcache.NewManager(cfg),
	}

	idp := NewNauthilusIdP(d)

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest("POST", "/login", nil)
	ctx.Request.RemoteAddr = "192.168.1.100:12345"

	setupMockContext(ctx, "test-idp-method-guid", definitions.ServIdP)

	_, _ = idp.Authenticate(ctx, "user1", "pass1", "client1", "")

	if verifier.method != "password" {
		t.Fatalf("expected method to be %q, got %q", "password", verifier.method)
	}
}
