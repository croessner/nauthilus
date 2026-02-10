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

package health

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/model/mfa"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/gin-gonic/gin"
	"github.com/go-ldap/ldap/v3"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/redis/go-redis/v9"
)

const (
	healthzStatusUp       = "up"
	healthzStatusDown     = "down"
	healthzStatusDegraded = "degraded"
	healthzStatusSkipped  = "skipped"
)

type HealthzDeps struct {
	Cfg         config.File
	Logger      *slog.Logger
	BackendName string
	Redis       rediscli.Client
}

type HealthzCheck struct {
	Status string         `json:"status"`
	Error  string         `json:"error,omitempty"`
	Meta   map[string]any `json:"meta,omitzero"`
}

type HealthzResult struct {
	Status string                   `json:"status"`
	Checks map[string]*HealthzCheck `json:"checks"`
}

func ReadinessCheck(ctx *gin.Context) {
	ReadinessCheckWithDeps(ctx, HealthzDeps{})
}

func ReadinessCheckWithDeps(ctx *gin.Context, deps HealthzDeps) {
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}

	if deps.Cfg == nil {
		if config.IsFileLoaded() {
			deps.Cfg = config.GetFile()
		} else {
			deps.Cfg = &config.FileSettings{Server: &config.ServerSection{}}
		}
	}

	if deps.BackendName == "" {
		deps.BackendName = definitions.DefaultBackendName
	}

	result := &HealthzResult{
		Status: healthzStatusUp,
		Checks: map[string]*HealthzCheck{},
	}

	checkTestBackend(deps, result)
	checkRedis(deps, result)
	checkLDAP(deps, result)

	statusCode := http.StatusOK
	if result.Status == healthzStatusDown {
		statusCode = http.StatusServiceUnavailable
	}

	ctx.JSON(statusCode, result)
}

func checkTestBackend(deps HealthzDeps, result *HealthzResult) {
	start := time.Now()

	auth := core.NewAuthStateFromContextWithDeps(nil, core.AuthDeps{
		Cfg:    deps.Cfg,
		Logger: deps.Logger,
	})
	authState, ok := auth.(*core.AuthState)

	if !ok || authState == nil {
		result.Checks["test_backend"] = &HealthzCheck{
			Status: healthzStatusDown,
			Error:  "auth state not initialized",
		}
		result.Status = healthzStatusDown

		return
	}

	authState.SetUsername("healthz-test")
	authState.SetPassword("healthz-secret")
	authState.Request.NoAuth = false
	backend := core.NewTestBackendManager(deps.BackendName, core.AuthDeps{
		Cfg:    deps.Cfg,
		Logger: deps.Logger,
	})
	passResult, err := backend.PassDB(authState)
	if err != nil {
		result.Checks["test_backend"] = &HealthzCheck{
			Status: healthzStatusDown,
			Error:  fmt.Sprintf("passdb failed: %v", err),
		}
		result.Status = healthzStatusDown

		return
	}

	if passResult == nil || !passResult.Authenticated {
		result.Checks["test_backend"] = &HealthzCheck{
			Status: healthzStatusDown,
			Error:  "passdb authentication failed",
		}
		result.Status = healthzStatusDown

		return
	}

	if accounts, err := backend.AccountDB(authState); err != nil {
		result.Checks["test_backend"] = &HealthzCheck{
			Status: healthzStatusDown,
			Error:  fmt.Sprintf("accountdb failed: %v", err),
		}
		result.Status = healthzStatusDown

		return
	} else if !containsAccount(accounts, authState.Request.Username) {
		result.Checks["test_backend"] = &HealthzCheck{
			Status: healthzStatusDown,
			Error:  "account missing after passdb",
		}
		result.Status = healthzStatusDown

		return
	}

	if err := backend.AddTOTPSecret(authState, mfa.NewTOTPSecret("healthz-secret")); err != nil {
		result.Checks["test_backend"] = &HealthzCheck{
			Status: healthzStatusDegraded,
			Error:  fmt.Sprintf("totp secret failed: %v", err),
		}
		result.Status = healthzStatusDegraded

		return
	}

	if err := backend.AddTOTPRecoveryCodes(authState, mfa.NewTOTPRecovery([]string{"healthz-recovery"})); err != nil {
		result.Checks["test_backend"] = &HealthzCheck{
			Status: healthzStatusDegraded,
			Error:  fmt.Sprintf("totp recovery failed: %v", err),
		}
		result.Status = healthzStatusDegraded

		return
	}

	credential := &mfa.PersistentCredential{
		Credential: webauthn.Credential{
			ID: []byte("healthz-credential"),
		},
		Name:     "healthz",
		LastUsed: time.Now().UTC(),
	}

	if err := backend.SaveWebAuthnCredential(authState, credential); err != nil {
		result.Checks["test_backend"] = &HealthzCheck{
			Status: healthzStatusDegraded,
			Error:  fmt.Sprintf("webauthn save failed: %v", err),
		}
		result.Status = healthzStatusDegraded

		return
	}

	if creds, err := backend.GetWebAuthnCredentials(authState); err != nil {
		result.Checks["test_backend"] = &HealthzCheck{
			Status: healthzStatusDegraded,
			Error:  fmt.Sprintf("webauthn read failed: %v", err),
		}
		result.Status = healthzStatusDegraded

		return
	} else if len(creds) == 0 {
		result.Checks["test_backend"] = &HealthzCheck{
			Status: healthzStatusDegraded,
			Error:  "webauthn credential not persisted",
		}
		result.Status = healthzStatusDegraded

		return
	}

	result.Checks["test_backend"] = &HealthzCheck{
		Status: healthzStatusUp,
		Meta: map[string]any{
			"latency_ms": time.Since(start).Milliseconds(),
		},
	}
}

func checkRedis(deps HealthzDeps, result *HealthzResult) {
	if deps.Redis == nil {
		result.Checks["redis_write"] = &HealthzCheck{
			Status: healthzStatusSkipped,
			Error:  "redis client not configured",
		}
		result.Checks["redis_read"] = &HealthzCheck{
			Status: healthzStatusSkipped,
			Error:  "redis client not configured",
		}

		return
	}

	writeTimeout := deps.Cfg.GetServer().GetTimeouts().GetRedisWrite()
	readTimeout := deps.Cfg.GetServer().GetTimeouts().GetRedisRead()

	checkRedisHandle("redis_write", deps.Redis.GetWriteHandle(), writeTimeout, result)
	checkRedisHandle("redis_read", deps.Redis.GetReadHandle(), readTimeout, result)
}

func checkRedisHandle(name string, handle redis.UniversalClient, timeout time.Duration, result *HealthzResult) {
	if handle == nil {
		result.Checks[name] = &HealthzCheck{
			Status: healthzStatusDown,
			Error:  "redis handle not available",
		}

		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	start := time.Now()
	err := handle.Ping(ctx).Err()
	latency := time.Since(start).Milliseconds()

	if err != nil {
		result.Checks[name] = &HealthzCheck{
			Status: healthzStatusDown,
			Error:  err.Error(),
			Meta: map[string]any{
				"latency_ms": latency,
			},
		}

		return
	}

	result.Checks[name] = &HealthzCheck{
		Status: healthzStatusUp,
		Meta: map[string]any{
			"latency_ms": latency,
		},
	}
}

func checkLDAP(deps HealthzDeps, result *HealthzResult) {
	if deps.Cfg == nil || !deps.Cfg.HaveLDAPBackend() {
		return
	}

	ldapSection := deps.Cfg.GetLDAP()

	if ldapSection == nil {
		result.Checks["ldap"] = &HealthzCheck{
			Status: healthzStatusDown,
			Error:  "ldap config not available",
		}

		return
	}

	ldapCfgAny := ldapSection.GetConfig()
	ldapConf, ok := ldapCfgAny.(*config.LDAPConf)

	if !ok || ldapConf == nil {
		result.Checks["ldap"] = &HealthzCheck{
			Status: healthzStatusDown,
			Error:  "ldap config not available",
		}

		return
	}

	targets := ldapConf.GetServerURIs()

	if len(targets) == 0 {
		result.Checks["ldap"] = &HealthzCheck{
			Status: healthzStatusDown,
			Error:  "ldap server uris not configured",
		}

		return
	}

	target := targets[0]
	timeout := ldapConf.GetHealthCheckTimeout()
	start := time.Now()

	options := []ldap.DialOpt{
		ldap.DialWithDialer(&net.Dialer{Timeout: timeout}),
	}

	if strings.HasPrefix(strings.ToLower(target), "ldaps://") || ldapConf.IsStartTLS() {
		options = append(options, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: ldapConf.IsTLSSkipVerify()}))
	}

	conn, err := ldap.DialURL(target, options...)
	if err != nil {
		result.Checks["ldap"] = &HealthzCheck{
			Status: healthzStatusDown,
			Error:  err.Error(),
			Meta: map[string]any{
				"target": target,
			},
		}

		return
	}

	if conn != nil {
		_ = conn.Close()
	}

	result.Checks["ldap"] = &HealthzCheck{
		Status: healthzStatusUp,
		Meta: map[string]any{
			"latency_ms": time.Since(start).Milliseconds(),
			"target":     target,
		},
	}
}

func containsAccount(accounts core.AccountList, username string) bool {
	for _, account := range accounts {
		if account == username {
			return true
		}
	}

	return false
}
