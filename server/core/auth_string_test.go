package core

import (
	"strings"
	"testing"

	"github.com/croessner/nauthilus/server/config"
	"github.com/stretchr/testify/assert"
)

func TestAuthState_String_HidesPassword(t *testing.T) {
	SetDefaultEnvironment(&config.EnvironmentSettings{DevMode: false})

	auth := &AuthState{
		Request: AuthRequest{
			Username: "alice",
			Password: "s3cret",
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
			Password: "s3cret",
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
