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
	"context"
	"testing"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/compiler"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"

	"github.com/gin-gonic/gin"
)

const (
	requestHeaderCompanyDomainName        = "X-Company-Domain"
	requestMetadataCompanyDomainKey       = "x-company-domain"
	requestHeaderCompanyDomainAttribute   = "request.header.company_domain"
	requestMetadataCompanyDomainAttribute = "request.metadata.company_domain"
	requestAttributeI18NKey               = "auth.policy.company.account_blocked"
	requestAttributeFallback              = "Login failed because the account is locked."
	requestAttributeVisibilityPublic      = "public"
	requestAttributePrivateValue          = "secret"
	requestAttributeLDAPBackendCheck      = "ldap_backend"
)

func TestPolicyRequestHeaderAttributeDrivesResponseLanguage(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	snapshot := compileRequestAttributeSnapshotForTest(t, cfg, requestAttributePolicyConfig{
		headers: []config.PolicyRequestHeaderAttributeConfig{
			{
				Header:     requestHeaderCompanyDomainName,
				Attribute:  requestHeaderCompanyDomainAttribute,
				Visibility: requestAttributeVisibilityPublic,
				Normalize: config.PolicyRequestAttributeNormalizeConfig{
					Trim:      true,
					Case:      requestAttributeCaseLower,
					MaxLength: 64,
				},
			},
		},
		policies: []config.PolicyRuleConfig{
			requestAttributeLanguagePolicy(
				"company_header_language",
				requestHeaderCompanyDomainAttribute,
				"companyde",
				"de",
			),
		},
	})
	activatePolicySnapshotForTest(t, snapshot)

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	ctx.Request.Header.Set(requestHeaderCompanyDomainName, " CompanyDE ")
	ctx.Request.Header.Set("X-Private-Domain", requestAttributePrivateValue)
	recordFailedBackendForRequestAttributeTest(t, auth, ctx)

	if _, ok := auth.configuredPolicyAuthResult(ctx, definitions.AuthResultFail); !ok {
		t.Fatal("configured auth decision was not evaluated")
	}

	policyCtx, ok := policyDecisionContext(ctx)
	if !ok {
		t.Fatal("missing policy decision context")
	}

	assertPolicyAttributeValue(t, policyCtx.Report().Attributes[requestHeaderCompanyDomainAttribute].Value, "companyde")

	if _, exists := policyCtx.Report().Attributes["request.header.private_domain"]; exists {
		t.Fatal("non-allowlisted request header was exposed as a policy attribute")
	}

	if got := auth.Runtime.ResponseLanguage; got != "de" {
		t.Fatalf("response language = %q, want de", got)
	}
}

func TestPolicyRequestMetadataAttributeDrivesResponseLanguage(t *testing.T) {
	cfg := newCurrentBehaviorConfig(t)
	snapshot := compileRequestAttributeSnapshotForTest(t, cfg, requestAttributePolicyConfig{
		metadata: []config.PolicyRequestMetadataAttributeConfig{
			{
				Key:        requestMetadataCompanyDomainKey,
				Attribute:  requestMetadataCompanyDomainAttribute,
				Visibility: requestAttributeVisibilityPublic,
				Normalize: config.PolicyRequestAttributeNormalizeConfig{
					Trim:      true,
					Case:      requestAttributeCaseLower,
					MaxLength: 64,
				},
			},
		},
		policies: []config.PolicyRuleConfig{
			requestAttributeLanguagePolicy(
				"company_metadata_language",
				requestMetadataCompanyDomainAttribute,
				"companyfr",
				"fr",
			),
		},
	})
	activatePolicySnapshotForTest(t, snapshot)

	auth, ctx, _ := newCurrentBehaviorAuthState(t, cfg)
	auth.Request.Service = definitions.ServGRPC
	auth.Request.RequestMetadata = map[string][]string{
		requestMetadataCompanyDomainKey: {" CompanyFR "},
		"x-private-domain":              {requestAttributePrivateValue},
	}
	recordFailedBackendForRequestAttributeTest(t, auth, ctx)

	if _, ok := auth.configuredPolicyAuthResult(ctx, definitions.AuthResultFail); !ok {
		t.Fatal("configured auth decision was not evaluated")
	}

	policyCtx, ok := policyDecisionContext(ctx)
	if !ok {
		t.Fatal("missing policy decision context")
	}

	assertPolicyAttributeValue(t, policyCtx.Report().Attributes[requestMetadataCompanyDomainAttribute].Value, "companyfr")

	if _, exists := policyCtx.Report().Attributes["request.metadata.private_domain"]; exists {
		t.Fatal("non-allowlisted request metadata was exposed as a policy attribute")
	}

	if got := auth.Runtime.ResponseLanguage; got != "fr" {
		t.Fatalf("response language = %q, want fr", got)
	}
}

type requestAttributePolicyConfig struct {
	headers  []config.PolicyRequestHeaderAttributeConfig
	metadata []config.PolicyRequestMetadataAttributeConfig
	policies []config.PolicyRuleConfig
}

func compileRequestAttributeSnapshotForTest(
	t *testing.T,
	cfg *config.FileSettings,
	policyConfig requestAttributePolicyConfig,
) *policyruntime.Snapshot {
	t.Helper()

	cfg.Auth = &config.AuthSection{
		Policy: config.AuthPolicySection{
			Mode:            policyModeEnforce,
			DefaultPolicy:   policy.BuiltinDefaultSet,
			RequestHeaders:  policyConfig.headers,
			RequestMetadata: policyConfig.metadata,
			Checks: []config.PolicyCheckConfig{
				{
					Name:      requestAttributeLDAPBackendCheck,
					Type:      policy.CheckTypeLDAPBackend,
					Stage:     string(policy.StageAuthBackend),
					ConfigRef: "auth.backends.ldap",
				},
			},
			Policies: policyConfig.policies,
		},
	}

	snapshot, err := compiler.NewCompiler().Compile(context.Background(), compiler.Input{
		Config:     cfg,
		Generation: 201,
	})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	return snapshot
}

func requestAttributeLanguagePolicy(name string, attribute string, value string, language string) config.PolicyRuleConfig {
	return config.PolicyRuleConfig{
		Name:  name,
		Stage: string(policy.StageAuthDecision),
		If: config.PolicyConditionConfig{
			All: []config.PolicyConditionConfig{
				{
					Attribute: policy.AttributeAuthenticated,
					Is:        false,
				},
				{
					Attribute: attribute,
					Eq:        value,
				},
			},
		},
		Then: config.PolicyThenConfig{
			Decision:       string(policy.DecisionDeny),
			ResponseMarker: policy.ResponseMarkerFail,
			ResponseMessage: config.PolicyResponseMessageConfig{
				From:     policy.ResponseSourceI18N,
				I18NKey:  requestAttributeI18NKey,
				Fallback: requestAttributeFallback,
			},
			ResponseLanguage: config.PolicyResponseLanguageConfig{
				From:     policy.ResponseSourceLiteral,
				Language: language,
			},
		},
	}
}

func recordFailedBackendForRequestAttributeTest(t *testing.T, auth *AuthState, ctx *gin.Context) {
	t.Helper()

	passDBResult := GetPassDBResultFromPool()
	passDBResult.Authenticated = false
	passDBResult.UserFound = true
	passDBResult.Backend = definitions.BackendTest

	t.Cleanup(func() {
		PutPassDBResultToPool(passDBResult)
	})

	auth.recordPolicyBackendResult(ctx, definitions.AuthResultFail, passDBResult, nil)
}

func assertPolicyAttributeValue(t *testing.T, got any, want string) {
	t.Helper()

	if got != want {
		t.Fatalf("policy attribute value = %#v, want %q", got, want)
	}
}
