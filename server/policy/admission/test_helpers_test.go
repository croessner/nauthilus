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

package admission

import (
	"context"
	"net/netip"
	"testing"

	"github.com/croessner/nauthilus/v3/server/definitions"
	policy "github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/compiler"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

const (
	admissionTestPrincipal = "Policy.Client-Case"
	admissionTestNamespace = "mail"
	admissionTestAction    = "submit"
	admissionTestSchema    = "mail/submit/v1"
)

type admissionTestContributor struct {
	contribution registry.DefinitionContribution
}

// Contribute returns the test-owned immutable catalog definitions.
func (c admissionTestContributor) Contribute(context.Context) (registry.DefinitionContribution, error) {
	return c.contribution, nil
}

type admissionTestRequestInput struct {
	subject            map[string]decision.Value
	resource           map[string]decision.Value
	environment        map[string]decision.Value
	input              map[string]decision.Value
	target             decision.Target
	includeDiagnostics bool
}

type admissionTestCallerInput struct {
	principal          string
	authenticationKind string
	scopes             []string
	internal           bool
}

// admissionTestConfiguration constructs one permissive profile with explicit limits.
func admissionTestConfiguration(t *testing.T, reference registry.ClientAdmissionReference) Configuration {
	t.Helper()

	return Configuration{
		GlobalLimits: Limits{
			MaxRequestBytes:   4096,
			MaxFacts:          16,
			MaxConcurrency:    8,
			RequestsPerSecond: 1000,
		},
		Profiles: []Profile{{
			Principal:                    admissionTestPrincipal,
			AuthenticationKinds:          []string{policy.CallerAuthenticationKindBearer, policy.CallerAuthenticationKindBasic},
			References:                   []registry.ClientAdmissionReference{reference},
			AllowedSubjectAttributes:     []string{"account"},
			AllowedResourceAttributes:    []string{"mail_from"},
			AllowedEnvironmentAttributes: []string{"network.risk"},
			AllowedInputAttributes:       []string{"request_id"},
			Diagnostics:                  true,
		}},
	}
}

// admissionTestPreparation constructs the default authority and exact profile metadata.
func admissionTestPreparation(t *testing.T, configuration Configuration) policyruntime.AdmissionPreparation {
	t.Helper()

	catalog, _, _ := admissionTestCatalog(t, admissionTestSchemaFacts(t))
	credentials := admissionTestCredentials(t, configurationProfileIDs(configuration))

	prepared, err := Prepare(configuration, catalog, credentials)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}

	return prepared
}

// admissionTestCredentials constructs immutable credential metadata for the supplied principals.
func admissionTestCredentials(t *testing.T, principals []string) policyruntime.CredentialProfiles {
	t.Helper()

	credentials, err := policyruntime.NewCredentialProfiles(principals)
	if err != nil {
		t.Fatalf("NewCredentialProfiles() error = %v", err)
	}

	return credentials
}

// configurationProfileIDs returns the exact profile principals in configuration order.
func configurationProfileIDs(configuration Configuration) []string {
	result := make([]string, 0, len(configuration.Profiles))
	for _, profile := range configuration.Profiles {
		result = append(result, profile.Principal)
	}

	return result
}

// admissionTestCatalog compiles one exact activated target around the supplied schema facts.
func admissionTestCatalog(
	t *testing.T,
	facts []registry.FactSchema,
) (*policyruntime.TargetCatalog, decision.Target, registry.ClientAdmissionReference) {
	t.Helper()

	target := admissionTestTarget(t, admissionTestNamespace, admissionTestAction)
	identity := admissionTestSchemaIdentity(t, admissionTestNamespace, admissionTestAction, "v1")
	schema := admissionTestSchemaDefinition(t, identity, facts)
	targetDefinition := admissionTestTargetDefinition(t, target, identity)
	contribution := admissionTestContribution(t, targetDefinition, schema)
	activation := admissionTestActivation(t, target, identity)

	catalog, err := compiler.NewTargetCatalogCompiler(
		admissionTestContributor{contribution: contribution},
	).Compile(context.Background(), []registry.TargetActivation{activation})
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	reference, err := registry.NewClientAdmissionReference(
		"policy.api.clients[0].targets[0]",
		target.Namespace(),
		target.Action(),
		identity.String(),
	)
	if err != nil {
		t.Fatalf("NewClientAdmissionReference() error = %v", err)
	}

	return catalog, target, reference
}

// admissionTestContribution constructs the minimum complete generic policy domain.
func admissionTestContribution(
	t *testing.T,
	target registry.TargetDefinition,
	schema registry.SchemaDefinition,
) registry.DefinitionContribution {
	t.Helper()

	setID, err := registry.NewPolicySetID(admissionTestNamespace, "root")
	if err != nil {
		t.Fatalf("NewPolicySetID() error = %v", err)
	}

	set, err := registry.NewPolicySetDefinition(registry.PolicySetDefinitionInput{ID: setID})
	if err != nil {
		t.Fatalf("NewPolicySetDefinition() error = %v", err)
	}

	binding, err := registry.NewPolicySetImport(
		"test.plan",
		setID.String(),
		target.Target(),
		"final_decision",
		registry.ExportContract{},
	)
	if err != nil {
		t.Fatalf("NewPolicySetImport() error = %v", err)
	}

	checkpoint, err := registry.NewCheckpointDefinition(
		"final_decision",
		[]registry.PolicySetImport{binding},
		nil,
	)
	if err != nil {
		t.Fatalf("NewCheckpointDefinition() error = %v", err)
	}

	plan, err := registry.NewDomainPlanDefinition(target.Target(), []registry.CheckpointDefinition{checkpoint})
	if err != nil {
		t.Fatalf("NewDomainPlanDefinition() error = %v", err)
	}

	ownership, err := registry.NewNamespaceOwnership("test.admission", []string{admissionTestNamespace})
	if err != nil {
		t.Fatalf("NewNamespaceOwnership() error = %v", err)
	}

	contribution, err := registry.NewCompleteDefinitionContribution(registry.DefinitionContributionInput{
		Ownership:  ownership,
		Targets:    []registry.TargetDefinition{target},
		Schemas:    []registry.SchemaDefinition{schema},
		PolicySets: []registry.PolicySetDefinition{set},
		Plans:      []registry.DomainPlanDefinition{plan},
	})
	if err != nil {
		t.Fatalf("NewCompleteDefinitionContribution() error = %v", err)
	}

	return contribution
}

// admissionTestActivation constructs the exact operator-owned schema selection.
func admissionTestActivation(
	t *testing.T,
	target decision.Target,
	identity registry.SchemaIdentity,
) registry.TargetActivation {
	t.Helper()

	activation, err := registry.NewTargetActivation(
		"policy.targets[0]",
		target.Namespace(),
		target.Action(),
		identity.String(),
	)
	if err != nil {
		t.Fatalf("NewTargetActivation() error = %v", err)
	}

	activation, err = activation.WithPolicy(admissionTestNamespace+"/root", "deny")
	if err != nil {
		t.Fatalf("TargetActivation.WithPolicy() error = %v", err)
	}

	activation, err = activation.WithAuthorityMode(registry.AuthorityModeEnforce)
	if err != nil {
		t.Fatalf("TargetActivation.WithAuthorityMode() error = %v", err)
	}

	return activation
}

// admissionTestTarget constructs one exact policy target.
func admissionTestTarget(t *testing.T, namespace string, action string) decision.Target {
	t.Helper()

	target, err := decision.NewTarget(namespace, action)
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	return target
}

// admissionTestSchemaIdentity constructs one exact schema identity.
func admissionTestSchemaIdentity(
	t *testing.T,
	namespace string,
	action string,
	version string,
) registry.SchemaIdentity {
	t.Helper()

	identity, err := registry.NewSchemaIdentity(namespace, action, version)
	if err != nil {
		t.Fatalf("NewSchemaIdentity() error = %v", err)
	}

	return identity
}

// admissionTestTargetDefinition binds one target to its supported exact schema.
func admissionTestTargetDefinition(
	t *testing.T,
	target decision.Target,
	identity registry.SchemaIdentity,
) registry.TargetDefinition {
	t.Helper()

	definition, err := registry.NewTargetDefinition(target, []registry.SchemaIdentity{identity})
	if err != nil {
		t.Fatalf("NewTargetDefinition() error = %v", err)
	}

	return definition
}

// admissionTestSchemaDefinition owns one deterministic fact declaration list.
func admissionTestSchemaDefinition(
	t *testing.T,
	identity registry.SchemaIdentity,
	facts []registry.FactSchema,
) registry.SchemaDefinition {
	t.Helper()

	schema, err := registry.NewSchemaDefinition(identity, facts)
	if err != nil {
		t.Fatalf("NewSchemaDefinition() error = %v", err)
	}

	return schema
}

// admissionTestSchemaFacts declares caller assertions and every trusted caller evidence family.
func admissionTestSchemaFacts(t *testing.T) []registry.FactSchema {
	t.Helper()

	return []registry.FactSchema{
		admissionTestFactSchema(t, "subject.account", decision.FactCategorySubject, decision.ValueKindString, decision.FactSourceCaller, 64, 0, 0),
		admissionTestFactSchema(t, "resource.mail_from", decision.FactCategoryResource, decision.ValueKindString, decision.FactSourceCaller, 64, 0, 0),
		admissionTestFactSchema(t, "environment.network.risk", decision.FactCategoryEnvironment, decision.ValueKindInteger, decision.FactSourceCaller, 0, 0, 0),
		admissionTestFactSchema(t, "input.request_id", decision.FactCategoryEnvironment, decision.ValueKindString, decision.FactSourceCaller, 64, 0, 0),
		admissionTestFactSchema(t, decision.FactCallerPrincipal, decision.FactCategoryEnvironment, decision.ValueKindString, decision.FactSourceNauthilus, 512, 0, 0),
		admissionTestFactSchema(t, decision.FactCallerClientID, decision.FactCategoryEnvironment, decision.ValueKindString, decision.FactSourceNauthilus, 512, 0, 0),
		admissionTestFactSchema(t, decision.FactCallerAuthenticationKind, decision.FactCategoryEnvironment, decision.ValueKindString, decision.FactSourceNauthilus, 64, 0, 0),
		admissionTestFactSchema(t, decision.FactCallerScopes, decision.FactCategoryEnvironment, decision.ValueKindStrings, decision.FactSourceNauthilus, 512, 16, 0),
		admissionTestFactSchema(t, decision.FactTokenSubject, decision.FactCategorySubject, decision.ValueKindString, decision.FactSourceToken, 512, 0, 0),
		admissionTestFactSchema(t, decision.FactTokenIssuer, decision.FactCategoryEnvironment, decision.ValueKindString, decision.FactSourceToken, 512, 0, 0),
		admissionTestFactSchema(t, decision.FactTransportKind, decision.FactCategoryEnvironment, decision.ValueKindString, decision.FactSourceTransport, 64, 0, 0),
		admissionTestFactSchema(t, decision.FactTransportListener, decision.FactCategoryEnvironment, decision.ValueKindString, decision.FactSourceTransport, 512, 0, 0),
		admissionTestFactSchema(t, decision.FactTransportHTTPRoute, decision.FactCategoryEnvironment, decision.ValueKindString, decision.FactSourceTransport, 512, 0, 0),
		admissionTestFactSchema(t, decision.FactTransportGRPCMethod, decision.FactCategoryEnvironment, decision.ValueKindString, decision.FactSourceTransport, 512, 0, 0),
		admissionTestFactSchema(t, decision.FactTransportMTLSIdentity, decision.FactCategoryEnvironment, decision.ValueKindString, decision.FactSourceTransport, 512, 0, 0),
		admissionTestFactSchema(t, decision.FactTransportSourceIP, decision.FactCategoryEnvironment, decision.ValueKindString, decision.FactSourceTransport, 64, 0, 0),
	}
}

// admissionTestFactSchema constructs one strict schema fact.
func admissionTestFactSchema(
	t *testing.T,
	id string,
	category decision.FactCategory,
	kind decision.ValueKind,
	source decision.FactSource,
	maxLength int,
	maxItems int,
	maxBytes int,
) registry.FactSchema {
	t.Helper()

	fact, err := registry.NewFactSchema(registry.FactSchemaInput{
		ID:             id,
		AllowedSources: []decision.FactSource{source},
		Category:       category,
		Kind:           kind,
		MaxLength:      maxLength,
		MaxItems:       maxItems,
		MaxBytes:       maxBytes,
	})
	if err != nil {
		t.Fatalf("NewFactSchema(%q) error = %v", id, err)
	}

	return fact
}

// admissionTestCaller constructs trusted caller evidence with deterministic optional fields.
func admissionTestCaller(t *testing.T, input admissionTestCallerInput) decision.CallerContext {
	t.Helper()

	principal := input.principal
	if principal == "" {
		principal = admissionTestPrincipal
	}

	authenticationKind := input.authenticationKind
	if authenticationKind == "" {
		authenticationKind = policy.CallerAuthenticationKindBearer
	}

	caller, err := decision.NewCallerContext(decision.TrustedCallerInput{
		Principal:          principal,
		ClientID:           principal,
		Subject:            "token-subject",
		Issuer:             "https://issuer.policy.test",
		Scopes:             append([]string(nil), input.scopes...),
		AuthenticationKind: authenticationKind,
		SourceIP:           netip.MustParseAddr("192.0.2.44"),
		MTLSIdentity:       "spiffe://policy.test/client",
		TransportKind:      "http",
		Listener:           "policy-http",
		HTTPRoute:          "/api/v1/policy/evaluate",
		Internal:           input.internal,
	})
	if err != nil {
		t.Fatalf("NewCallerContext() error = %v", err)
	}

	return caller
}

// admissionTestBearerCaller constructs a Bearer caller with both Policy scopes.
func admissionTestBearerCaller(t *testing.T) decision.CallerContext {
	t.Helper()

	return admissionTestCaller(t, admissionTestCallerInput{
		scopes: []string{definitions.ScopePolicyEvaluate, definitions.ScopePolicyDiagnostics},
	})
}

// admissionTestRequest constructs one deeply owned unary decision request.
func admissionTestRequest(
	t *testing.T,
	caller decision.CallerContext,
	input admissionTestRequestInput,
) decision.DecisionRequest {
	t.Helper()

	target := input.target
	if target.String() == "/" {
		target = admissionTestTarget(t, admissionTestNamespace, admissionTestAction)
	}

	subject := admissionTestEntity(t, "account", "subject-1", input.subject)
	resource := admissionTestEntity(t, "message", "resource-1", input.resource)
	environment := admissionTestEnvironment(t, input.environment)

	request, err := decision.NewDecisionRequest(decision.DecisionRequestInput{
		Version:     decision.ContractVersion,
		RequestID:   "admission-request",
		Target:      target,
		Subject:     subject,
		Resource:    resource,
		Environment: environment,
		Attributes:  input.input,
		Options: decision.EvaluationOptions{
			IncludeDiagnostics: input.includeDiagnostics,
		},
	}, caller)
	if err != nil {
		t.Fatalf("NewDecisionRequest() error = %v", err)
	}

	return request
}

// admissionTestEntity constructs one caller-asserted entity.
func admissionTestEntity(
	t *testing.T,
	typeName string,
	id string,
	attributes map[string]decision.Value,
) decision.Entity {
	t.Helper()

	entity, err := decision.NewEntity(decision.EntityInput{Type: typeName, ID: id, Attributes: attributes})
	if err != nil {
		t.Fatalf("NewEntity() error = %v", err)
	}

	return entity
}

// admissionTestEnvironment constructs one caller-asserted environment.
func admissionTestEnvironment(t *testing.T, attributes map[string]decision.Value) decision.Environment {
	t.Helper()

	environment, err := decision.NewEnvironment(decision.EnvironmentInput{
		Service:    "smtp",
		Instance:   "mx1",
		Protocol:   "smtp",
		Attributes: attributes,
	})
	if err != nil {
		t.Fatalf("NewEnvironment() error = %v", err)
	}

	return environment
}

// admissionTestStringValue constructs one strict string value.
func admissionTestStringValue(t *testing.T, input string) decision.Value {
	t.Helper()

	value, err := decision.NewValue(decision.ValueInput{String: &input})
	if err != nil {
		t.Fatalf("NewValue(string) error = %v", err)
	}

	return value
}

// admissionTestIntegerValue constructs one strict integer value.
func admissionTestIntegerValue(t *testing.T, input int64) decision.Value {
	t.Helper()

	value, err := decision.NewValue(decision.ValueInput{Integer: &input})
	if err != nil {
		t.Fatalf("NewValue(integer) error = %v", err)
	}

	return value
}

// admissionTestPermit admits one request or fails the owning test.
func admissionTestPermit(
	t *testing.T,
	authority policyruntime.AdmissionAuthority,
	caller decision.CallerContext,
	request decision.DecisionRequest,
) policyruntime.AdmissionPermit {
	t.Helper()

	permit, err := authority.Admit(context.Background(), caller, request)
	if err != nil {
		t.Fatalf("Admit() error = %v", err)
	}

	return permit
}
