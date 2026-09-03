// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/config/policyconfig"
	"github.com/croessner/nauthilus/v4/server/core/localization"
	"github.com/croessner/nauthilus/v4/server/openapi/generated/management"
	"github.com/croessner/nauthilus/v4/server/pluginloader"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
	"github.com/croessner/nauthilus/v4/server/pluginruntime"
	"github.com/croessner/nauthilus/v4/server/policy/admission"
	"github.com/croessner/nauthilus/v4/server/policy/catalogcompile"
	"github.com/croessner/nauthilus/v4/server/policy/configinput"
	"github.com/croessner/nauthilus/v4/server/policy/decision"
	decisionservice "github.com/croessner/nauthilus/v4/server/policy/decision/service"
	"github.com/croessner/nauthilus/v4/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v4/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v4/server/policy/runtime"
)

const (
	trackedPolicyRequestFixture = "../../../server/docs/policy-layer/dkim2_rspamd_policy_request_v1.example.json"
	trackedPolicyConfigFixture  = "../../../server/docs/examples/policy_dkim2_rspamd_verifier.yml"
)

//nolint:gocyclo // The cross-artifact proof keeps its independent boundary assertions visible.
func TestTrackedPolicyRequestPassesAdmissionAndNativeProvider(t *testing.T) {
	ctx := context.Background()
	dto := readTrackedPolicyRequest(t)
	prepared := prepareTrackedPolicyAdmission(ctx, t)
	caller := trackedPolicyCaller(t)
	request := decisionRequestFromWire(t, dto, caller)

	permit, err := prepared.Authority.Admit(ctx, caller, request)
	if err != nil {
		t.Fatalf("Admit() error = %v", err)
	}
	defer permit.Release()

	admitted := permit.Facts()
	if _, ok := admitted.Get("resource.dkim2.projection_schema"); !ok {
		t.Fatal("admission did not qualify the local DKIM2 projection fact")
	}

	if _, ok := admitted.Get("environment.rspamd.smtp_client_ip"); !ok {
		t.Fatal("admission did not qualify the local SMTP peer fact")
	}

	if _, duplicate := admitted.Get("resource.resource.dkim2.projection_schema"); duplicate {
		t.Fatal("admission double-prefixed the local resource fact")
	}

	if _, duplicate := admitted.Get("environment.environment.rspamd.smtp_client_ip"); duplicate {
		t.Fatal("admission double-prefixed the local environment fact")
	}

	plugin := NewPlugin()
	plugin.swapConfig(mustTestConfig(t))

	result, err := (decisionFactProvider{plugin: plugin}).Collect(ctx, pluginRequestFromAdmittedFacts(t, admitted))
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}

	if result.ErrorClass != "" || len(result.Facts) != 1 || result.Facts[0].Name != outputAssessedChain {
		t.Fatalf("Collect() result = %#v, want assessed_chain", result)
	}

	chain, ok := result.Facts[0].Value.Records()
	if !ok || len(chain.Records()) == 0 || !wireAssessmentAcceptable(t, chain.Records()[0]) {
		t.Fatalf("assessed_chain = %#v, want a non-empty acceptable assessment", result.Facts[0].Value)
	}
}

func TestTrackedPolicyRequestReceivesPermitFromDecisionService(t *testing.T) {
	tests := []struct {
		name    string
		request func(*testing.T) management.PolicyDecisionRequest
	}{
		{name: "complete chain", request: readTrackedPolicyRequest},
		{name: "current projection", request: readTrackedCurrentPolicyRequest},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertTrackedPolicyPermit(t, test.request(t))
		})
	}
}

// assertTrackedPolicyPermit exercises admission, the native provider, and the shipped policy as one decision path.
func assertTrackedPolicyPermit(t *testing.T, dto management.PolicyDecisionRequest) {
	t.Helper()

	ctx := context.Background()
	service, store := trackedPolicyDecisionService(ctx, t)
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		if err := store.Shutdown(shutdownCtx); err != nil {
			t.Errorf("GenerationStore.Shutdown() error = %v", err)
		}
	})

	authentication, err := decision.NewAuthenticationInput(decision.AuthenticationEvidence{
		Kind: "basic", Credential: []byte("opaque-policy-basic-proof"), TransportKind: "http", Protected: true,
	})
	if err != nil {
		t.Fatalf("NewAuthenticationInput() error = %v", err)
	}

	response, err := service.Evaluate(ctx, decision.Invocation{
		Request: decisionRequestInputFromWire(t, dto), Authentication: authentication,
		Finalization: decision.NewEvaluationFinalization(effectsupervisor.BoundaryHTTPCommit),
	})
	if err != nil {
		t.Fatalf("DecisionService.Evaluate() error = %v", err)
	}

	if response.Effect() != decision.EffectPermit || response.Policy().Rule() != "permit_strict_pass" {
		t.Fatalf(
			"DecisionService response = %q/%q status=%q, want permit/permit_strict_pass",
			response.Effect(), response.Policy().Rule(), response.Status().Code(),
		)
	}
}

// readTrackedCurrentPolicyRequest derives the producer-golden-backed current-mode request.
func readTrackedCurrentPolicyRequest(t *testing.T) management.PolicyDecisionRequest {
	t.Helper()

	dto := readTrackedPolicyRequest(t)
	replacements := map[string]string{
		"dkim2.scope":                 scopeCurrent,
		"dkim2.historical_content":    stateNotEvaluated,
		"dkim2.historical_signatures": stateNotEvaluated,
		"dkim2.do_not_modify_state":   stateNotEvaluated,
		"dkim2.do_not_explode_state":  stateNotEvaluated,
	}

	for name, replacement := range replacements {
		value := (*dto.Resource.Attributes)[name]
		value.String = &replacement
		(*dto.Resource.Attributes)[name] = value
	}

	return dto
}

// trackedPolicyDecisionService builds one sealed generation with the actual native provider and real admission.
//
//nolint:funlen // The test generation graph remains explicit so every real authority is reviewable.
func trackedPolicyDecisionService(
	ctx context.Context,
	t *testing.T,
) (*decisionservice.DecisionService, *policyruntime.GenerationStore) {
	t.Helper()

	document := decodeTrackedPolicyConfig(t)
	plugin := NewPlugin()
	plugin.swapConfig(mustTestConfig(t))
	provider := decisionFactProvider{plugin: plugin}
	acceptor := trackedPolicyEffectAcceptor{}
	bindings := trackedPolicyNativeBindings(t, provider)

	extensions, err := configinput.PrepareConfiguredNativeGeneration(ctx, configinput.ConfiguredNativeGenerationInput{
		Policy: document.Policy, Bindings: bindings, PostActionAcceptance: acceptor,
	})
	if err != nil {
		t.Fatalf("PrepareConfiguredNativeGeneration() error = %v", err)
	}

	preparedPolicy, err := configinput.PreparePolicy(ctx, 1, document.Policy)
	if err != nil {
		t.Fatalf("PreparePolicy() error = %v", err)
	}

	catalog := compileTrackedPolicyTarget(ctx, t, document, acceptor)
	definitions := extensions.Definitions

	if err = extensions.Bindings.ValidateCatalog(catalog); err != nil {
		t.Fatalf("ValidateCatalog() error = %v", err)
	}

	credentials, err := policyruntime.NewCredentialProfiles([]string{"rspamd-verifier"})
	if err != nil {
		t.Fatalf("NewCredentialProfiles() error = %v", err)
	}

	admissionPreparation, err := admission.Prepare(
		configinputAdmission(ctx, t, document), catalog, credentials,
	)
	if err != nil {
		t.Fatalf("admission.Prepare() error = %v", err)
	}

	store := policyruntime.NewGenerationStore()
	configured := &config.FileSettings{Policy: document.Policy}

	coordinator, err := policyruntime.NewCoordinator(policyruntime.CoordinatorConfig{
		Store: store,
		Slots: trackedPolicyRuntimeSlots(
			preparedPolicy, catalog, definitions, extensions, credentials, admissionPreparation,
		),
	})
	if err != nil {
		t.Fatalf("NewCoordinator() error = %v", err)
	}

	if _, err = coordinator.Apply(ctx, policyruntime.PrepareInput{Config: configured, ID: 1}); err != nil {
		t.Fatalf("Coordinator.Apply() error = %v", err)
	}

	source, err := decisionservice.NewStoreGenerationSource(store)
	if err != nil {
		t.Fatalf("NewStoreGenerationSource() error = %v", err)
	}

	service, err := decisionservice.NewDecisionService(source)
	if err != nil {
		t.Fatalf("NewDecisionService() error = %v", err)
	}

	return service, store
}

// compileTrackedPolicyTarget isolates the exact generic target from unrelated builtin authn activations.
func compileTrackedPolicyTarget(
	ctx context.Context,
	t *testing.T,
	document policyconfig.Document,
	acceptor effectsupervisor.Acceptor,
) *policyruntime.TargetCatalog {
	t.Helper()

	input, err := configinput.Normalize(ctx, document)
	if err != nil {
		t.Fatalf("configinput.Normalize() error = %v", err)
	}

	contributors, err := input.Contributors(ctx, acceptor)
	if err != nil {
		t.Fatalf("Contributors() error = %v", err)
	}

	activations := make([]registry.TargetActivation, 0, 1)

	for _, activation := range input.Activations {
		if activation.Target().String() == "dkim2/accept-message-instance" {
			activations = append(activations, activation)
		}
	}

	if len(activations) != 1 {
		t.Fatalf("tracked DKIM2 activations = %d, want one", len(activations))
	}

	catalog, err := catalogcompile.NewTargetCatalogCompiler(contributors...).Compile(ctx, activations)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	return catalog
}

// decodeTrackedPolicyConfig reads the executable reference Policy configuration.
func decodeTrackedPolicyConfig(t *testing.T) policyconfig.Document {
	t.Helper()

	file, err := os.Open(trackedPolicyConfigFixture)
	if err != nil {
		t.Fatalf("Open(%s) error = %v", trackedPolicyConfigFixture, err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			t.Errorf("Close(%s) error = %v", trackedPolicyConfigFixture, closeErr)
		}
	}()

	document, err := policyconfig.Decode("yaml", file)
	if err != nil {
		t.Fatalf("policyconfig.Decode() error = %v", err)
	}

	return document
}

// trackedPolicyNativeBindings captures the actual provider behind immutable native module identity.
func trackedPolicyNativeBindings(
	t *testing.T,
	provider pluginapi.DecisionFactProvider,
) *pluginruntime.GenerationBindings {
	t.Helper()

	descriptor := provider.Descriptor()
	component := pluginregistry.Component{
		Value: provider, DecisionFactProviderDescriptor: descriptor,
		ModuleName: pluginName, LocalName: providerName,
		Kind: pluginregistry.ComponentKindDecisionFactProvider, Origin: pluginregistry.ComponentOriginNative,
	}

	artifact := filepath.Join(t.TempDir(), "dkim2_reputation.so")
	if err := os.WriteFile(artifact, []byte("dkim2-reputation-native-binding-proof"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	digest, err := pluginloader.DigestArtifact(artifact)
	if err != nil {
		t.Fatalf("DigestArtifact() error = %v", err)
	}

	bindings, err := pluginruntime.CaptureGenerationBindings([]pluginloader.ModuleInstance{{
		Module: config.PluginModule{
			Name: pluginName, Type: config.PluginModuleTypeGo, Path: artifact, Config: testConfigMap(),
		},
		Descriptors: []pluginregistry.Component{component}, ArtifactPath: artifact, ArtifactDigest: digest,
		ModuleName: pluginName, Status: pluginloader.ModuleStatusRegistered,
	}})
	if err != nil {
		t.Fatalf("CaptureGenerationBindings() error = %v", err)
	}

	return bindings
}

// configinputAdmission returns the real caller-admission configuration from normalized tracked Policy.
func configinputAdmission(
	ctx context.Context,
	t *testing.T,
	document policyconfig.Document,
) admission.Configuration {
	t.Helper()

	input, err := configinput.Normalize(ctx, document)
	if err != nil {
		t.Fatalf("configinput.Normalize() error = %v", err)
	}

	return input.CallerAdmission()
}

// trackedPolicyRuntimeSlots assembles the complete coordinator graph around tracked immutable authorities.
func trackedPolicyRuntimeSlots(
	preparedPolicy *configinput.PreparedPolicy,
	catalog *policyruntime.TargetCatalog,
	definitions []registry.DefinitionContribution,
	extensions policyruntime.ExtensionPreparation,
	credentials policyruntime.CredentialProfiles,
	admissionPreparation policyruntime.AdmissionPreparation,
) policyruntime.PreparationSlots {
	return policyruntime.PreparationSlots{
		Policy: policyruntime.PolicyPreparationFunc(func(
			context.Context,
			policyruntime.PreparationInput,
		) (policyruntime.PolicyPreparation, error) {
			return policyruntime.PolicyPreparation{Policy: preparedPolicy}, nil
		}),
		Extensions: policyruntime.ExtensionPreparationFunc(func(
			context.Context,
			policyruntime.PreparationInput,
		) (policyruntime.ExtensionPreparation, error) {
			return extensions, nil
		}),
		Catalog: policyruntime.CatalogPreparationFunc(func(
			context.Context,
			policyruntime.CatalogPreparationInput,
		) (policyruntime.CatalogPreparation, error) {
			return policyruntime.CatalogPreparation{Catalog: catalog, Definitions: definitions}, nil
		}),
		CallerAuthentication: policyruntime.CallerAuthenticationPreparationFunc(func(
			context.Context,
			policyruntime.AuthorityPreparationInput,
		) (policyruntime.CallerAuthenticationPreparation, error) {
			return policyruntime.CallerAuthenticationPreparation{
				Authenticator: trackedPolicyAuthenticator{}, Credentials: credentials,
			}, nil
		}),
		Admission: policyruntime.AdmissionPreparationFunc(func(
			context.Context,
			policyruntime.AdmissionPreparationInput,
		) (policyruntime.AdmissionPreparation, error) {
			return admissionPreparation, nil
		}),
		Settings: policyruntime.SettingsPreparationFunc(func(
			context.Context,
			policyruntime.SettingsPreparationInput,
		) (policyruntime.SettingsPreparation, error) {
			return policyruntime.SettingsPreparation{
				MessageResolver: localization.NewResolver(localization.NewMapCatalog(nil), "en"),
				Settings: policyruntime.GenerationSettings{
					Limits: policyruntime.DecisionLimits{
						EvaluationTimeout: 2 * time.Second, PostActionBudget: time.Second, MaxDiagnosticsEntries: 64,
					},
					Reports: policyruntime.DecisionReportSettings{MaxEntries: 64},
				},
			}, nil
		}),
		Application: decisionservice.NewRuntimeApplicationPreparationSlot(),
	}
}

type trackedPolicyAuthenticator struct{}

// Authenticate returns the exact trusted caller accepted by the tracked Policy-Basic profile.
func (trackedPolicyAuthenticator) Authenticate(
	ctx context.Context,
	_ decision.AuthenticationInput,
) (decision.CallerContext, error) {
	if err := ctx.Err(); err != nil {
		return decision.CallerContext{}, err
	}

	return decision.NewCallerContext(decision.TrustedCallerInput{
		Principal: "rspamd-verifier", AuthenticationKind: "basic", TransportKind: "http",
	})
}

type trackedPolicyEffectAcceptor struct{}

// Accept is unreachable because the DKIM2 reference target defines no executable effects.
func (trackedPolicyEffectAcceptor) Accept(context.Context, effectsupervisor.Plan) (effectsupervisor.Receipt, error) {
	return effectsupervisor.Receipt{}, nil
}

// prepareTrackedPolicyAdmission compiles the executable reference configuration into the real admission authority.
func prepareTrackedPolicyAdmission(ctx context.Context, t *testing.T) policyruntime.AdmissionPreparation {
	t.Helper()

	file, err := os.Open(trackedPolicyConfigFixture)
	if err != nil {
		t.Fatalf("Open(%s) error = %v", trackedPolicyConfigFixture, err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			t.Errorf("Close(%s) error = %v", trackedPolicyConfigFixture, closeErr)
		}
	}()

	document, err := policyconfig.Decode("yaml", file)
	if err != nil {
		t.Fatalf("policyconfig.Decode() error = %v", err)
	}

	input, err := configinput.Normalize(ctx, document)
	if err != nil {
		t.Fatalf("configinput.Normalize() error = %v", err)
	}

	catalog, err := input.Compile(ctx, nil)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}

	credentials, err := policyruntime.NewCredentialProfiles([]string{"rspamd-verifier"})
	if err != nil {
		t.Fatalf("NewCredentialProfiles() error = %v", err)
	}

	prepared, err := admission.Prepare(input.CallerAdmission(), catalog, credentials)
	if err != nil {
		t.Fatalf("admission.Prepare() error = %v", err)
	}

	return prepared
}

// trackedPolicyCaller constructs the trusted Policy-Basic caller used by the executable reference configuration.
func trackedPolicyCaller(t *testing.T) decision.CallerContext {
	t.Helper()

	caller, err := decision.NewCallerContext(decision.TrustedCallerInput{
		Principal: "rspamd-verifier", AuthenticationKind: "basic", TransportKind: "http",
	})
	if err != nil {
		t.Fatalf("NewCallerContext() error = %v", err)
	}

	return caller
}

// decisionRequestFromWire maps local public attributes into the internal request consumed by admission.
func decisionRequestFromWire(
	t *testing.T,
	dto management.PolicyDecisionRequest,
	caller decision.CallerContext,
) decision.DecisionRequest {
	t.Helper()

	input := decisionRequestInputFromWire(t, dto)

	request, err := decision.NewDecisionRequest(input, caller)
	if err != nil {
		t.Fatalf("NewDecisionRequest() error = %v", err)
	}

	return request
}

// decisionRequestInputFromWire maps the public DTO into local-key internal request input.
func decisionRequestInputFromWire(t *testing.T, dto management.PolicyDecisionRequest) decision.DecisionRequestInput {
	t.Helper()

	target, err := decision.NewTarget(dto.Target.Namespace, dto.Target.Action)
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}

	resource := decisionEntityFromWire(t, dto.Resource)
	environment := decisionEnvironmentFromWire(t, dto.Environment)
	subject := decisionEntityFromWire(t, dto.Subject)
	attributes := decisionValueMapFromWire(t, dto.Attributes)

	requestID := ""
	if dto.RequestId != nil {
		requestID = *dto.RequestId
	}

	includeDiagnostics := false
	if dto.Options != nil && dto.Options.IncludeDiagnostics != nil {
		includeDiagnostics = *dto.Options.IncludeDiagnostics
	}

	return decision.DecisionRequestInput{
		Version: string(dto.Version), RequestID: requestID, Target: target, Subject: subject,
		Resource: resource, Environment: environment, Attributes: attributes,
		Options: decision.EvaluationOptions{IncludeDiagnostics: includeDiagnostics},
	}
}

// decisionEntityFromWire maps one optional public subject or resource with local attribute keys.
func decisionEntityFromWire(t *testing.T, input *management.PolicyEntity) decision.Entity {
	t.Helper()

	entityInput := decision.EntityInput{}

	if input != nil {
		if input.Type != nil {
			entityInput.Type = *input.Type
		}

		if input.Id != nil {
			entityInput.ID = *input.Id
		}

		entityInput.Attributes = decisionValueMapFromWire(t, input.Attributes)
	}

	entity, err := decision.NewEntity(entityInput)
	if err != nil {
		t.Fatalf("NewEntity() error = %v", err)
	}

	return entity
}

// decisionEnvironmentFromWire maps one optional public environment with local attribute keys.
func decisionEnvironmentFromWire(t *testing.T, input *management.PolicyEnvironment) decision.Environment {
	t.Helper()

	environmentInput := decision.EnvironmentInput{}

	if input != nil {
		if input.Service != nil {
			environmentInput.Service = *input.Service
		}

		if input.Instance != nil {
			environmentInput.Instance = *input.Instance
		}

		if input.Protocol != nil {
			environmentInput.Protocol = *input.Protocol
		}

		environmentInput.Attributes = decisionValueMapFromWire(t, input.Attributes)
	}

	environment, err := decision.NewEnvironment(environmentInput)
	if err != nil {
		t.Fatalf("NewEnvironment() error = %v", err)
	}

	return environment
}

// decisionValueMapFromWire converts an optional local public value map into strict internal values.
func decisionValueMapFromWire(t *testing.T, input *management.PolicyValueMap) map[string]decision.Value {
	t.Helper()

	if input == nil {
		return nil
	}

	result := make(map[string]decision.Value, len(*input))
	for name, value := range *input {
		result[name] = decisionValueFromWire(t, value)
	}

	return result
}

// decisionValueFromWire converts one strict OpenAPI union into the internal policy vocabulary.
func decisionValueFromWire(t *testing.T, value management.PolicyValue) decision.Value {
	t.Helper()

	input := decision.ValueInput{
		String: value.String, Boolean: value.Boolean, Double: value.Double, Timestamp: value.Timestamp,
	}
	if value.Strings != nil {
		input.Strings = *value.Strings
	}

	if value.Bytes != nil {
		input.Bytes = *value.Bytes
	}

	if value.Integer != nil {
		integer, err := strconv.ParseInt(*value.Integer, 10, 64)
		if err != nil {
			t.Fatalf("ParseInt(%q) error = %v", *value.Integer, err)
		}

		input.Integer = &integer
	}

	if value.Records != nil {
		records := decisionRecordsFromWire(t, *value.Records)
		input.Records = &records
	}

	converted, err := decision.NewValue(input)
	if err != nil {
		t.Fatalf("decision.NewValue() error = %v", err)
	}

	return converted
}

// decisionRecordsFromWire converts a public record collection into immutable internal records.
func decisionRecordsFromWire(t *testing.T, input []management.PolicyRecord) decision.RecordList {
	t.Helper()

	records := make([]decision.Record, 0, len(input))
	for recordIndex, wireRecord := range input {
		fields := make([]decision.RecordField, 0, len(wireRecord.Fields))
		for _, wireField := range wireRecord.Fields {
			value := decisionRecordValueFromWire(t, wireField.Value)

			field, err := decision.NewRecordField(wireField.Name, value)
			if err != nil {
				t.Fatalf("record %d field %s: %v", recordIndex, wireField.Name, err)
			}

			fields = append(fields, field)
		}

		record, err := decision.NewRecord(fields)
		if err != nil {
			t.Fatalf("decision.NewRecord(%d) error = %v", recordIndex, err)
		}

		records = append(records, record)
	}

	result, err := decision.NewRecordList(records)
	if err != nil {
		t.Fatalf("decision.NewRecordList() error = %v", err)
	}

	return result
}

// decisionRecordValueFromWire converts one public non-recursive field union.
func decisionRecordValueFromWire(t *testing.T, value management.PolicyRecordFieldValue) decision.RecordFieldValue {
	t.Helper()

	input := decision.RecordFieldValueInput{
		String: value.String, Boolean: value.Boolean, Double: value.Double, Timestamp: value.Timestamp,
	}
	if value.Strings != nil {
		input.Strings = *value.Strings
	}

	if value.Bytes != nil {
		input.Bytes = *value.Bytes
	}

	if value.Integer != nil {
		integer, err := strconv.ParseInt(*value.Integer, 10, 64)
		if err != nil {
			t.Fatalf("ParseInt(%q) error = %v", *value.Integer, err)
		}

		input.Integer = &integer
	}

	converted, err := decision.NewRecordFieldValue(input)
	if err != nil {
		t.Fatalf("decision.NewRecordFieldValue() error = %v", err)
	}

	return converted
}

// pluginRequestFromAdmittedFacts adapts validated host facts into the public native-provider view.
func pluginRequestFromAdmittedFacts(t *testing.T, admitted decision.FactSet) pluginapi.DecisionFactRequest {
	t.Helper()

	facts := make([]pluginapi.DecisionFactView, 0, admitted.Len())
	for _, fact := range admitted.Facts() {
		view, err := pluginapi.NewDecisionFactView(pluginapi.DecisionFactViewInput{
			ID: fact.ID(), Category: pluginFactCategory(t, fact.Category()), Value: pluginValueFromDecision(t, fact.Value()),
		})
		if err != nil {
			t.Fatalf("NewDecisionFactView(%s) error = %v", fact.ID(), err)
		}

		facts = append(facts, view)
	}

	caller, err := pluginapi.NewDecisionCallerView(pluginapi.DecisionCallerViewInput{
		Principal: "rspamd-verifier", ClientID: "rspamd-verifier", AuthenticationKind: "policy_basic",
	})
	if err != nil {
		t.Fatalf("NewDecisionCallerView() error = %v", err)
	}

	request, err := pluginapi.NewDecisionFactRequest(exactTarget, caller, facts)
	if err != nil {
		t.Fatalf("NewDecisionFactRequest() error = %v", err)
	}

	return request
}

// pluginFactCategory maps one internal admitted category into the public plugin vocabulary.
func pluginFactCategory(t *testing.T, category decision.FactCategory) pluginapi.DecisionFactCategory {
	t.Helper()

	switch category {
	case decision.FactCategorySubject:
		return pluginapi.DecisionFactCategorySubject
	case decision.FactCategoryResource:
		return pluginapi.DecisionFactCategoryResource
	case decision.FactCategoryEnvironment:
		return pluginapi.DecisionFactCategoryEnvironment
	default:
		t.Fatalf("unknown admitted fact category %q", category)

		return ""
	}
}

// pluginValueFromDecision maps one admitted strict value into the public plugin vocabulary.
func pluginValueFromDecision(t *testing.T, value decision.Value) pluginapi.DecisionValue {
	t.Helper()

	input := pluginapi.DecisionValueInput{}

	switch value.Kind() {
	case decision.ValueKindString:
		member, _ := value.StringValue()
		input.String = &member
	case decision.ValueKindBoolean:
		member, _ := value.Boolean()
		input.Boolean = &member
	case decision.ValueKindInteger:
		member, _ := value.Integer()
		input.Integer = &member
	case decision.ValueKindDouble:
		member, _ := value.Double()
		input.Double = &member
	case decision.ValueKindStrings:
		input.Strings, _ = value.Strings()
	case decision.ValueKindBytes:
		input.Bytes, _ = value.Bytes()
	case decision.ValueKindTimestamp:
		member, _ := value.Timestamp()
		input.Timestamp = &member
	case decision.ValueKindRecords:
		records, _ := value.Records()
		converted := pluginRecordsFromDecision(t, records)
		input.Records = &converted
	default:
		t.Fatalf("unknown admitted value kind %q", value.Kind())
	}

	converted, err := pluginapi.NewDecisionValue(input)
	if err != nil {
		t.Fatalf("pluginapi.NewDecisionValue() error = %v", err)
	}

	return converted
}

// pluginRecordsFromDecision maps admitted internal records into public immutable plugin records.
func pluginRecordsFromDecision(t *testing.T, input decision.RecordList) pluginapi.DecisionRecordList {
	t.Helper()

	records := make([]pluginapi.DecisionRecord, 0, len(input.Records()))
	for recordIndex, record := range input.Records() {
		fields := make([]pluginapi.DecisionRecordField, 0, len(record.Fields()))
		for _, field := range record.Fields() {
			value := pluginValueFromDecision(t, field.Value().Value())

			leaf, err := pluginapi.NewDecisionRecordFieldValue(value)
			if err != nil {
				t.Fatalf("record %d field %s value: %v", recordIndex, field.Name(), err)
			}

			converted, err := pluginapi.NewDecisionRecordField(field.Name(), leaf)
			if err != nil {
				t.Fatalf("record %d field %s: %v", recordIndex, field.Name(), err)
			}

			fields = append(fields, converted)
		}

		converted, err := pluginapi.NewDecisionRecord(fields)
		if err != nil {
			t.Fatalf("pluginapi.NewDecisionRecord(%d) error = %v", recordIndex, err)
		}

		records = append(records, converted)
	}

	result, err := pluginapi.NewDecisionRecordList(records)
	if err != nil {
		t.Fatalf("pluginapi.NewDecisionRecordList() error = %v", err)
	}

	return result
}

// readTrackedPolicyRequest decodes the exact OpenAPI-generated request DTO used by the HTTP boundary.
func readTrackedPolicyRequest(t *testing.T) management.PolicyDecisionRequest {
	t.Helper()

	payload, err := os.ReadFile(trackedPolicyRequestFixture)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	var dto management.PolicyDecisionRequest
	if err = json.Unmarshal(payload, &dto); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	return dto
}

// wireAssessmentAcceptable extracts the provider's exact boolean assessment field.
func wireAssessmentAcceptable(t *testing.T, record pluginapi.DecisionRecord) bool {
	t.Helper()

	for _, field := range record.Fields() {
		if field.Name() != "acceptable" {
			continue
		}

		value, ok := field.Value().Value().Boolean()
		if !ok {
			t.Fatal("acceptable output is not boolean")
		}

		return value
	}

	t.Fatal("acceptable output is missing")

	return false
}
