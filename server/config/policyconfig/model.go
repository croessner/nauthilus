// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Package policyconfig owns the standalone unified policy configuration contract.
package policyconfig

import (
	"time"

	"github.com/croessner/nauthilus/v3/server/secret"
)

const (
	// ProviderKindLua selects the standalone target-aware Lua provider path.
	ProviderKindLua = "lua"

	// ProviderKindLuaEnvironment selects one generation-bound authn environment source.
	ProviderKindLuaEnvironment = "lua_environment"

	// ProviderKindLuaSubject selects one generation-bound authn subject source.
	ProviderKindLuaSubject = "lua_subject"

	// ProviderKindNative selects a generation-bound native Go provider.
	ProviderKindNative = "native"

	// ProviderKindPlugin selects an existing public auth-shaped native extension.
	ProviderKindPlugin = "plugin"

	// VisibilityPrivate keeps a policy set inside its owning namespace.
	VisibilityPrivate = "private"

	// VisibilityExported permits exact contract-checked cross-namespace use.
	VisibilityExported = "exported"

	// RedactedValue is the only canonical representation of secret material.
	RedactedValue = "***REDACTED***"
)

// Document is the isolated top-level configuration document.
type Document struct {
	Policy PolicyConfig `mapstructure:"policy"`
}

// PolicyConfig groups global API admission, namespace definitions, and explicit activations.
type PolicyConfig struct {
	Namespaces map[string]NamespaceConfig `mapstructure:"namespaces"`
	API        APIConfig                  `mapstructure:"api"`
	Targets    []TargetConfig             `mapstructure:"targets"`
}

// APIConfig controls standalone Policy API enablement and caller admission.
type APIConfig struct {
	HTTP    HTTPConfig            `mapstructure:"http"`
	GRPC    GRPCConfig            `mapstructure:"grpc"`
	Limits  APILimitsConfig       `mapstructure:"limits"`
	Clients []ClientProfileConfig `mapstructure:"clients"`
	Enabled bool                  `mapstructure:"enabled"`
}

// HTTPConfig controls HTTP transport availability.
type HTTPConfig struct {
	Enabled bool `mapstructure:"enabled"`
}

// GRPCConfig controls gRPC transport availability and mTLS requirements.
type GRPCConfig struct {
	Enabled     bool `mapstructure:"enabled"`
	RequireMTLS bool `mapstructure:"require_mtls"`
}

// APILimitsConfig declares global unary request and evaluation bounds.
type APILimitsConfig struct {
	ProviderTimeout            time.Duration `mapstructure:"provider_timeout"`
	EvaluationTimeout          time.Duration `mapstructure:"evaluation_timeout"`
	MaxRequestBytes            int           `mapstructure:"max_request_bytes"`
	MaxFacts                   int           `mapstructure:"max_facts"`
	MaxStringBytes             int           `mapstructure:"max_string_bytes"`
	MaxListItems               int           `mapstructure:"max_list_items"`
	MaxValueBytes              int           `mapstructure:"max_value_bytes"`
	PerClientConcurrency       int           `mapstructure:"per_client_concurrency"`
	PerClientRequestsPerSecond int           `mapstructure:"per_client_requests_per_second"`
	MaxObligations             int           `mapstructure:"max_obligations"`
	MaxAdvice                  int           `mapstructure:"max_advice"`
	MaxParameterBytes          int           `mapstructure:"max_parameter_bytes"`
}

// ClientProfileConfig binds one authenticated principal to a bounded admission profile.
type ClientProfileConfig struct {
	Authentication               ClientAuthenticationConfig `mapstructure:"authentication"`
	Principal                    string                     `mapstructure:"principal"`
	AuthenticationKinds          []string                   `mapstructure:"authentication_kinds"`
	Targets                      []ClientTargetConfig       `mapstructure:"targets"`
	AllowedSubjectAttributes     []string                   `mapstructure:"allowed_subject_attributes"`
	AllowedResourceAttributes    []string                   `mapstructure:"allowed_resource_attributes"`
	AllowedEnvironmentAttributes []string                   `mapstructure:"allowed_environment_attributes"`
	AllowedInputAttributes       []string                   `mapstructure:"allowed_input_attributes"`
	AllowedSchemas               []string                   `mapstructure:"allowed_schemas"`
	MaxRequestBytes              int                        `mapstructure:"max_request_bytes"`
	MaxFacts                     int                        `mapstructure:"max_facts"`
	MaxConcurrency               int                        `mapstructure:"max_concurrency"`
	RequestsPerSecond            int                        `mapstructure:"requests_per_second"`
	Diagnostics                  bool                       `mapstructure:"diagnostics"`
	RequireMTLS                  bool                       `mapstructure:"require_mtls"`
}

// ClientAuthenticationConfig contains profile-owned authentication material.
type ClientAuthenticationConfig struct {
	Basic *BasicAuthenticationConfig `mapstructure:"basic"`
}

// BasicAuthenticationConfig contains dedicated Policy-Basic credentials.
type BasicAuthenticationConfig struct {
	Username string       `mapstructure:"username"`
	Password secret.Value `mapstructure:"password"`
}

// ClientTargetConfig grants a profile a bounded namespace/action allowlist.
type ClientTargetConfig struct {
	Namespace string   `mapstructure:"namespace"`
	Actions   []string `mapstructure:"actions"`
}

// NamespaceConfig owns every configurable definition in one policy namespace.
type NamespaceConfig struct {
	Localization        LocalizationConfig          `mapstructure:"localization"`
	ConditionSets       ConditionSetsConfig         `mapstructure:"condition_sets"`
	SchemaContributions SchemaContributionsConfig   `mapstructure:"schema_contributions"`
	FactSources         FactSourcesConfig           `mapstructure:"fact_sources"`
	Providers           map[string]ProviderConfig   `mapstructure:"providers"`
	Effects             map[string]EffectConfig     `mapstructure:"effects"`
	DomainPlans         map[string]DomainPlanConfig `mapstructure:"domain_plans"`
	PolicySets          map[string]PolicySetConfig  `mapstructure:"policy_sets"`
}

// LocalizationConfig contains namespace-owned translation catalogs.
type LocalizationConfig struct {
	Catalogs []TranslationCatalogConfig `mapstructure:"catalogs"`
}

// TranslationCatalogConfig declares one language catalog.
type TranslationCatalogConfig struct {
	Entries   map[string]string `mapstructure:"entries"`
	Namespace string            `mapstructure:"namespace"`
	Language  string            `mapstructure:"language"`
}

// ConditionSetsConfig owns reusable condition operands.
type ConditionSetsConfig struct {
	Networks    map[string][]string         `mapstructure:"networks"`
	Strings     map[string][]string         `mapstructure:"strings"`
	TimeWindows map[string]TimeWindowConfig `mapstructure:"time_windows"`
}

// TimeWindowConfig declares one named local-time window.
type TimeWindowConfig struct {
	Timezone  string               `mapstructure:"timezone"`
	Days      []string             `mapstructure:"days"`
	Intervals []TimeIntervalConfig `mapstructure:"intervals"`
}

// TimeIntervalConfig declares one local-time interval.
type TimeIntervalConfig struct {
	Start string `mapstructure:"start"`
	End   string `mapstructure:"end"`
}

// SchemaContributionsConfig groups namespace-owned schema extensions.
type SchemaContributionsConfig struct {
	Static map[string]StaticTargetSchemaConfig `mapstructure:"static"`
	Lua    LuaSchemaContributionsConfig        `mapstructure:"lua"`
}

// LuaSchemaContributionsConfig declares Lua registry scripts.
type LuaSchemaContributionsConfig struct {
	RegistryScripts []string `mapstructure:"registry_scripts"`
}

// FactSourcesConfig declares bounded request and backend fact projections.
type FactSourcesConfig struct {
	HTTPHeaders       []HTTPHeaderFactSourceConfig       `mapstructure:"http_headers"`
	GRPCMetadata      []GRPCMetadataFactSourceConfig     `mapstructure:"grpc_metadata"`
	BackendAttributes []BackendAttributeFactSourceConfig `mapstructure:"backend_attributes"`
}

// NormalizeConfig controls deterministic request-value normalization.
type NormalizeConfig struct {
	Case      string `mapstructure:"case"`
	MaxLength int    `mapstructure:"max_length"`
	Trim      bool   `mapstructure:"trim"`
}

// HTTPHeaderFactSourceConfig maps one allowlisted HTTP header to a fact.
type HTTPHeaderFactSourceConfig struct {
	Normalize  NormalizeConfig `mapstructure:"normalize"`
	Header     string          `mapstructure:"header"`
	Attribute  string          `mapstructure:"attribute"`
	Visibility string          `mapstructure:"visibility"`
}

// GRPCMetadataFactSourceConfig maps one allowlisted gRPC metadata key to a fact.
type GRPCMetadataFactSourceConfig struct {
	Normalize  NormalizeConfig `mapstructure:"normalize"`
	Key        string          `mapstructure:"key"`
	Attribute  string          `mapstructure:"attribute"`
	Visibility string          `mapstructure:"visibility"`
}

// BackendAttributeFactSourceConfig maps one backend attribute to a policy fact.
type BackendAttributeFactSourceConfig struct {
	Name        string `mapstructure:"name"`
	Attribute   string `mapstructure:"attribute"`
	Type        string `mapstructure:"type"`
	Sensitivity string `mapstructure:"sensitivity"`
}

// TargetReferenceConfig names one exact target action inside the owning namespace.
type TargetReferenceConfig struct {
	Action string `mapstructure:"action"`
}

// DiagnosticsConfig contains an optional public target-local alias.
type DiagnosticsConfig struct {
	PublicID string `mapstructure:"public_id"`
}

// ProviderConfig declares one namespace-owned provider definition.
//
// Secrets reserves stable schema and redaction paths. The production generation
// rejects non-empty values until a typed provider credential carrier exists.
type ProviderConfig struct {
	Secrets       map[string]secret.Value `mapstructure:"secrets"`
	Kind          string                  `mapstructure:"kind"`
	ScriptPath    string                  `mapstructure:"script_path"`
	Module        string                  `mapstructure:"module"`
	Targets       []TargetReferenceConfig `mapstructure:"targets"`
	Executions    []string                `mapstructure:"executions"`
	Requires      []string                `mapstructure:"requires"`
	ProducedFacts []string                `mapstructure:"produced_facts"`
	Failure       string                  `mapstructure:"failure"`
	Timeout       time.Duration           `mapstructure:"timeout"`
	Diagnostics   DiagnosticsConfig       `mapstructure:"diagnostics"`
}

// CanonicalID derives host-owned generic identities while preserving legacy provider names.
func (p ProviderConfig) CanonicalID(namespace string, name string) string {
	switch p.Kind {
	case ProviderKindLua:
		return namespace + "/lua." + p.Module + "." + name
	case ProviderKindNative:
		return namespace + "/plugin." + p.Module + "." + name
	}

	return namespace + "/" + name
}

// EffectConfig declares one namespace-owned typed effect definition.
//
// Secrets reserves stable schema and redaction paths. The production generation
// rejects non-empty values until a typed effect credential carrier exists.
type EffectConfig struct {
	Secrets     map[string]secret.Value          `mapstructure:"secrets"`
	Parameters  map[string]EffectParameterConfig `mapstructure:"parameters"`
	Kind        string                           `mapstructure:"kind"`
	ActionType  string                           `mapstructure:"action_type"`
	ScriptPath  string                           `mapstructure:"script_path"`
	Provider    string                           `mapstructure:"provider"`
	Targets     []TargetReferenceConfig          `mapstructure:"targets"`
	Execution   string                           `mapstructure:"execution"`
	Diagnostics DiagnosticsConfig                `mapstructure:"diagnostics"`
}

// EffectParameterConfig declares one bounded typed effect parameter.
type EffectParameterConfig struct {
	Type           string   `mapstructure:"type"`
	AllowedStrings []string `mapstructure:"allowed_strings"`
	MaxLength      int      `mapstructure:"max_length"`
	MaxItems       int      `mapstructure:"max_items"`
	MaxBytes       int      `mapstructure:"max_bytes"`
	NonEmpty       bool     `mapstructure:"non_empty"`
	Required       bool     `mapstructure:"required"`
}

// DomainPlanConfig declares one namespace-owned provider orchestration plan.
type DomainPlanConfig struct {
	SchedulerGuards map[string]SchedulerGuardConfig `mapstructure:"scheduler_guards"`
	Checkpoints     map[string]CheckpointConfig     `mapstructure:"checkpoints"`
}

// SchedulerGuardConfig declares one provider scheduling guard.
type SchedulerGuardConfig struct {
	If                 ConditionConfig `mapstructure:"if"`
	OnMissingAttribute string          `mapstructure:"on_missing_attribute"`
}

// CheckpointConfig declares ordered providers in one domain checkpoint.
type CheckpointConfig struct {
	Providers []ProviderInstanceConfig `mapstructure:"providers"`
}

// ProviderInstanceConfig binds a provider definition into a checkpoint.
type ProviderInstanceConfig struct {
	RunIf       RunIfConfig `mapstructure:"run_if"`
	ObserveSafe *bool       `mapstructure:"observe_safe"`
	Name        string      `mapstructure:"name"`
	Use         string      `mapstructure:"use"`
	Actions     []string    `mapstructure:"actions"`
	After       []string    `mapstructure:"after"`
	SkipIf      []string    `mapstructure:"skip_if"`
	Output      string      `mapstructure:"output"`
}

// RunIfConfig contains the authn-only structural provider guard.
type RunIfConfig struct {
	AuthState string `mapstructure:"auth_state"`
}

// PolicySetConfig declares one namespace-owned reusable set.
type PolicySetConfig struct {
	ExportContract *ExportContractConfig `mapstructure:"export_contract"`
	Visibility     string                `mapstructure:"visibility"`
	Rules          []PolicyRuleConfig    `mapstructure:"rules"`
	Diagnostics    DiagnosticsConfig     `mapstructure:"diagnostics"`
}

// ExportContractConfig declares the exact capability of an exported set.
type ExportContractConfig struct {
	RequiredFacts         []RequiredFactConfig `mapstructure:"required_facts"`
	CompatibleCheckpoints []string             `mapstructure:"compatible_checkpoints"`
	AllowedDecisions      []string             `mapstructure:"allowed_decisions"`
	AllowedEffects        []string             `mapstructure:"allowed_effects"`
}

// RequiredFactConfig declares one typed fact required by an exported set.
type RequiredFactConfig struct {
	Attribute string `mapstructure:"attribute"`
	Type      string `mapstructure:"type"`
}

// PolicyRuleConfig declares one ordered checkpoint-scoped policy rule.
type PolicyRuleConfig struct {
	If               ConditionConfig `mapstructure:"if"`
	Then             ThenConfig      `mapstructure:"then"`
	Name             string          `mapstructure:"name"`
	Checkpoint       string          `mapstructure:"checkpoint"`
	Actions          []string        `mapstructure:"actions"`
	RequireProviders []string        `mapstructure:"require_providers"`
}

// ConditionConfig is the standalone recursive policy condition tree.
type ConditionConfig struct {
	Not              *ConditionConfig  `mapstructure:"not"`
	Always           *bool             `mapstructure:"always"`
	Attribute        string            `mapstructure:"attribute"`
	Detail           string            `mapstructure:"detail"`
	Matches          string            `mapstructure:"matches"`
	CIDRContains     string            `mapstructure:"cidr_contains"`
	WithinTimeWindow string            `mapstructure:"within_time_window"`
	Is               any               `mapstructure:"is"`
	Eq               any               `mapstructure:"eq"`
	Ne               any               `mapstructure:"ne"`
	In               any               `mapstructure:"in"`
	NotIn            any               `mapstructure:"not_in"`
	Exists           *bool             `mapstructure:"exists"`
	Contains         any               `mapstructure:"contains"`
	ContainsAny      []any             `mapstructure:"contains_any"`
	ContainsAll      []any             `mapstructure:"contains_all"`
	ContainsNone     []any             `mapstructure:"contains_none"`
	GT               any               `mapstructure:"gt"`
	GTE              any               `mapstructure:"gte"`
	LT               any               `mapstructure:"lt"`
	LTE              any               `mapstructure:"lte"`
	All              []ConditionConfig `mapstructure:"all"`
	Any              []ConditionConfig `mapstructure:"any"`
}

// ThenConfig declares the selected decision, public response markers, and effects.
type ThenConfig struct {
	ResponseMessage  ResponseMessageConfig   `mapstructure:"response_message"`
	ResponseLanguage ResponseLanguageConfig  `mapstructure:"response_language"`
	Control          DecisionControlConfig   `mapstructure:"control"`
	Decision         string                  `mapstructure:"decision"`
	Reason           string                  `mapstructure:"reason"`
	OutcomeMarker    string                  `mapstructure:"outcome_marker"`
	FSMEventMarker   string                  `mapstructure:"fsm_event_marker"`
	ResponseMarker   string                  `mapstructure:"response_marker"`
	Obligations      []EffectSelectionConfig `mapstructure:"obligations"`
	Advice           []EffectSelectionConfig `mapstructure:"advice"`
}

// ResponseMessageConfig declares one optional response message source.
type ResponseMessageConfig struct {
	From      string `mapstructure:"from"`
	Text      string `mapstructure:"text"`
	I18NKey   string `mapstructure:"i18n_key"`
	Attribute string `mapstructure:"attribute"`
	Detail    string `mapstructure:"detail"`
	Fallback  string `mapstructure:"fallback"`
}

// ResponseLanguageConfig declares optional response-language metadata.
type ResponseLanguageConfig struct {
	From      string `mapstructure:"from"`
	Language  string `mapstructure:"language"`
	Attribute string `mapstructure:"attribute"`
	Fallback  string `mapstructure:"fallback"`
}

// EffectSelectionConfig selects one qualified effect with typed parameters.
type EffectSelectionConfig struct {
	ID         string         `mapstructure:"id"`
	Parameters map[string]any `mapstructure:"parameters"`
}

// DecisionControlConfig carries checkpoint-local provider control output.
type DecisionControlConfig struct {
	SkipRemainingCheckpointProviders bool `mapstructure:"skip_remaining_checkpoint_providers"`
}

// TargetConfig explicitly activates one exact namespace/action/schema target.
type TargetConfig struct {
	Plans         map[string]TargetPlanConfig `mapstructure:"plans"`
	Namespace     string                      `mapstructure:"namespace"`
	Action        string                      `mapstructure:"action"`
	Schema        string                      `mapstructure:"schema"`
	DomainPlan    string                      `mapstructure:"domain_plan"`
	Mode          string                      `mapstructure:"mode"`
	DefaultPolicy string                      `mapstructure:"default_policy"`
	NoMatch       string                      `mapstructure:"no_match"`
	Timeouts      TargetTimeoutsConfig        `mapstructure:"timeouts"`
	Report        ReportConfig                `mapstructure:"report"`
}

// TargetTimeoutsConfig declares generic evaluation and provider budgets.
type TargetTimeoutsConfig struct {
	Evaluation      time.Duration `mapstructure:"evaluation"`
	ProviderDefault time.Duration `mapstructure:"provider_default"`
}

// TargetPlanConfig binds exact qualified policy sets into one checkpoint.
type TargetPlanConfig struct {
	PolicySets []string `mapstructure:"policy_sets"`
}

// ReportConfig controls target diagnostic report construction.
type ReportConfig struct {
	Enabled           bool `mapstructure:"enabled"`
	IncludeFSM        bool `mapstructure:"include_fsm"`
	IncludeChecks     bool `mapstructure:"include_checks"`
	IncludeAttributes bool `mapstructure:"include_attributes"`
}
