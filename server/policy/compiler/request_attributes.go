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

package compiler

import (
	"fmt"
	"net/textproto"
	"regexp"
	"strings"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/policy"
	policyregistry "github.com/croessner/nauthilus/v3/server/policy/registry"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"

	"golang.org/x/net/http/httpguts"
)

const (
	requestHeadersConfigPath       = "auth.policy.request_headers"
	requestMetadataConfigPath      = "auth.policy.request_metadata"
	requestHeaderAttributePrefix   = "request.header."
	requestMetadataAttributePrefix = "request.metadata."
	requestAttributeVisibility     = "public"
	requestAttributeDefaultMaxLen  = 256
	requestAttributeCaseLower      = "lower"
	requestAttributeCaseUpper      = "upper"
)

var (
	requestAttributeIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)
	metadataKeyPattern        = regexp.MustCompile(`^[0-9a-z_.-]+$`)
	unsafeRequestSourceNames  = map[string]struct{}{
		"authorization":       {},
		"proxy-authorization": {},
		"cookie":              {},
		"set-cookie":          {},
	}
)

func registerRequestAttributes(
	policyConfig config.AuthPolicySection,
	registry *policyregistry.AttributeRegistry,
) (policyruntime.RequestAttributeSettings, error) {
	if registry == nil {
		return policyruntime.RequestAttributeSettings{}, nil
	}

	seen := make(map[string]string, len(policyConfig.RequestHeaders)+len(policyConfig.RequestMetadata))

	headers, err := compileRequestHeaderAttributes(policyConfig.RequestHeaders, seen, registry)
	if err != nil {
		return policyruntime.RequestAttributeSettings{}, err
	}

	metadata, err := compileRequestMetadataAttributes(policyConfig.RequestMetadata, seen, registry)
	if err != nil {
		return policyruntime.RequestAttributeSettings{}, err
	}

	return policyruntime.RequestAttributeSettings{
		Headers:  headers,
		Metadata: metadata,
	}, nil
}

func compileRequestHeaderAttributes(
	configs []config.PolicyRequestHeaderAttributeConfig,
	seen map[string]string,
	registry *policyregistry.AttributeRegistry,
) ([]policyruntime.RequestHeaderAttribute, error) {
	return compileRequestAttributePlans(configs, seen, registry, requestHeaderPlanAdapter())
}

func compileRequestMetadataAttributes(
	configs []config.PolicyRequestMetadataAttributeConfig,
	seen map[string]string,
	registry *policyregistry.AttributeRegistry,
) ([]policyruntime.RequestMetadataAttribute, error) {
	return compileRequestAttributePlans(configs, seen, registry, requestMetadataPlanAdapter())
}

func requestHeaderPlanAdapter() requestAttributePlanAdapter[
	config.PolicyRequestHeaderAttributeConfig,
	policyruntime.RequestHeaderAttribute,
] {
	return newRequestAttributePlanAdapter(
		requestHeadersConfigPath,
		"header",
		requestHeaderAttributePrefix,
		requestHeaderSource,
		requestHeaderAttribute,
		requestHeaderNormalize,
		requestHeaderVisibility,
		compileRequestHeaderName,
		"HTTP request header",
		newRequestHeaderPlan,
	)
}

func requestMetadataPlanAdapter() requestAttributePlanAdapter[
	config.PolicyRequestMetadataAttributeConfig,
	policyruntime.RequestMetadataAttribute,
] {
	return newRequestAttributePlanAdapter(
		requestMetadataConfigPath,
		"key",
		requestMetadataAttributePrefix,
		requestMetadataSource,
		requestMetadataAttribute,
		requestMetadataNormalize,
		requestMetadataVisibility,
		compileRequestMetadataKey,
		"gRPC request metadata",
		newRequestMetadataPlan,
	)
}

type requestAttributePlanAdapter[C any, P any] struct {
	configPath      string
	sourceField     string
	attributePrefix string
	source          func(C) string
	attribute       func(C) string
	normalize       func(C) config.PolicyRequestAttributeNormalizeConfig
	visibility      func(C) string
	compileSource   func(string, string) (string, error)
	description     func(string) string
	plan            func(string, string, policyruntime.RequestAttributeNormalization) P
}

func newRequestAttributePlanAdapter[C any, P any](
	configPath string,
	sourceField string,
	attributePrefix string,
	source func(C) string,
	attribute func(C) string,
	normalize func(C) config.PolicyRequestAttributeNormalizeConfig,
	visibility func(C) string,
	compileSource func(string, string) (string, error),
	sourceLabel string,
	plan func(string, string, policyruntime.RequestAttributeNormalization) P,
) requestAttributePlanAdapter[C, P] {
	return requestAttributePlanAdapter[C, P]{
		configPath:      configPath,
		sourceField:     sourceField,
		attributePrefix: attributePrefix,
		source:          source,
		attribute:       attribute,
		normalize:       normalize,
		visibility:      visibility,
		compileSource:   compileSource,
		description:     requestAttributeDescription(sourceLabel),
		plan:            plan,
	}
}

func requestAttributeDescription(sourceLabel string) func(string) string {
	return func(source string) string {
		return fmt.Sprintf("Allowlisted %s %q exposed as a normalized policy request fact.", sourceLabel, source)
	}
}

func requestHeaderSource(entry config.PolicyRequestHeaderAttributeConfig) string { return entry.Header }

func requestHeaderAttribute(entry config.PolicyRequestHeaderAttributeConfig) string {
	return entry.Attribute
}

func requestHeaderNormalize(entry config.PolicyRequestHeaderAttributeConfig) config.PolicyRequestAttributeNormalizeConfig {
	return entry.Normalize
}

func requestHeaderVisibility(entry config.PolicyRequestHeaderAttributeConfig) string {
	return entry.Visibility
}

func newRequestHeaderPlan(
	source string,
	attributeID string,
	normalize policyruntime.RequestAttributeNormalization,
) policyruntime.RequestHeaderAttribute {
	return policyruntime.RequestHeaderAttribute{Header: source, Attribute: attributeID, Normalize: normalize}
}

func requestMetadataSource(entry config.PolicyRequestMetadataAttributeConfig) string {
	return entry.Key
}

func requestMetadataAttribute(entry config.PolicyRequestMetadataAttributeConfig) string {
	return entry.Attribute
}

func requestMetadataNormalize(entry config.PolicyRequestMetadataAttributeConfig) config.PolicyRequestAttributeNormalizeConfig {
	return entry.Normalize
}

func requestMetadataVisibility(entry config.PolicyRequestMetadataAttributeConfig) string {
	return entry.Visibility
}

func newRequestMetadataPlan(
	source string,
	attributeID string,
	normalize policyruntime.RequestAttributeNormalization,
) policyruntime.RequestMetadataAttribute {
	return policyruntime.RequestMetadataAttribute{Key: source, Attribute: attributeID, Normalize: normalize}
}

func compileRequestAttributePlans[C any, P any](
	configs []C,
	seen map[string]string,
	registry *policyregistry.AttributeRegistry,
	adapter requestAttributePlanAdapter[C, P],
) ([]P, error) {
	plans := make([]P, 0, len(configs))
	for index, requestConfig := range configs {
		plan, err := compileRequestAttributePlan(requestConfig, indexedPath(adapter.configPath, index), seen, registry, adapter)
		if err != nil {
			return nil, err
		}

		plans = append(plans, plan)
	}

	return plans, nil
}

func compileRequestAttributePlan[C any, P any](
	requestConfig C,
	path string,
	seen map[string]string,
	registry *policyregistry.AttributeRegistry,
	adapter requestAttributePlanAdapter[C, P],
) (P, error) {
	source, attributeID, normalize, err := compileRequestAttributePlanParts(requestConfig, path, seen, adapter)
	if err != nil {
		var zero P

		return zero, err
	}

	if err := registerRequestAttributeDefinition(registry, requestAttributeDefinition(attributeID, adapter.description(source))); err != nil {
		var zero P

		return zero, err
	}

	return adapter.plan(source, attributeID, normalize), nil
}

func compileRequestAttributePlanParts[C any, P any](
	requestConfig C,
	path string,
	seen map[string]string,
	adapter requestAttributePlanAdapter[C, P],
) (string, string, policyruntime.RequestAttributeNormalization, error) {
	source, err := adapter.compileSource(adapter.source(requestConfig), childPath(path, adapter.sourceField))
	if err != nil {
		return "", "", policyruntime.RequestAttributeNormalization{}, err
	}

	attributeID, err := compileRequestAttributeID(adapter.attribute(requestConfig), adapter.attributePrefix, childPath(path, "attribute"), seen, path)
	if err != nil {
		return "", "", policyruntime.RequestAttributeNormalization{}, err
	}

	normalize, err := compileRequestAttributeNormalization(adapter.normalize(requestConfig), childPath(path, "normalize"))
	if err != nil {
		return "", "", policyruntime.RequestAttributeNormalization{}, err
	}

	if err := validateRequestAttributeVisibility(adapter.visibility(requestConfig), childPath(path, "visibility")); err != nil {
		return "", "", policyruntime.RequestAttributeNormalization{}, err
	}

	return source, attributeID, normalize, nil
}

func compileRequestHeaderName(value string, path string) (string, error) {
	header := strings.TrimSpace(value)
	if header == "" {
		return "", configPathError(path, "must not be empty")
	}

	if !httpguts.ValidHeaderFieldName(header) {
		return "", configPathError(path, "must be a valid HTTP header name")
	}

	if requestSourceNameUnsafe(header) {
		return "", configPathError(path, "must not expose credential or session headers")
	}

	return textproto.CanonicalMIMEHeaderKey(header), nil
}

func compileRequestMetadataKey(value string, path string) (string, error) {
	key := strings.TrimSpace(value)
	if key == "" {
		return "", configPathError(path, "must not be empty")
	}

	if key != strings.ToLower(key) || !metadataKeyPattern.MatchString(key) {
		return "", configPathError(path, "must be a lowercase gRPC metadata key")
	}

	if requestSourceNameUnsafe(key) {
		return "", configPathError(path, "must not expose credential or session metadata")
	}

	return key, nil
}

func compileRequestAttributeID(
	value string,
	requiredPrefix string,
	path string,
	seen map[string]string,
	sourcePath string,
) (string, error) {
	attributeID := strings.TrimSpace(value)
	if attributeID == "" {
		return "", configPathError(path, "must not be empty")
	}

	if !strings.HasPrefix(attributeID, requiredPrefix) || !requestAttributeIDPattern.MatchString(attributeID) {
		return "", configPathError(path, "must be a safe request attribute ID with the correct source prefix")
	}

	if previous, exists := seen[attributeID]; exists {
		return "", configPathError(path, fmt.Sprintf("duplicates request attribute from %s", previous))
	}

	seen[attributeID] = sourcePath

	return attributeID, nil
}

func compileRequestAttributeNormalization(
	normalize config.PolicyRequestAttributeNormalizeConfig,
	path string,
) (policyruntime.RequestAttributeNormalization, error) {
	caseMode := strings.TrimSpace(normalize.Case)
	switch caseMode {
	case "", requestAttributeCaseLower, requestAttributeCaseUpper:
	default:
		return policyruntime.RequestAttributeNormalization{}, configPathError(childPath(path, "case"), "must be lower or upper")
	}

	maxLength := normalize.MaxLength
	if maxLength == 0 {
		maxLength = requestAttributeDefaultMaxLen
	}

	if maxLength < 0 {
		return policyruntime.RequestAttributeNormalization{}, configPathError(childPath(path, "max_length"), "must not be negative")
	}

	return policyruntime.RequestAttributeNormalization{
		Trim:      normalize.Trim,
		Case:      caseMode,
		MaxLength: maxLength,
	}, nil
}

func validateRequestAttributeVisibility(value string, path string) error {
	switch strings.TrimSpace(value) {
	case "", requestAttributeVisibility:
		return nil
	default:
		return configPathError(path, "must be public")
	}
}

func requestAttributeDefinition(id string, description string) policyregistry.AttributeDefinition {
	return policyregistry.AttributeDefinition{
		ID:          id,
		Description: description,
		Stage:       policy.StagePreAuth,
		Operations: []policy.Operation{
			policy.OperationAuthenticate,
			policy.OperationLookupIdentity,
			policy.OperationListAccounts,
		},
		Category: policyregistry.AttributeCategoryEnvironment,
		Type:     policyregistry.AttributeTypeString,
		Source:   policyregistry.SourceBuiltin,
	}
}

func registerRequestAttributeDefinition(
	registry *policyregistry.AttributeRegistry,
	definition policyregistry.AttributeDefinition,
) error {
	if err := registry.Register(definition); err != nil {
		return configPathError("auth.policy", err.Error())
	}

	return nil
}

func requestSourceNameUnsafe(value string) bool {
	_, unsafe := unsafeRequestSourceNames[strings.ToLower(strings.TrimSpace(value))]

	return unsafe
}
