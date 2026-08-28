// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Package policyhttp adapts the Policy management HTTP contract to DecisionService.
package policyhttp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	management "github.com/croessner/nauthilus/v3/server/openapi/generated/management"
	policy "github.com/croessner/nauthilus/v3/server/policy"
	"github.com/croessner/nauthilus/v3/server/policy/admission"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	decisionservice "github.com/croessner/nauthilus/v3/server/policy/decision/service"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	"github.com/croessner/nauthilus/v3/server/policy/transportsecurity"
	"github.com/croessner/nauthilus/v3/server/util"
	"github.com/gin-gonic/gin"
)

const (
	pathDecisions           = "/policy/decisions"
	noStore                 = "no-store"
	policyHTTPTransportKind = "http"
	policyValueString       = "string"
	policyValueBoolean      = "boolean"
	policyValueInteger      = "integer"
	policyValueDouble       = "double"
	policyValueStrings      = "strings"
	policyValueBytes        = "bytes"
	policyValueTimestamp    = "timestamp"
	policyValueRecords      = "records"
)

var (
	errPolicyHTTPCredentialsRequired  = errors.New("policy HTTP credentials required")
	errPolicyHTTPUnsupportedMediaType = errors.New("policy HTTP media type is unsupported")
)

// TransportEvidence resolves protected transport from server-observed HTTP evidence.
// It is intentionally separate from credential extraction and DecisionService admission.
type TransportEvidence interface {
	Protected(*gin.Context) bool
}

// DirectTLSTransportEvidence accepts only verified direct TLS by default.
// Deployments terminating TLS at a proxy must inject their shared trusted-proxy resolver.
type DirectTLSTransportEvidence struct{}

// Protected reports whether the request arrived through direct verified TLS.
func (DirectTLSTransportEvidence) Protected(ctx *gin.Context) bool {
	return ctx != nil && ctx.Request != nil && ctx.Request.TLS != nil
}

// TrustedProxyTransportEvidence applies the shared Policy transport predicate to direct and proxy-terminated HTTP.
type TrustedProxyTransportEvidence struct {
	trusted []netip.Prefix
}

// NewTrustedProxyTransportEvidence compiles trusted immediate-peer CIDRs for HTTP transport classification.
func NewTrustedProxyTransportEvidence(entries []string) TrustedProxyTransportEvidence {
	trusted := make([]netip.Prefix, 0, len(entries))
	for _, entry := range entries {
		prefix, err := netip.ParsePrefix(entry)
		if err == nil {
			trusted = append(trusted, prefix.Masked())

			continue
		}

		address, addressErr := netip.ParseAddr(entry)
		if addressErr == nil {
			trusted = append(trusted, netip.PrefixFrom(address.Unmap(), address.BitLen()))
		}
	}

	return TrustedProxyTransportEvidence{trusted: trusted}
}

// Protected preserves the shared direct-TLS or trusted-immediate-proxy HTTPS predicate.
func (e TrustedProxyTransportEvidence) Protected(ctx *gin.Context) bool {
	if ctx == nil || ctx.Request == nil {
		return false
	}

	return transportsecurity.NewHTTP(ctx.Request.TLS, e.peerTrusted(ctx.Request.RemoteAddr), ctx.Request.Header.Values("X-Forwarded-Proto"), "").Protected()
}

// peerTrusted checks only the raw immediate peer, never Gin's forwarded client address.
func (e TrustedProxyTransportEvidence) peerTrusted(remoteAddress string) bool {
	host, _, err := net.SplitHostPort(remoteAddress)
	if err != nil {
		host = remoteAddress
	}

	address, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}

	address = address.Unmap()
	for _, prefix := range e.trusted {
		if prefix.Contains(address) {
			return true
		}
	}

	return false
}

// Handler adapts strict HTTP requests to the admission-enforcing DecisionService.
type Handler struct {
	service   decisionservice.PreparedService
	transport TransportEvidence
}

// New constructs the Policy HTTP adapter. A nil service remains fail-closed as 503.
func New(service decisionservice.PreparedService, transport TransportEvidence) *Handler {
	return &Handler{service: service, transport: transport}
}

// Register mounts only the unary Policy endpoint and its unconditional no-store response policy.
func (h *Handler) Register(group *gin.RouterGroup) {
	if group == nil {
		return
	}

	group.POST(pathDecisions, noStoreMiddleware(), h.evaluate)
}

// noStoreMiddleware ensures every terminal Policy route response is never cacheable.
func noStoreMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.Header("Cache-Control", noStore)
		ctx.Next()
	}
}

// evaluate captures and gates one generation before transport-owned request preparation.
func (h *Handler) evaluate(ctx *gin.Context) {
	if h == nil || h.service == nil {
		h.writeError(ctx, http.StatusServiceUnavailable, "service_unavailable", "policy service unavailable")

		return
	}

	finalization := decision.NewEvaluationFinalization(effectsupervisor.BoundaryHTTPCommit)

	response, err := h.service.EvaluatePrepared(
		ctx.Request.Context(),
		policyHTTPTransportKind,
		func(captured config.File) (decision.Invocation, error) {
			return h.prepareInvocation(ctx, captured, finalization)
		},
	)
	if err != nil {
		h.writeServiceError(ctx, err)

		return
	}

	dto, err := responseDTO(response)
	if err != nil {
		h.writeError(ctx, http.StatusInternalServerError, "response_projection_failed", "policy response projection failed")

		return
	}

	ctx.JSON(http.StatusOK, dto)
	ctx.Writer.WriteHeaderNow()
	finalization.Complete()
}

// prepareInvocation derives the bounded payload and credential evidence only after route activation passed.
func (h *Handler) prepareInvocation(
	ctx *gin.Context,
	captured config.File,
	finalization decision.EvaluationFinalization,
) (decision.Invocation, error) {
	if !isJSONContentType(ctx.GetHeader("Content-Type")) {
		return decision.Invocation{}, errPolicyHTTPUnsupportedMediaType
	}

	maxRequestBytes := policyHTTPMaxRequestBytes(captured)
	if maxRequestBytes <= 0 {
		return decision.Invocation{}, decisionservice.ErrDecisionGenerationUnavailable
	}

	body, err := util.ReadBoundedRequestBody(ctx.Request.Body, maxRequestBytes)
	if err != nil {
		return decision.Invocation{}, err
	}

	request, err := decodeRequest(body)
	if err != nil {
		return decision.Invocation{}, decision.ErrInvalidRequest
	}

	authentication, err := h.authentication(ctx, captured)
	if err != nil {
		return decision.Invocation{}, fmt.Errorf("%w: %v", errPolicyHTTPCredentialsRequired, err)
	}

	return decision.Invocation{
		Request: request, Authentication: authentication, Finalization: finalization,
	}, nil
}

// policyHTTPMaxRequestBytes returns the captured generation's exact unary wire limit.
func policyHTTPMaxRequestBytes(captured config.File) int64 {
	if captured == nil {
		return 0
	}

	return int64(captured.GetPolicy().API.Limits.MaxRequestBytes)
}

// isJSONContentType accepts only the OpenAPI-declared application/json media type.
func isJSONContentType(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	return err == nil && mediaType == "application/json"
}

// authentication extracts opaque HTTP presentation without authenticating or admitting it.
//
//nolint:wsl_v5 // The credential parsing branches form one tightly coupled opaque-evidence adapter.
func (h *Handler) authentication(ctx *gin.Context, captured config.File) (decision.AuthenticationInput, error) {
	header := strings.TrimSpace(ctx.GetHeader("Authorization"))
	scheme, credential, found := strings.Cut(header, " ")
	if !found || strings.TrimSpace(credential) == "" {
		return decision.AuthenticationInput{}, errors.New("missing policy credentials")
	}

	kind := ""
	presentation := []byte(strings.TrimSpace(credential))
	switch strings.ToLower(strings.TrimSpace(scheme)) {
	case "bearer":
		kind = policy.CallerAuthenticationKindBearer
	case "basic":
		kind = policy.CallerAuthenticationKindBasic
		decoded, decodeErr := base64.StdEncoding.DecodeString(strings.TrimSpace(credential))
		if decodeErr != nil || len(decoded) == 0 {
			return decision.AuthenticationInput{}, errors.New("invalid Policy-Basic presentation")
		}

		presentation = decoded
	default:
		return decision.AuthenticationInput{}, errors.New("unsupported policy credential scheme")
	}

	peer, _, _ := net.SplitHostPort(ctx.Request.RemoteAddr)
	if peer == "" {
		peer = ctx.Request.RemoteAddr
	}

	transport := h.transport
	if transport == nil {
		transport = DirectTLSTransportEvidence{}
		if captured != nil && captured.GetServer() != nil {
			transport = NewTrustedProxyTransportEvidence(captured.GetServer().GetTrustedProxies())
		}
	}

	return decision.NewAuthenticationInput(decision.AuthenticationEvidence{
		Kind:          kind,
		Credential:    presentation,
		TransportKind: policyHTTPTransportKind,
		HTTPRoute:     "/api/v1/policy/decisions",
		Peer:          peer,
		Protected:     transport.Protected(ctx),
	})
}

// writeServiceError maps only application-boundary error categories to HTTP statuses.
func (h *Handler) writeServiceError(ctx *gin.Context, err error) {
	switch {
	case errors.Is(err, decisionservice.ErrDecisionRouteUnavailable):
		h.writeError(ctx, http.StatusNotFound, "not_found", "policy endpoint is disabled")
	case errors.Is(err, errPolicyHTTPUnsupportedMediaType):
		h.writeError(ctx, http.StatusUnsupportedMediaType, "unsupported_media_type", "policy endpoint requires application/json")
	case errors.Is(err, util.ErrRequestBodyTooLarge):
		h.writeError(ctx, http.StatusRequestEntityTooLarge, "request_too_large", "policy request exceeds body limit")
	case errors.Is(err, errPolicyHTTPCredentialsRequired):
		h.writeError(ctx, http.StatusUnauthorized, "unauthenticated", "policy credentials required")
	case errors.Is(err, decision.ErrInvalidRequest):
		h.writeError(ctx, http.StatusBadRequest, "invalid_request", "invalid policy decision request")
	case errors.Is(err, decisionservice.ErrDecisionAuthentication):
		h.writeError(ctx, http.StatusUnauthorized, "unauthenticated", "policy credentials rejected")
	case errors.Is(err, decisionservice.ErrDecisionAdmission):
		switch {
		case errors.Is(err, admission.ErrRequestLimitExceeded):
			h.writeError(ctx, http.StatusRequestEntityTooLarge, "request_too_large", "policy request exceeds admitted limits")
		case errors.Is(err, admission.ErrCapacityLimitExceeded):
			h.writeError(ctx, http.StatusTooManyRequests, "rate_limited", "policy client limit exceeded")
		default:
			h.writeError(ctx, http.StatusForbidden, "forbidden", "policy request is not permitted")
		}
	case errors.Is(err, decisionservice.ErrDecisionGenerationUnavailable), errors.Is(err, decisionservice.ErrDecisionServiceDependencyMissing):
		h.writeError(ctx, http.StatusServiceUnavailable, "service_unavailable", "policy service unavailable")
	default:
		h.writeError(ctx, http.StatusServiceUnavailable, "service_unavailable", "policy service unavailable")
	}
}

// writeError writes the closed safe public error envelope.
func (h *Handler) writeError(ctx *gin.Context, status int, code string, message string) {
	ctx.JSON(status, management.PolicyError{Code: code, Message: message})
}

// decodeRequest rejects duplicate JSON names, unknown fields, trailing documents, arrays, and invalid Value unions.
//
//nolint:wsl_v5 // The strict decoder intentionally keeps its ordered raw and generated decoding gates together.
func decodeRequest(body []byte) (decision.DecisionRequestInput, error) {
	if len(body) == 0 {
		return decision.DecisionRequestInput{}, errors.New("empty request")
	}

	if err := rejectDuplicateJSONMembers(body); err != nil {
		return decision.DecisionRequestInput{}, err
	}

	if err := validatePolicyValueObjects(body); err != nil {
		return decision.DecisionRequestInput{}, err
	}

	var dto management.PolicyDecisionRequest
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&dto); err != nil {
		return decision.DecisionRequestInput{}, err
	}

	if err := requireJSONEOF(decoder); err != nil {
		return decision.DecisionRequestInput{}, err
	}

	return requestInput(dto)
}

// validatePolicyValueObjects rejects unknown nested members before generated union decoding discards them.
//
//nolint:wsl_v5 // Raw value-map walking keeps nested generated-union validation deterministic.
func validatePolicyValueObjects(body []byte) error {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(body, &root); err != nil {
		return err
	}

	for _, path := range []string{"attributes", "subject.attributes", "resource.attributes", "environment.attributes"} {
		values, found, err := policyValueMapAtPath(root, path)
		if err != nil {
			return err
		}
		if !found {
			continue
		}

		for key, value := range values {
			if err = validatePolicyValueObject(value); err != nil {
				return fmt.Errorf("%s.%s: %w", path, key, err)
			}
		}
	}

	return nil
}

// policyValueMapAtPath resolves one optional Policy value-map from the raw request object.
//
//nolint:wsl_v5 // The segment traversal is deliberately linear to preserve exact path attribution.
func policyValueMapAtPath(root map[string]json.RawMessage, path string) (map[string]json.RawMessage, bool, error) {
	segments := strings.Split(path, ".")
	current := root
	for index, segment := range segments {
		raw, found := current[segment]
		if !found {
			return nil, false, nil
		}

		if index == len(segments)-1 {
			var values map[string]json.RawMessage
			if err := json.Unmarshal(raw, &values); err != nil {
				return nil, false, err
			}

			return values, true, nil
		}

		if err := json.Unmarshal(raw, &current); err != nil {
			return nil, false, err
		}
	}

	return nil, false, nil
}

// validatePolicyValueObject enforces the exact generated PolicyValue member vocabulary.
func validatePolicyValueObject(raw json.RawMessage) error {
	var value map[string]json.RawMessage
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}

	for member := range value {
		switch member {
		case policyValueString, policyValueBoolean, policyValueInteger, policyValueDouble,
			policyValueStrings, policyValueBytes, policyValueTimestamp, policyValueRecords:
		default:
			return fmt.Errorf("unknown PolicyValue member %q", member)
		}
	}

	if records, exists := value[policyValueRecords]; exists {
		return validatePolicyRecords(records)
	}

	return nil
}

// validatePolicyRecords rejects empty records, duplicate field names, and unknown nested members.
func validatePolicyRecords(raw json.RawMessage) error {
	var records []json.RawMessage
	if err := json.Unmarshal(raw, &records); err != nil {
		return err
	}

	for recordIndex, rawRecord := range records {
		var record map[string]json.RawMessage
		if err := json.Unmarshal(rawRecord, &record); err != nil {
			return err
		}

		if len(record) != 1 || record["fields"] == nil {
			return fmt.Errorf("records[%d] must contain only fields", recordIndex)
		}

		var fields []json.RawMessage
		if err := json.Unmarshal(record["fields"], &fields); err != nil {
			return err
		}

		if len(fields) == 0 {
			return fmt.Errorf("records[%d] must not be empty", recordIndex)
		}

		seen := make(map[string]struct{}, len(fields))
		for fieldIndex, rawField := range fields {
			name, value, err := validatePolicyRecordField(rawField)
			if err != nil {
				return fmt.Errorf("records[%d].fields[%d]: %w", recordIndex, fieldIndex, err)
			}

			if _, exists := seen[name]; exists {
				return fmt.Errorf("records[%d].fields[%d]: duplicate field name %q", recordIndex, fieldIndex, name)
			}

			seen[name] = struct{}{}

			if err = validatePolicyRecordFieldValue(value); err != nil {
				return fmt.Errorf("records[%d].fields[%d].value: %w", recordIndex, fieldIndex, err)
			}
		}
	}

	return nil
}

// validatePolicyRecordField returns the exact name and raw leaf value from one closed field object.
func validatePolicyRecordField(raw json.RawMessage) (string, json.RawMessage, error) {
	var field map[string]json.RawMessage
	if err := json.Unmarshal(raw, &field); err != nil {
		return "", nil, err
	}

	if len(field) != 2 || field["name"] == nil || field["value"] == nil {
		return "", nil, errors.New("must contain only name and value")
	}

	var name string
	if err := json.Unmarshal(field["name"], &name); err != nil || name == "" {
		return "", nil, errors.New("name must be a non-empty string")
	}

	return name, field["value"], nil
}

// validatePolicyRecordFieldValue enforces the non-recursive leaf-value vocabulary.
func validatePolicyRecordFieldValue(raw json.RawMessage) error {
	var value map[string]json.RawMessage
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}

	for member := range value {
		switch member {
		case policyValueString, policyValueBoolean, policyValueInteger, policyValueDouble,
			policyValueStrings, policyValueBytes, policyValueTimestamp:
		default:
			return fmt.Errorf("unknown PolicyRecordFieldValue member %q", member)
		}
	}

	return nil
}

// requestInput explicitly converts generated transport DTOs into the closed DecisionService input.
func requestInput(dto management.PolicyDecisionRequest) (decision.DecisionRequestInput, error) {
	target, err := decision.NewTarget(dto.Target.Namespace, dto.Target.Action)
	if err != nil {
		return decision.DecisionRequestInput{}, err
	}

	subject, err := entityInput(dto.Subject)
	if err != nil {
		return decision.DecisionRequestInput{}, err
	}

	resource, err := entityInput(dto.Resource)
	if err != nil {
		return decision.DecisionRequestInput{}, err
	}

	environment, err := environmentInput(dto.Environment)
	if err != nil {
		return decision.DecisionRequestInput{}, err
	}

	attributes, err := valueMap(dto.Attributes)
	if err != nil {
		return decision.DecisionRequestInput{}, err
	}

	requestID := ""
	if dto.RequestId != nil {
		requestID = *dto.RequestId
	}

	options := decision.EvaluationOptions{}
	if dto.Options != nil && dto.Options.IncludeDiagnostics != nil {
		options.IncludeDiagnostics = *dto.Options.IncludeDiagnostics
	}

	return decision.DecisionRequestInput{Version: string(dto.Version), RequestID: requestID, Target: target, Subject: subject, Resource: resource, Environment: environment, Attributes: attributes, Options: options}, nil
}

// entityInput converts an optional public entity to its constructor-owned representation.
func entityInput(dto *management.PolicyEntity) (decision.Entity, error) {
	if dto == nil {
		return decision.NewEntity(decision.EntityInput{})
	}

	attributes, err := valueMap(dto.Attributes)
	if err != nil {
		return decision.Entity{}, err
	}

	return decision.NewEntity(decision.EntityInput{Type: stringValue(dto.Type), ID: stringValue(dto.Id), Attributes: attributes})
}

// environmentInput converts an optional public environment to its constructor-owned representation.
func environmentInput(dto *management.PolicyEnvironment) (decision.Environment, error) {
	if dto == nil {
		return decision.NewEnvironment(decision.EnvironmentInput{})
	}

	attributes, err := valueMap(dto.Attributes)
	if err != nil {
		return decision.Environment{}, err
	}

	return decision.NewEnvironment(decision.EnvironmentInput{Service: stringValue(dto.Service), Instance: stringValue(dto.Instance), Protocol: stringValue(dto.Protocol), Attributes: attributes})
}

// valueMap converts a public map without allowing any caller type to bypass Value validation.
func valueMap(dto *management.PolicyValueMap) (map[string]decision.Value, error) {
	if dto == nil {
		return nil, nil
	}

	result := make(map[string]decision.Value, len(*dto))
	for key, value := range *dto {
		converted, err := valueInput(value)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}

		result[key] = converted
	}

	return result, nil
}

// valueInput enforces exactly one public PolicyValue member after strict DTO decoding.
func valueInput(dto management.PolicyValue) (decision.Value, error) {
	input, err := strictLeafValueInput(dto.String, dto.Boolean, dto.Double, dto.Integer, dto.Strings, dto.Bytes, dto.Timestamp)
	if err != nil {
		return decision.Value{}, err
	}

	if dto.Records != nil {
		records, recordsErr := recordListInput(*dto.Records)
		if recordsErr != nil {
			return decision.Value{}, recordsErr
		}

		input.Records = &records
	}

	return decision.NewValue(input)
}

// strictLeafValueInput centralizes parsing for top-level and record-field leaf values.
func strictLeafValueInput(
	stringValue *string,
	booleanValue *bool,
	doubleValue *float64,
	integerValue *string,
	stringsValue *[]string,
	bytesMember *[]byte,
	timestampValue *time.Time,
) (decision.ValueInput, error) {
	if doubleValue != nil && (math.IsNaN(*doubleValue) || math.IsInf(*doubleValue, 0)) {
		return decision.ValueInput{}, errors.New("non-finite double")
	}

	input := decision.ValueInput{
		String: stringValue, Boolean: booleanValue, Double: doubleValue,
		Strings: sliceValue(stringsValue), Bytes: bytesValue(bytesMember), Timestamp: timestampValue,
	}

	if integerValue != nil {
		if !validPolicyInteger(*integerValue) {
			return decision.ValueInput{}, errors.New("invalid integer")
		}

		value, err := strconv.ParseInt(*integerValue, 10, 64)
		if err != nil {
			return decision.ValueInput{}, err
		}

		input.Integer = &value
	}

	return input, nil
}

// recordListInput constructs one ordered non-recursive internal record collection.
func recordListInput(input []management.PolicyRecord) (decision.RecordList, error) {
	records := make([]decision.Record, 0, len(input))
	for _, dtoRecord := range input {
		fields := make([]decision.RecordField, 0, len(dtoRecord.Fields))
		for _, dtoField := range dtoRecord.Fields {
			leaf, err := strictLeafValueInput(
				dtoField.Value.String, dtoField.Value.Boolean, dtoField.Value.Double, dtoField.Value.Integer,
				dtoField.Value.Strings, dtoField.Value.Bytes, dtoField.Value.Timestamp,
			)
			if err != nil {
				return decision.RecordList{}, err
			}

			value, err := decision.NewValue(leaf)
			if err != nil {
				return decision.RecordList{}, err
			}

			fieldValue, err := decision.NewRecordFieldValueFromValue(value)
			if err != nil {
				return decision.RecordList{}, err
			}

			field, err := decision.NewRecordField(dtoField.Name, fieldValue)
			if err != nil {
				return decision.RecordList{}, err
			}

			fields = append(fields, field)
		}

		record, err := decision.NewRecord(fields)
		if err != nil {
			return decision.RecordList{}, err
		}

		records = append(records, record)
	}

	return decision.NewRecordList(records)
}

// validPolicyInteger matches the canonical signed-integer lexical form declared by PolicyValue.
func validPolicyInteger(value string) bool {
	if value == "0" {
		return true
	}

	digits := value
	digits = strings.TrimPrefix(digits, "-")

	if digits == "0" {
		return true
	}

	if len(digits) == 0 || digits[0] == '0' {
		return false
	}

	for _, digit := range digits {
		if digit < '0' || digit > '9' {
			return false
		}
	}

	return true
}

// stringValue returns the optional generated text field without aliasing it.
func stringValue(value *string) string {
	if value == nil {
		return ""
	}

	return *value
}

// sliceValue detaches an optional generated string list.
func sliceValue(value *[]string) []string {
	if value == nil {
		return nil
	}

	return append([]string(nil), (*value)...)
}

// bytesValue detaches an optional generated byte sequence.
func bytesValue(value *[]byte) []byte {
	if value == nil {
		return nil
	}

	return append([]byte(nil), (*value)...)
}

// responseDTO projects only public DecisionResponse fields into generated management DTOs.
//
//nolint:wsl_v5 // The generated DTO projection retains one ordered public-surface mapping.
func responseDTO(response decision.DecisionResponse) (management.PolicyDecisionResponse, error) {
	status := response.Status()
	result := management.PolicyDecisionResponse{DecisionId: response.DecisionID().String(), Effect: management.PolicyDecisionResponseEffect(response.Effect()), Status: management.PolicyStatus{Code: string(status.Code()), Message: status.Message(), Retryable: status.Retryable()}}
	if details := status.Details(); len(details) > 0 {
		result.Status.Details = policyDetails(details)
	}

	obligations, err := effectRequests(response.Obligations())
	if err != nil {
		return management.PolicyDecisionResponse{}, err
	}

	if len(obligations) > 0 {
		result.Obligations = &obligations
	}

	advice, err := adviceRequests(response.Advice())
	if err != nil {
		return management.PolicyDecisionResponse{}, err
	}

	if len(advice) > 0 {
		result.Advice = &advice
	}

	if diagnostics := response.Diagnostics(); diagnostics != nil {
		entries, err := policyResponseValues(diagnostics.Entries().Values())
		if err != nil {
			return management.PolicyDecisionResponse{}, err
		}

		result.Diagnostics = &management.PolicyDiagnostics{Entries: entries}
	}

	return result, nil
}

// policyDetails converts safe application validation details.
func policyDetails(details []decision.ValidationDetail) *[]management.PolicyValidationDetail {
	result := make([]management.PolicyValidationDetail, 0, len(details))
	for _, detail := range details {
		result = append(result, management.PolicyValidationDetail{Field: detail.Field(), Reason: detail.Reason()})
	}

	return &result
}

// effectRequests converts return-only effect selections.
func effectRequests(requests []decision.EffectRequest) ([]management.PolicyObligation, error) {
	return projectResponseEffectRequests(requests, func(id string, parameters management.PolicyResponseValueMap) management.PolicyObligation {
		return management.PolicyObligation{Id: id, Parameters: parameters}
	})
}

// adviceRequests converts return-only advice selections without reusing obligation DTO types.
func adviceRequests(requests []decision.EffectRequest) ([]management.PolicyAdvice, error) {
	return projectResponseEffectRequests(requests, func(id string, parameters management.PolicyResponseValueMap) management.PolicyAdvice {
		return management.PolicyAdvice{Id: id, Parameters: parameters}
	})
}

// projectResponseEffectRequests shares record-free response parameter conversion across effect DTOs.
func projectResponseEffectRequests[T any](
	requests []decision.EffectRequest,
	factory func(string, management.PolicyResponseValueMap) T,
) ([]T, error) {
	result := make([]T, 0, len(requests))
	for _, request := range requests {
		parameters, err := policyResponseValues(request.Parameters().Values())
		if err != nil {
			return nil, err
		}

		result = append(result, factory(request.ID(), parameters))
	}

	return result, nil
}

// policyResponseValues converts constructor-validated record-free values to restricted response DTOs.
func policyResponseValues(values map[string]decision.Value) (management.PolicyResponseValueMap, error) {
	result := make(management.PolicyResponseValueMap, len(values))
	for key, value := range values {
		leaf, err := decision.NewRecordFieldValueFromValue(value)
		if err != nil {
			return nil, err
		}

		result[key] = policyRecordFieldValue(leaf)
	}

	return result, nil
}

// policyValues converts the strict internal Value vocabulary to generated transport DTOs.
//
//nolint:wsl_v5 // The closed Value-kind switch is one cohesive transport conversion table.
func policyValues(values map[string]decision.Value) map[string]management.PolicyValue {
	result := make(map[string]management.PolicyValue, len(values))
	for key, value := range values {
		converted := management.PolicyValue{}
		switch value.Kind() {
		case decision.ValueKindString:
			text, _ := value.StringValue()
			converted.String = &text
		case decision.ValueKindBoolean:
			flag, _ := value.Boolean()
			converted.Boolean = &flag
		case decision.ValueKindInteger:
			number, _ := value.Integer()
			text := strconv.FormatInt(number, 10)
			converted.Integer = &text
		case decision.ValueKindDouble:
			number, _ := value.Double()
			float := number
			converted.Double = &float
		case decision.ValueKindStrings:
			strings, _ := value.Strings()
			converted.Strings = &strings
		case decision.ValueKindBytes:
			bytes, _ := value.Bytes()
			converted.Bytes = &bytes
		case decision.ValueKindTimestamp:
			timestamp, _ := value.Timestamp()
			converted.Timestamp = &timestamp
		case decision.ValueKindRecords:
			records, _ := value.Records()
			convertedRecords := policyRecords(records)
			converted.Records = &convertedRecords
		}

		result[key] = converted
	}

	return result
}

// policyRecords projects ordered internal records without map-induced field ambiguity.
func policyRecords(input decision.RecordList) []management.PolicyRecord {
	records := make([]management.PolicyRecord, 0, len(input.Records()))
	for _, record := range input.Records() {
		fields := make([]management.PolicyRecordField, 0, len(record.Fields()))
		for _, field := range record.Fields() {
			fields = append(fields, management.PolicyRecordField{
				Name: field.Name(), Value: policyRecordFieldValue(field.Value()),
			})
		}

		records = append(records, management.PolicyRecord{Fields: fields})
	}

	return records
}

// policyRecordFieldValue maps the closed non-recursive internal leaf vocabulary.
func policyRecordFieldValue(input decision.RecordFieldValue) management.PolicyRecordFieldValue {
	result := management.PolicyRecordFieldValue{}

	switch input.Kind() {
	case decision.ValueKindString:
		value, _ := input.StringValue()
		result.String = &value
	case decision.ValueKindBoolean:
		value, _ := input.Boolean()
		result.Boolean = &value
	case decision.ValueKindInteger:
		value, _ := input.Integer()
		text := strconv.FormatInt(value, 10)
		result.Integer = &text
	case decision.ValueKindDouble:
		value, _ := input.Double()
		result.Double = &value
	case decision.ValueKindStrings:
		value, _ := input.Strings()
		result.Strings = &value
	case decision.ValueKindBytes:
		value, _ := input.Bytes()
		result.Bytes = &value
	case decision.ValueKindTimestamp:
		value, _ := input.Timestamp()
		result.Timestamp = &value
	}

	return result
}

// rejectDuplicateJSONMembers walks raw JSON tokens so normal Go decoding cannot apply last-member-wins semantics.
func rejectDuplicateJSONMembers(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := consumeJSONValue(decoder, ""); err != nil {
		return err
	}

	return requireJSONEOF(decoder)
}

// consumeJSONValue recursively rejects duplicate keys in every object while preserving ordinary JSON values.
//
//nolint:gocyclo,wsl_v5 // Recursive JSON grammar validation requires each delimiter branch to remain explicit.
func consumeJSONValue(decoder *json.Decoder, path string) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token == nil {
		return errors.New("JSON null is not permitted")
	}

	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}

	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, tokenErr := decoder.Token()
			if tokenErr != nil {
				return tokenErr
			}

			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key must be text")
			}

			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON member %q", key)
			}

			seen[key] = struct{}{}
			if err := consumeJSONValue(decoder, path+"."+key); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder, path); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return errors.New("unexpected JSON delimiter")
	}
}

// requireJSONEOF rejects a second top-level document after the requested JSON value.
func requireJSONEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); errors.Is(err, io.EOF) {
		return nil
	} else if err != nil {
		return err
	}

	return errors.New("multiple JSON documents")
}
