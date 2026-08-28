// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Package policygrpc adapts the public Policy protobuf contract to DecisionService.
package policygrpc

import (
	"context"
	"errors"
	"fmt"
	"math"

	policyv1 "github.com/croessner/nauthilus/v3/api/policy/v1"
	"github.com/croessner/nauthilus/v3/server/core"
	"github.com/croessner/nauthilus/v3/server/policy/admission"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	decisionservice "github.com/croessner/nauthilus/v3/server/policy/decision/service"
	"github.com/croessner/nauthilus/v3/server/policy/effectsupervisor"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const policyGRPCTransportKind = "grpc"

var (
	errPolicyGRPCCredentialsRequired = errors.New("policy gRPC credentials required")
	errPolicyGRPCRequestTooLarge     = errors.New("policy gRPC request is too large")
)

type authenticationContextKey struct{}

// AuthenticationPreparer derives opaque caller evidence from server-observed gRPC transport state.
type AuthenticationPreparer func(context.Context) (decision.AuthenticationInput, error)

// Handler adapts one normalized gRPC Policy request to the application authority.
type Handler struct {
	policyv1.UnimplementedPolicyDecisionServiceServer

	service        decisionservice.PreparedService
	authentication AuthenticationPreparer
}

// New constructs the Policy gRPC adapter with its mandatory application authority.
func New(service decisionservice.PreparedService, authentication AuthenticationPreparer) *Handler {
	return &Handler{service: service, authentication: authentication}
}

// ContextWithAuthentication attaches opaque evidence for focused adapter tests.
func ContextWithAuthentication(ctx context.Context, input decision.AuthenticationInput) context.Context {
	return context.WithValue(ctx, authenticationContextKey{}, input)
}

// contextAuthenticationEvidence resolves the focused test seam without transport globals.
func contextAuthenticationEvidence(ctx context.Context) (decision.AuthenticationInput, error) {
	authentication, ok := ctx.Value(authenticationContextKey{}).(decision.AuthenticationInput)
	if !ok {
		return decision.AuthenticationInput{}, errPolicyGRPCCredentialsRequired
	}

	return authentication, nil
}

// Evaluate gates one captured generation before protobuf or credential preparation.
func (h *Handler) Evaluate(ctx context.Context, request *policyv1.DecisionRequest) (*policyv1.DecisionResponse, error) {
	if h == nil || h.service == nil {
		return nil, status.Error(codes.Unavailable, "policy service unavailable")
	}

	response, err := h.service.EvaluatePrepared(
		ctx,
		policyGRPCTransportKind,
		func(captured policyruntime.GenerationConfig) (decision.Invocation, error) {
			return h.prepareInvocation(ctx, request, captured)
		},
	)
	if err != nil {
		return nil, grpcServiceError(err)
	}

	converted, err := responseProto(response)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "policy service unavailable")
	}

	return converted, nil
}

// prepareInvocation derives the bounded request and caller evidence only after route activation passed.
func (h *Handler) prepareInvocation(
	ctx context.Context,
	request *policyv1.DecisionRequest,
	captured policyruntime.GenerationConfig,
) (decision.Invocation, error) {
	if err := requestContextError(ctx); err != nil {
		return decision.Invocation{}, err
	}

	maxRequestBytes := policyGRPCMaxRequestBytes(captured)
	if maxRequestBytes <= 0 {
		return decision.Invocation{}, decisionservice.ErrDecisionGenerationUnavailable
	}

	if request != nil && proto.Size(request) > maxRequestBytes {
		return decision.Invocation{}, errPolicyGRPCRequestTooLarge
	}

	input, err := requestInput(request)
	if err != nil {
		return decision.Invocation{}, decision.ErrInvalidRequest
	}

	if h.authentication == nil {
		return decision.Invocation{}, errPolicyGRPCCredentialsRequired
	}

	authentication, err := h.authentication(ctx)
	if err != nil {
		return decision.Invocation{}, err
	}

	gate := core.PostActionFinalizationGateFromContext(ctx)
	if gate == nil {
		return decision.Invocation{}, decisionservice.ErrDecisionServiceDependencyMissing
	}

	finalization := decision.NewExternalEvaluationFinalization(effectsupervisor.BoundaryGRPCUnaryReturn, gate.Done())

	return decision.Invocation{
		Request: input, Authentication: authentication, Finalization: finalization,
	}, nil
}

// policyGRPCMaxRequestBytes returns the captured generation's exact unary wire limit.
func policyGRPCMaxRequestBytes(captured policyruntime.GenerationConfig) int {
	if captured == nil {
		return 0
	}

	return captured.GetPolicy().API.Limits.MaxRequestBytes
}

// requestContextError maps a deadline already observed before application evaluation.
func requestContextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}

	if errors.Is(ctx.Err(), context.Canceled) {
		return context.Canceled
	}

	return nil
}

// grpcServiceError preserves the closed Policy application-boundary status taxonomy.
func grpcServiceError(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return status.Error(codes.Canceled, "policy evaluation cancelled")
	case errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.DeadlineExceeded, "policy evaluation deadline exceeded")
	case errors.Is(err, decision.ErrInvalidRequest):
		return status.Error(codes.InvalidArgument, "invalid policy decision request")
	case errors.Is(err, decisionservice.ErrDecisionRouteUnavailable):
		return status.Error(codes.Unimplemented, "policy endpoint is disabled")
	case errors.Is(err, errPolicyGRPCRequestTooLarge), status.Code(err) == codes.ResourceExhausted:
		return status.Error(codes.ResourceExhausted, "policy request exceeds the message limit")
	case errors.Is(err, errPolicyGRPCCredentialsRequired), status.Code(err) == codes.Unauthenticated:
		return status.Error(codes.Unauthenticated, "policy credentials required")
	case errors.Is(err, decisionservice.ErrDecisionAuthentication):
		return status.Error(codes.Unauthenticated, "policy credentials rejected")
	case errors.Is(err, decisionservice.ErrDecisionAdmission):
		switch {
		case errors.Is(err, admission.ErrRequestLimitExceeded), errors.Is(err, admission.ErrCapacityLimitExceeded):
			return status.Error(codes.ResourceExhausted, "policy request exceeds admitted limits")
		default:
			return status.Error(codes.PermissionDenied, "policy request is not permitted")
		}
	case errors.Is(err, decisionservice.ErrDecisionGenerationUnavailable), errors.Is(err, decisionservice.ErrDecisionServiceDependencyMissing):
		return status.Error(codes.Unavailable, "policy service unavailable")
	default:
		return status.Error(codes.Unavailable, "policy service unavailable")
	}
}

// requestInput rejects retained protobuf unknown fields before converting the normalized DTO.
func requestInput(request *policyv1.DecisionRequest) (decision.DecisionRequestInput, error) {
	if request == nil {
		return decision.DecisionRequestInput{}, errors.New("request is required")
	}

	if err := rejectUnknownFields(request); err != nil {
		return decision.DecisionRequestInput{}, err
	}

	target, err := targetInput(request.GetTarget())
	if err != nil {
		return decision.DecisionRequestInput{}, err
	}

	subject, err := entityInput(request.GetSubject())
	if err != nil {
		return decision.DecisionRequestInput{}, err
	}

	resource, err := entityInput(request.GetResource())
	if err != nil {
		return decision.DecisionRequestInput{}, err
	}

	environment, err := environmentInput(request.GetEnvironment())
	if err != nil {
		return decision.DecisionRequestInput{}, err
	}

	attributes, err := valueMap(request.GetAttributes())
	if err != nil {
		return decision.DecisionRequestInput{}, err
	}

	return decision.DecisionRequestInput{
		Version:     request.GetVersion(),
		RequestID:   request.GetRequestId(),
		Target:      target,
		Subject:     subject,
		Resource:    resource,
		Environment: environment,
		Attributes:  attributes,
		Options:     decision.EvaluationOptions{IncludeDiagnostics: request.GetOptions().GetIncludeDiagnostics()},
	}, nil
}

// rejectUnknownFields walks every nested protobuf message so unknown fields cannot survive normalization.
func rejectUnknownFields(message proto.Message) error {
	if message == nil {
		return nil
	}

	return rejectUnknownMessage(message.ProtoReflect())
}

// rejectUnknownMessage validates unknown-field absence recursively, including map values and repeated messages.
func rejectUnknownMessage(message protoreflect.Message) error {
	if len(message.GetUnknown()) != 0 {
		return errors.New("protobuf request contains unknown fields")
	}

	var visitErr error

	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		visitErr = rejectUnknownField(field, value)

		return visitErr == nil
	})

	return visitErr
}

// rejectUnknownField descends into all populated nested protobuf message values.
func rejectUnknownField(field protoreflect.FieldDescriptor, value protoreflect.Value) error {
	if field.IsMap() {
		var visitErr error

		value.Map().Range(func(_ protoreflect.MapKey, item protoreflect.Value) bool {
			if field.MapValue().Kind() == protoreflect.MessageKind {
				visitErr = rejectUnknownMessage(item.Message())
			}

			return visitErr == nil
		})

		return visitErr
	}

	if field.IsList() && field.Kind() == protoreflect.MessageKind {
		list := value.List()
		for index := 0; index < list.Len(); index++ {
			if err := rejectUnknownMessage(list.Get(index).Message()); err != nil {
				return err
			}
		}

		return nil
	}

	if field.Kind() == protoreflect.MessageKind {
		return rejectUnknownMessage(value.Message())
	}

	return nil
}

// targetInput converts a required public target into its constructor-owned representation.
func targetInput(value *policyv1.Target) (decision.Target, error) {
	if value == nil {
		return decision.Target{}, errors.New("target is required")
	}

	return decision.NewTarget(value.GetNamespace(), value.GetAction())
}

// entityInput converts an optional public entity into its constructor-owned representation.
func entityInput(value *policyv1.Entity) (decision.Entity, error) {
	if value == nil {
		return decision.NewEntity(decision.EntityInput{})
	}

	attributes, err := valueMap(value.GetAttributes())
	if err != nil {
		return decision.Entity{}, err
	}

	return decision.NewEntity(decision.EntityInput{Type: value.GetType(), ID: value.GetId(), Attributes: attributes})
}

// environmentInput converts an optional public environment into its constructor-owned representation.
func environmentInput(value *policyv1.Environment) (decision.Environment, error) {
	if value == nil {
		return decision.NewEnvironment(decision.EnvironmentInput{})
	}

	attributes, err := valueMap(value.GetAttributes())
	if err != nil {
		return decision.Environment{}, err
	}

	return decision.NewEnvironment(decision.EnvironmentInput{
		Service: value.GetService(), Instance: value.GetInstance(), Protocol: value.GetProtocol(), Attributes: attributes,
	})
}

// valueMap converts every public map member through the strict single-value converter.
func valueMap(values map[string]*policyv1.Value) (map[string]decision.Value, error) {
	if len(values) == 0 {
		return nil, nil
	}

	result := make(map[string]decision.Value, len(values))
	for key, value := range values {
		converted, err := valueInput(value)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}

		result[key] = converted
	}

	return result, nil
}

// valueInput accepts exactly one protobuf-normalized oneof member.
func valueInput(value *policyv1.Value) (decision.Value, error) {
	if value == nil {
		return decision.Value{}, errors.New("value is required")
	}

	if typed, ok := value.GetKind().(*policyv1.Value_Records); ok {
		if typed.Records == nil {
			return decision.Value{}, errors.New("records value is required")
		}

		records, err := recordListInput(typed.Records)
		if err != nil {
			return decision.Value{}, err
		}

		return decision.NewValue(decision.ValueInput{Records: &records})
	}

	return protoLeafValue(value.GetKind())
}

// protoLeafValue centralizes public protobuf leaf conversion for values and record fields.
func protoLeafValue(kind any) (decision.Value, error) {
	if value, handled, err := protoScalarLeafValue(kind); handled {
		return value, err
	}

	return protoCollectionLeafValue(kind)
}

// protoScalarLeafValue converts scalar protobuf members shared by top-level and record values.
func protoScalarLeafValue(kind any) (decision.Value, bool, error) {
	switch typed := kind.(type) {
	case *policyv1.Value_String_:
		value, err := decision.NewValue(decision.ValueInput{String: &typed.String_})

		return value, true, err
	case *policyv1.RecordFieldValue_String_:
		value, err := decision.NewValue(decision.ValueInput{String: &typed.String_})

		return value, true, err
	case *policyv1.Value_Boolean:
		value, err := decision.NewValue(decision.ValueInput{Boolean: &typed.Boolean})

		return value, true, err
	case *policyv1.RecordFieldValue_Boolean:
		value, err := decision.NewValue(decision.ValueInput{Boolean: &typed.Boolean})

		return value, true, err
	case *policyv1.Value_Integer:
		value, err := decision.NewValue(decision.ValueInput{Integer: &typed.Integer})

		return value, true, err
	case *policyv1.RecordFieldValue_Integer:
		value, err := decision.NewValue(decision.ValueInput{Integer: &typed.Integer})

		return value, true, err
	case *policyv1.Value_Double:
		value, err := protoDoubleValue(typed.Double)

		return value, true, err
	case *policyv1.RecordFieldValue_Double:
		value, err := protoDoubleValue(typed.Double)

		return value, true, err
	default:
		return decision.Value{}, false, nil
	}
}

// protoCollectionLeafValue converts bounded leaf collections and timestamps.
func protoCollectionLeafValue(kind any) (decision.Value, error) {
	switch typed := kind.(type) {
	case *policyv1.Value_Strings:
		return protoStringsValue(typed.Strings)
	case *policyv1.RecordFieldValue_Strings:
		return protoStringsValue(typed.Strings)
	case *policyv1.Value_Bytes:
		return decision.NewValue(decision.ValueInput{Bytes: append([]byte(nil), typed.Bytes...)})
	case *policyv1.RecordFieldValue_Bytes:
		return decision.NewValue(decision.ValueInput{Bytes: append([]byte(nil), typed.Bytes...)})
	case *policyv1.Value_Timestamp:
		return timestampValue(typed.Timestamp)
	case *policyv1.RecordFieldValue_Timestamp:
		return timestampValue(typed.Timestamp)
	default:
		return decision.Value{}, errors.New("value kind is required")
	}
}

// protoDoubleValue rejects non-finite protobuf doubles.
func protoDoubleValue(value float64) (decision.Value, error) {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return decision.Value{}, errors.New("double must be finite")
	}

	return decision.NewValue(decision.ValueInput{Double: &value})
}

// protoStringsValue requires a present ordered string-list wrapper.
func protoStringsValue(value *policyv1.StringList) (decision.Value, error) {
	if value == nil {
		return decision.Value{}, errors.New("strings value is required")
	}

	return decision.NewValue(decision.ValueInput{Strings: append([]string(nil), value.GetValues()...)})
}

// recordListInput constructs one ordered internal record collection from repeated messages.
func recordListInput(input *policyv1.RecordList) (decision.RecordList, error) {
	records := make([]decision.Record, 0, len(input.GetRecords()))
	for _, protoRecord := range input.GetRecords() {
		if protoRecord == nil {
			return decision.RecordList{}, errors.New("record is required")
		}

		fields := make([]decision.RecordField, 0, len(protoRecord.GetFields()))
		for _, protoField := range protoRecord.GetFields() {
			if protoField == nil || protoField.GetValue() == nil {
				return decision.RecordList{}, errors.New("record field and value are required")
			}

			leaf, err := protoLeafValue(protoField.GetValue().GetKind())
			if err != nil {
				return decision.RecordList{}, err
			}

			fieldValue, err := decision.NewRecordFieldValueFromValue(leaf)
			if err != nil {
				return decision.RecordList{}, err
			}

			field, err := decision.NewRecordField(protoField.GetName(), fieldValue)
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

// timestampValue validates a public protobuf timestamp before UTC normalization in the model constructor.
func timestampValue(value *timestamppb.Timestamp) (decision.Value, error) {
	if value == nil || value.CheckValid() != nil {
		return decision.Value{}, errors.New("timestamp is invalid")
	}

	instant := value.AsTime().Round(0).UTC()

	return decision.NewValue(decision.ValueInput{Timestamp: &instant})
}

// responseProto projects a completed internal result into the public protobuf response.
func responseProto(response decision.DecisionResponse) (*policyv1.DecisionResponse, error) {
	obligations, err := effectRequestsProto(response.Obligations(), func(id string, parameters map[string]*policyv1.ResponseValue) *policyv1.Obligation {
		return &policyv1.Obligation{Id: id, Parameters: parameters}
	})
	if err != nil {
		return nil, err
	}

	advice, err := effectRequestsProto(response.Advice(), func(id string, parameters map[string]*policyv1.ResponseValue) *policyv1.Advice {
		return &policyv1.Advice{Id: id, Parameters: parameters}
	})
	if err != nil {
		return nil, err
	}

	statusValue := response.Status()
	result := &policyv1.DecisionResponse{
		DecisionId: response.DecisionID().String(),
		Effect:     effectProto(response.Effect()),
		Status: &policyv1.Status{
			Code:      string(statusValue.Code()),
			Message:   statusValue.Message(),
			Retryable: statusValue.Retryable(),
			Details:   validationDetails(statusValue.Details()),
		},
		Obligations: obligations,
		Advice:      advice,
	}

	if diagnostics := response.Diagnostics(); diagnostics != nil {
		entries, err := responseValueMapProto(diagnostics.Entries().Values())
		if err != nil {
			return nil, err
		}

		result.Diagnostics = &policyv1.Diagnostics{Entries: entries}
	}

	return result, nil
}

// effectProto maps the closed internal effect set to the generated protobuf enum.
func effectProto(effect decision.Effect) policyv1.Effect {
	switch effect {
	case decision.EffectPermit:
		return policyv1.Effect_EFFECT_PERMIT
	case decision.EffectDeny:
		return policyv1.Effect_EFFECT_DENY
	case decision.EffectNotApplicable:
		return policyv1.Effect_EFFECT_NOT_APPLICABLE
	case decision.EffectIndeterminate:
		return policyv1.Effect_EFFECT_INDETERMINATE
	default:
		return policyv1.Effect_EFFECT_UNSPECIFIED
	}
}

// validationDetails converts bounded validation details without retaining internal slices.
func validationDetails(details []decision.ValidationDetail) []*policyv1.ValidationDetail {
	result := make([]*policyv1.ValidationDetail, 0, len(details))
	for _, detail := range details {
		result = append(result, &policyv1.ValidationDetail{Field: detail.Field(), Reason: detail.Reason()})
	}

	return result
}

// effectRequestsProto projects return-only effect selections through one typed DTO factory.
func effectRequestsProto[T any](values []decision.EffectRequest, factory func(string, map[string]*policyv1.ResponseValue) *T) ([]*T, error) {
	result := make([]*T, 0, len(values))
	for _, value := range values {
		parameters, err := responseValueMapProto(value.Parameters().Values())
		if err != nil {
			return nil, err
		}

		result = append(result, factory(value.ID(), parameters))
	}

	return result, nil
}

// responseValueMapProto converts record-free response values to their restricted generated DTO.
func responseValueMapProto(values map[string]decision.Value) (map[string]*policyv1.ResponseValue, error) {
	result := make(map[string]*policyv1.ResponseValue, len(values))
	for key, value := range values {
		converted, err := responseValueProto(value)
		if err != nil {
			return nil, err
		}

		result[key] = converted
	}

	return result, nil
}

// responseValueProto maps one non-record internal value to the response-only protobuf oneof.
func responseValueProto(value decision.Value) (*policyv1.ResponseValue, error) {
	switch value.Kind() {
	case decision.ValueKindString:
		member, _ := value.StringValue()

		return &policyv1.ResponseValue{Kind: &policyv1.ResponseValue_String_{String_: member}}, nil
	case decision.ValueKindBoolean:
		member, _ := value.Boolean()

		return &policyv1.ResponseValue{Kind: &policyv1.ResponseValue_Boolean{Boolean: member}}, nil
	case decision.ValueKindInteger:
		member, _ := value.Integer()

		return &policyv1.ResponseValue{Kind: &policyv1.ResponseValue_Integer{Integer: member}}, nil
	case decision.ValueKindDouble:
		member, _ := value.Double()

		return &policyv1.ResponseValue{Kind: &policyv1.ResponseValue_Double{Double: member}}, nil
	case decision.ValueKindStrings:
		member, _ := value.Strings()

		return &policyv1.ResponseValue{Kind: &policyv1.ResponseValue_Strings{Strings: &policyv1.StringList{Values: member}}}, nil
	case decision.ValueKindBytes:
		member, _ := value.Bytes()

		return &policyv1.ResponseValue{Kind: &policyv1.ResponseValue_Bytes{Bytes: member}}, nil
	case decision.ValueKindTimestamp:
		member, _ := value.Timestamp()

		return &policyv1.ResponseValue{Kind: &policyv1.ResponseValue_Timestamp{Timestamp: timestamppb.New(member)}}, nil
	default:
		return nil, errors.New("response value kind is invalid")
	}
}

// valueMapProto converts constructor-validated internal values to the generated oneof DTO.
func valueMapProto(values map[string]decision.Value) (map[string]*policyv1.Value, error) {
	result := make(map[string]*policyv1.Value, len(values))
	for key, value := range values {
		converted, err := valueProto(value)
		if err != nil {
			return nil, err
		}

		result[key] = converted
	}

	return result, nil
}

// valueProto maps one strict internal value to exactly one generated protobuf oneof member.
func valueProto(value decision.Value) (*policyv1.Value, error) {
	switch value.Kind() {
	case decision.ValueKindString:
		member, _ := value.StringValue()

		return &policyv1.Value{Kind: &policyv1.Value_String_{String_: member}}, nil
	case decision.ValueKindBoolean:
		member, _ := value.Boolean()

		return &policyv1.Value{Kind: &policyv1.Value_Boolean{Boolean: member}}, nil
	case decision.ValueKindInteger:
		member, _ := value.Integer()

		return &policyv1.Value{Kind: &policyv1.Value_Integer{Integer: member}}, nil
	case decision.ValueKindDouble:
		member, _ := value.Double()

		return &policyv1.Value{Kind: &policyv1.Value_Double{Double: member}}, nil
	case decision.ValueKindStrings:
		member, _ := value.Strings()

		return &policyv1.Value{Kind: &policyv1.Value_Strings{Strings: &policyv1.StringList{Values: member}}}, nil
	case decision.ValueKindBytes:
		member, _ := value.Bytes()

		return &policyv1.Value{Kind: &policyv1.Value_Bytes{Bytes: member}}, nil
	case decision.ValueKindTimestamp:
		member, _ := value.Timestamp()

		return &policyv1.Value{Kind: &policyv1.Value_Timestamp{Timestamp: timestamppb.New(member)}}, nil
	case decision.ValueKindRecords:
		member, _ := value.Records()

		return &policyv1.Value{Kind: &policyv1.Value_Records{Records: recordListProto(member)}}, nil
	default:
		return nil, errors.New("internal value kind is invalid")
	}
}

// recordListProto preserves logical record and field order through repeated messages.
func recordListProto(input decision.RecordList) *policyv1.RecordList {
	result := &policyv1.RecordList{Records: make([]*policyv1.Record, 0, len(input.Records()))}
	for _, record := range input.Records() {
		converted := &policyv1.Record{Fields: make([]*policyv1.RecordField, 0, len(record.Fields()))}
		for _, field := range record.Fields() {
			converted.Fields = append(converted.Fields, &policyv1.RecordField{
				Name: field.Name(), Value: recordFieldValueProto(field.Value()),
			})
		}

		result.Records = append(result.Records, converted)
	}

	return result
}

// recordFieldValueProto maps the closed non-recursive leaf vocabulary.
func recordFieldValueProto(input decision.RecordFieldValue) *policyv1.RecordFieldValue {
	result := &policyv1.RecordFieldValue{}

	switch input.Kind() {
	case decision.ValueKindString:
		value, _ := input.StringValue()
		result.Kind = &policyv1.RecordFieldValue_String_{String_: value}
	case decision.ValueKindBoolean:
		value, _ := input.Boolean()
		result.Kind = &policyv1.RecordFieldValue_Boolean{Boolean: value}
	case decision.ValueKindInteger:
		value, _ := input.Integer()
		result.Kind = &policyv1.RecordFieldValue_Integer{Integer: value}
	case decision.ValueKindDouble:
		value, _ := input.Double()
		result.Kind = &policyv1.RecordFieldValue_Double{Double: value}
	case decision.ValueKindStrings:
		value, _ := input.Strings()
		result.Kind = &policyv1.RecordFieldValue_Strings{Strings: &policyv1.StringList{Values: value}}
	case decision.ValueKindBytes:
		value, _ := input.Bytes()
		result.Kind = &policyv1.RecordFieldValue_Bytes{Bytes: value}
	case decision.ValueKindTimestamp:
		value, _ := input.Timestamp()
		result.Kind = &policyv1.RecordFieldValue_Timestamp{Timestamp: timestamppb.New(value)}
	}

	return result
}
