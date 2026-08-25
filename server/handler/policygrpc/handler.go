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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type authenticationContextKey struct{}

// Handler adapts one normalized gRPC Policy request to the application authority.
type Handler struct {
	policyv1.UnimplementedPolicyDecisionServiceServer

	service decision.Service
}

// New constructs the Policy gRPC adapter with its mandatory application authority.
func New(service decision.Service) *Handler {
	return &Handler{service: service}
}

// ContextWithAuthentication attaches interceptor-created opaque evidence to one Policy RPC.
func ContextWithAuthentication(ctx context.Context, input decision.AuthenticationInput) context.Context {
	return context.WithValue(ctx, authenticationContextKey{}, input)
}

// Evaluate strictly normalizes one protobuf request before invoking DecisionService.
func (h *Handler) Evaluate(ctx context.Context, request *policyv1.DecisionRequest) (*policyv1.DecisionResponse, error) {
	if h == nil || h.service == nil {
		return nil, status.Error(codes.Unavailable, "policy service unavailable")
	}

	if err := requestContextError(ctx); err != nil {
		return nil, err
	}

	input, err := requestInput(request)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid policy decision request")
	}

	authentication, ok := ctx.Value(authenticationContextKey{}).(decision.AuthenticationInput)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "policy credentials required")
	}

	gate := core.PostActionFinalizationGateFromContext(ctx)
	if gate == nil {
		return nil, status.Error(codes.Unavailable, "policy response finalization is unavailable")
	}

	finalization := decision.NewExternalEvaluationFinalization(effectsupervisor.BoundaryGRPCUnaryReturn, gate.Done())

	response, err := h.service.Evaluate(ctx, decision.Invocation{
		Request:        input,
		Authentication: authentication,
		Finalization:   finalization,
	})
	if err != nil {
		return nil, grpcServiceError(err)
	}

	converted, err := responseProto(response)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "policy service unavailable")
	}

	return converted, nil
}

// requestContextError maps a deadline already observed before application evaluation.
func requestContextError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return status.Error(codes.DeadlineExceeded, "policy evaluation deadline exceeded")
	}

	if errors.Is(ctx.Err(), context.Canceled) {
		return status.Error(codes.Canceled, "policy evaluation cancelled")
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

	switch typed := value.GetKind().(type) {
	case *policyv1.Value_String_:
		return decision.NewValue(decision.ValueInput{String: &typed.String_})
	case *policyv1.Value_Boolean:
		return decision.NewValue(decision.ValueInput{Boolean: &typed.Boolean})
	case *policyv1.Value_Integer:
		return decision.NewValue(decision.ValueInput{Integer: &typed.Integer})
	case *policyv1.Value_Double:
		if math.IsNaN(typed.Double) || math.IsInf(typed.Double, 0) {
			return decision.Value{}, errors.New("double must be finite")
		}

		return decision.NewValue(decision.ValueInput{Double: &typed.Double})
	case *policyv1.Value_Strings:
		if typed.Strings == nil {
			return decision.Value{}, errors.New("strings value is required")
		}

		return decision.NewValue(decision.ValueInput{Strings: append([]string(nil), typed.Strings.GetValues()...)})
	case *policyv1.Value_Bytes:
		return decision.NewValue(decision.ValueInput{Bytes: append([]byte(nil), typed.Bytes...)})
	case *policyv1.Value_Timestamp:
		return timestampValue(typed.Timestamp)
	default:
		return decision.Value{}, errors.New("value kind is required")
	}
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
	obligations, err := effectRequestsProto(response.Obligations(), func(id string, parameters map[string]*policyv1.Value) *policyv1.Obligation {
		return &policyv1.Obligation{Id: id, Parameters: parameters}
	})
	if err != nil {
		return nil, err
	}

	advice, err := effectRequestsProto(response.Advice(), func(id string, parameters map[string]*policyv1.Value) *policyv1.Advice {
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
		entries, err := valueMapProto(diagnostics.Entries().Values())
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
func effectRequestsProto[T any](values []decision.EffectRequest, factory func(string, map[string]*policyv1.Value) *T) ([]*T, error) {
	result := make([]*T, 0, len(values))
	for _, value := range values {
		parameters, err := valueMapProto(value.Parameters().Values())
		if err != nil {
			return nil, err
		}

		result = append(result, factory(value.ID(), parameters))
	}

	return result, nil
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
	default:
		return nil, errors.New("internal value kind is invalid")
	}
}
