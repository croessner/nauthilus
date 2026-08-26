// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package service

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/croessner/nauthilus/v3/server/policy/decision"
	policyruntime "github.com/croessner/nauthilus/v3/server/policy/runtime"
)

const internalProfileSeparator = ":"

type capturedConfigContextKey struct{}

type capturedMessageResolverContextKey struct{}

// InternalProfileID is the canonical code-owned internal caller presentation identity.
type InternalProfileID struct {
	value      string
	entryPoint string
	operation  string
}

// InternalSessionInput contains the unauthenticated request resolved inside one captured generation.
type InternalSessionInput struct {
	Request      decision.DecisionRequestInput
	Finalization decision.EvaluationFinalization
	ProfileID    InternalProfileID
}

// NewInternalProfileID constructs a stable entry-point and operation identity.
func NewInternalProfileID(entryPoint string, operation string) (InternalProfileID, error) {
	if !validInternalProfilePart(entryPoint) || !validInternalProfilePart(operation) {
		return InternalProfileID{}, fmt.Errorf("%w: invalid internal profile identity", ErrDecisionServiceDependencyMissing)
	}

	return InternalProfileID{
		value: entryPoint + internalProfileSeparator + operation, entryPoint: entryPoint, operation: operation,
	}, nil
}

// String returns the canonical internal profile identity.
func (id InternalProfileID) String() string {
	return id.value
}

// EntryPoint returns the exact code-owned host entry identity.
func (id InternalProfileID) EntryPoint() string {
	return id.entryPoint
}

// Operation returns the exact authn target action.
func (id InternalProfileID) Operation() string {
	return id.operation
}

// WithInternalSession captures a generation before resolving its code-owned presentation.
func (s *DecisionService) WithInternalSession(
	ctx context.Context,
	input InternalSessionInput,
	use func(DecisionSession) error,
) error {
	ctx = normalizeContext(ctx)

	if use == nil || input.ProfileID.String() == "" {
		return fmt.Errorf("%w: internal session profile and callback are required", ErrDecisionServiceDependencyMissing)
	}

	return s.withGeneration(ctx, func(generation *runtimeGeneration) error {
		presentation, ok := generation.internalPresentations[input.ProfileID.String()]
		if !ok || !validAuthenticationInput(presentation) {
			return fmt.Errorf("%w: internal caller profile is unavailable", ErrDecisionAuthentication)
		}

		generationCtx := policyruntime.ContextWithGeneration(ctx, generation.id)

		session, err := s.openSession(generationCtx, generation, decision.Invocation{
			Request: input.Request, Authentication: presentation, Finalization: input.Finalization,
		}, true)
		if err != nil {
			return err
		}
		defer session.close()

		return use(session)
	})
}

// CapturedConfigFromContext returns the exact configuration captured with a Decision Session.
func CapturedConfigFromContext(ctx context.Context) (policyruntime.GenerationConfig, bool) {
	if ctx == nil {
		return nil, false
	}

	configured, ok := ctx.Value(capturedConfigContextKey{}).(policyruntime.GenerationConfig)

	return configured, ok && configured != nil
}

// CapturedMessageResolverFromContext returns the immutable resolver owned by the captured Decision Session.
func CapturedMessageResolverFromContext(ctx context.Context) (policyruntime.MessageResolver, bool) {
	if ctx == nil {
		return nil, false
	}

	resolver, ok := ctx.Value(capturedMessageResolverContextKey{}).(policyruntime.MessageResolver)

	return resolver, ok && resolver != nil
}

// contextWithCapturedConfig attaches one immutable generation-owned configuration view.
func contextWithCapturedConfig(ctx context.Context, configured policyruntime.GenerationConfig) context.Context {
	return context.WithValue(ctx, capturedConfigContextKey{}, configured)
}

// contextWithCapturedMessageResolver attaches immutable localization authority to host work.
func contextWithCapturedMessageResolver(
	ctx context.Context,
	resolver policyruntime.MessageResolver,
) context.Context {
	return context.WithValue(ctx, capturedMessageResolverContextKey{}, resolver)
}

// validateDecisionRoute enforces captured Policy API activation before authentication.
func validateDecisionRoute(availability policyruntime.PolicyAPIAvailability, transport string) error {
	if transport == "internal" {
		return nil
	}

	switch transport {
	case "http":
		if availability.Enabled && availability.HTTP {
			return nil
		}
	case "grpc":
		if availability.Enabled && availability.GRPC {
			return nil
		}
	}

	return ErrDecisionRouteUnavailable
}

// validInternalProfilePart rejects ambiguous or unbounded code-owned identifiers.
func validInternalProfilePart(value string) bool {
	return value != "" && len(value) <= 255 && strings.TrimSpace(value) == value &&
		!strings.Contains(value, internalProfileSeparator) && utf8.ValidString(value)
}
