// Copyright 2025-2026 Nauthilus authors
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package mfastate composes typed MFA state owned by one canonical browser session.
package mfastate

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/croessner/nauthilus/v3/server/sessionstate"
)

// Aggregate exposes typed enrollment, step-up, and TOTP/recovery operations without browser keys.
type Aggregate struct {
	stores  *sessionstate.RedisStores
	session sessionstate.Handle
	ttl     time.Duration
}

// NewAggregate binds MFA state to one canonical browser session.
func NewAggregate(stores *sessionstate.RedisStores, session sessionstate.Handle, ttl time.Duration) *Aggregate {
	return &Aggregate{stores: stores, session: session, ttl: ttl}
}

// SaveEnrollment creates or revision-checks one enrollment state machine.
func (a *Aggregate) SaveEnrollment(ctx context.Context, record *sessionstate.EnrollmentRecord) error {
	return saveRecord(ctx, a, record, "enrollment", locateEnrollment, setEnrollmentRevision, a.stores.CommitEnrollment)
}

// BeginEnrollment creates one non-replaceable ordered enrollment chain.
func (a *Aggregate) BeginEnrollment(ctx context.Context, record *sessionstate.EnrollmentRecord) error {
	if err := validateNewEnrollment(record); err != nil {
		return err
	}

	return a.SaveEnrollment(ctx, record)
}

// CompleteEnrollmentMethod advances exactly the next required method by CAS.
func (a *Aggregate) CompleteEnrollmentMethod(
	ctx context.Context,
	handle sessionstate.Handle,
	method string,
) (sessionstate.Versioned[sessionstate.EnrollmentRecord], error) {
	loaded, err := a.LoadEnrollment(ctx, handle)
	if err != nil {
		return sessionstate.Versioned[sessionstate.EnrollmentRecord]{}, err
	}

	method = strings.TrimSpace(method)

	next, ok := nextEnrollmentMethod(loaded.Value)
	if !ok || method == "" || method != next {
		return sessionstate.Versioned[sessionstate.EnrollmentRecord]{}, sessionstate.ErrBindingMismatch
	}

	record := loaded.Value

	record.CompletedMethods = append(record.CompletedMethods, method)
	if len(record.CompletedMethods) == len(record.RequiredMethods) {
		record.Completed = true
		record.CurrentStep = "complete"
	} else {
		record.CurrentStep = record.RequiredMethods[len(record.CompletedMethods)]
	}

	record.Revision = loaded.Revision
	if err = a.SaveEnrollment(ctx, &record); err != nil {
		return sessionstate.Versioned[sessionstate.EnrollmentRecord]{}, err
	}

	return sessionstate.Versioned[sessionstate.EnrollmentRecord]{Value: record, Revision: record.Revision}, nil
}

// LoadEnrollment loads one enrollment bound to this browser session.
func (a *Aggregate) LoadEnrollment(
	ctx context.Context,
	handle sessionstate.Handle,
) (sessionstate.Versioned[sessionstate.EnrollmentRecord], error) {
	return loadRecord(ctx, a, handle, a.stores.Enrollment)
}

// DeleteEnrollment revision-checks and removes one enrollment and its anchor index.
func (a *Aggregate) DeleteEnrollment(ctx context.Context, handle sessionstate.Handle) error {
	return deleteRecord(ctx, a, handle, a.stores.Enrollment, a.stores.DeleteEnrollment)
}

// SaveStepUp creates or revision-checks one dynamic-assurance operation.
func (a *Aggregate) SaveStepUp(ctx context.Context, record *sessionstate.StepUpRecord) error {
	return saveRecord(ctx, a, record, "step-up", locateStepUp, setStepUpRevision, a.stores.CommitStepUp)
}

// BeginStepUp creates one non-replaceable flow-bound or self-service assurance operation.
func (a *Aggregate) BeginStepUp(ctx context.Context, record *sessionstate.StepUpRecord) error {
	if err := validateNewStepUp(record); err != nil {
		return err
	}

	return a.SaveStepUp(ctx, record)
}

// LoadStepUp loads one dynamic-assurance operation bound to this browser session.
func (a *Aggregate) LoadStepUp(
	ctx context.Context,
	handle sessionstate.Handle,
) (sessionstate.Versioned[sessionstate.StepUpRecord], error) {
	return loadRecord(ctx, a, handle, a.stores.StepUp)
}

// DeleteStepUp revision-checks and removes one step-up operation and its anchor index.
func (a *Aggregate) DeleteStepUp(ctx context.Context, handle sessionstate.Handle) error {
	return deleteRecord(ctx, a, handle, a.stores.StepUp, a.stores.DeleteStepUp)
}

// SaveTOTPRecovery creates or revision-checks one TOTP or recovery operation.
func (a *Aggregate) SaveTOTPRecovery(ctx context.Context, record *sessionstate.TOTPRecoveryRecord) error {
	return saveRecord(ctx, a, record, "TOTP/recovery operation", locateTOTPRecovery, setTOTPRecoveryRevision,
		a.stores.CommitTOTPRecovery)
}

// LoadTOTPRecovery loads one TOTP or recovery operation bound to this browser session.
func (a *Aggregate) LoadTOTPRecovery(
	ctx context.Context,
	handle sessionstate.Handle,
) (sessionstate.Versioned[sessionstate.TOTPRecoveryRecord], error) {
	return loadRecord(ctx, a, handle, a.stores.TOTPRecovery)
}

// DeleteTOTPRecovery revision-checks and removes one TOTP/recovery operation and its anchor index.
func (a *Aggregate) DeleteTOTPRecovery(ctx context.Context, handle sessionstate.Handle) error {
	return deleteRecord(ctx, a, handle, a.stores.TOTPRecovery, a.stores.DeleteTOTPRecovery)
}

func (a *Aggregate) validRecord(session sessionstate.Handle, handle sessionstate.Handle) error {
	if err := a.validHandle(handle); err != nil {
		return err
	}

	if session != a.session {
		return sessionstate.ErrBindingMismatch
	}

	return nil
}

func (a *Aggregate) validHandle(handle sessionstate.Handle) error {
	if a == nil || a.stores == nil || a.session == "" || handle == "" {
		return fmt.Errorf("MFA state aggregate: unavailable or incomplete")
	}

	return nil
}

func (a *Aggregate) reference(handle sessionstate.Handle) sessionstate.Reference {
	return sessionstate.Reference{Session: a.session, Record: handle}
}

func locateEnrollment(record *sessionstate.EnrollmentRecord) (sessionstate.Handle, sessionstate.Handle, sessionstate.Revision) {
	return record.Session, record.Handle, record.Revision
}

func setEnrollmentRevision(record *sessionstate.EnrollmentRecord, revision sessionstate.Revision) {
	record.Revision = revision
}

func validateNewEnrollment(record *sessionstate.EnrollmentRecord) error {
	if err := validateNewEnrollmentBinding(record); err != nil {
		return err
	}

	if err := validateEnrollmentMethods(record.RequiredMethods); err != nil {
		return err
	}

	if record.CurrentStep != record.RequiredMethods[0] {
		return sessionstate.ErrBindingMismatch
	}

	return nil
}

func validateNewEnrollmentBinding(record *sessionstate.EnrollmentRecord) error {
	if record == nil || record.Revision != 0 || record.Flow == "" ||
		strings.TrimSpace(record.AccountReference) == "" || strings.TrimSpace(record.IdentityReference) == "" ||
		len(record.RequiredMethods) == 0 || len(record.CompletedMethods) != 0 || record.Completed ||
		len(record.Continuation) > 512 {
		return sessionstate.ErrBindingMismatch
	}

	return nil
}

func validateEnrollmentMethods(methods []string) error {
	if len(methods) > 8 {
		return sessionstate.ErrBindingMismatch
	}

	seen := make(map[string]struct{}, len(methods))
	for _, method := range methods {
		method = strings.TrimSpace(method)
		if method == "" || len(method) > 32 {
			return sessionstate.ErrBindingMismatch
		}

		if _, exists := seen[method]; exists {
			return sessionstate.ErrBindingMismatch
		}

		seen[method] = struct{}{}
	}

	return nil
}

func nextEnrollmentMethod(record sessionstate.EnrollmentRecord) (string, bool) {
	if record.Completed || len(record.RequiredMethods) == 0 || len(record.CompletedMethods) >= len(record.RequiredMethods) {
		return "", false
	}

	for index, completed := range record.CompletedMethods {
		if completed != record.RequiredMethods[index] {
			return "", false
		}
	}

	return record.RequiredMethods[len(record.CompletedMethods)], true
}

//nolint:gocyclo // Validation covers the complete bounded persisted step-up contract.
func validateNewStepUp(record *sessionstate.StepUpRecord) error {
	if record == nil {
		return sessionstate.ErrBindingMismatch
	}

	credentialID := strings.TrimSpace(record.SelfServiceCredentialID)

	deviceName := strings.TrimSpace(record.SelfServiceDeviceName)
	if record.Revision != 0 || record.RequestedLevel <= 0 || record.RequestedLevel > 32 ||
		strings.TrimSpace(record.Scope) == "" || len(record.Scope) > 256 ||
		(record.Flow == "") == (strings.TrimSpace(record.SelfServiceOperation) == "") ||
		len(record.SelfServiceOperation) > 64 || len(credentialID) > 2048 || len(deviceName) > 256 ||
		(credentialID == "") != (deviceName == "") ||
		record.Flow != "" && (credentialID != "" || deviceName != "") ||
		strings.TrimSpace(record.ProofMethod) != "" ||
		!record.CompletedAt.IsZero() || !record.FreshUntil.IsZero() || record.Completed {
		return sessionstate.ErrBindingMismatch
	}

	if err := validatePendingStepUpIdentity(record); err != nil {
		return err
	}

	return validateEnrollmentMethods(record.SupportedMethods)
}

//nolint:gocyclo // Pending identity validation is deliberately exhaustive and fail-closed.
func validatePendingStepUpIdentity(record *sessionstate.StepUpRecord) error {
	identity := record.PendingIdentity
	affinity := record.PendingBackendAffinity
	outcome := strings.TrimSpace(record.AuthOutcome)
	reference := strings.TrimSpace(record.PendingIdentityReference)
	account := strings.TrimSpace(identity.Account)
	subject := strings.TrimSpace(identity.Subject)
	protocol := strings.TrimSpace(identity.Protocol)
	hasIdentity := reference != "" || account != "" || subject != "" ||
		strings.TrimSpace(identity.DisplayName) != "" || protocol != ""
	hasAffinity := strings.TrimSpace(affinity.Type) != "" || strings.TrimSpace(affinity.Name) != "" ||
		strings.TrimSpace(affinity.Protocol) != "" || strings.TrimSpace(affinity.Authority) != "" ||
		strings.TrimSpace(affinity.OpaqueToken) != ""

	if outcome == "" {
		if hasIdentity || hasAffinity {
			return sessionstate.ErrBindingMismatch
		}

		return nil
	}

	if outcome != "fail_latched" || record.Flow == "" || strings.TrimSpace(record.SelfServiceOperation) != "" ||
		reference == "" || account == "" || subject != reference || protocol == "" ||
		len(reference) > 512 || len(account) > 512 || len(subject) > 512 ||
		len(identity.DisplayName) > 512 || len(protocol) > 64 {
		return sessionstate.ErrBindingMismatch
	}

	if hasAffinity && (strings.TrimSpace(affinity.Type) == "" || strings.TrimSpace(affinity.Name) == "" ||
		strings.TrimSpace(affinity.Protocol) == "" || strings.TrimSpace(affinity.Authority) == "" ||
		strings.TrimSpace(affinity.OpaqueToken) == "" || len(affinity.Type) > 64 || len(affinity.Name) > 256 ||
		len(affinity.Protocol) > 64 || len(affinity.Authority) > 512 || len(affinity.OpaqueToken) > 2048) {
		return sessionstate.ErrBindingMismatch
	}

	return nil
}

func locateStepUp(record *sessionstate.StepUpRecord) (sessionstate.Handle, sessionstate.Handle, sessionstate.Revision) {
	return record.Session, record.Handle, record.Revision
}

func setStepUpRevision(record *sessionstate.StepUpRecord, revision sessionstate.Revision) {
	record.Revision = revision
}

func locateTOTPRecovery(record *sessionstate.TOTPRecoveryRecord) (sessionstate.Handle, sessionstate.Handle, sessionstate.Revision) {
	return record.Session, record.Handle, record.Revision
}

func setTOTPRecoveryRevision(record *sessionstate.TOTPRecoveryRecord, revision sessionstate.Revision) {
	record.Revision = revision
}

func saveRecord[T any](
	ctx context.Context,
	aggregate *Aggregate,
	record *T,
	kind string,
	locate func(*T) (sessionstate.Handle, sessionstate.Handle, sessionstate.Revision),
	setRevision func(*T, sessionstate.Revision),
	commit func(context.Context, sessionstate.CommitRequest[T]) (sessionstate.Revision, error),
) error {
	if record == nil {
		return fmt.Errorf("MFA state aggregate: missing %s", kind)
	}

	session, handle, revision := locate(record)
	if err := aggregate.validRecord(session, handle); err != nil {
		return err
	}

	nextRevision, err := commit(ctx, sessionstate.CommitRequest[T]{
		Reference: aggregate.reference(handle), ExpectedRevision: revision, Value: *record, TTL: aggregate.ttl,
	})
	setRevision(record, nextRevision)

	return err
}

func loadRecord[T any](
	ctx context.Context,
	aggregate *Aggregate,
	handle sessionstate.Handle,
	repository *sessionstate.RedisRepository[T],
) (sessionstate.Versioned[T], error) {
	if err := aggregate.validHandle(handle); err != nil {
		return sessionstate.Versioned[T]{}, err
	}

	return repository.Load(ctx, aggregate.reference(handle))
}

func deleteRecord[T any](
	ctx context.Context,
	aggregate *Aggregate,
	handle sessionstate.Handle,
	repository *sessionstate.RedisRepository[T],
	remove func(context.Context, sessionstate.DeleteRequest) error,
) error {
	loaded, err := loadRecord(ctx, aggregate, handle, repository)
	if err != nil {
		return err
	}

	return remove(ctx, sessionstate.DeleteRequest{
		Reference: aggregate.reference(handle), ExpectedRevision: loaded.Revision,
	})
}
