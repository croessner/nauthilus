// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package dcr

import (
	"context"
	"log/slog"
)

const (
	// AuditOutcomeFailed identifies a failed security operation.
	AuditOutcomeFailed = "failed"
	// AuditOutcomeRevoked identifies a security operation stopped by revocation.
	AuditOutcomeRevoked = "revoked"
	// AuditOutcomeSuccess identifies a successful security operation.
	AuditOutcomeSuccess = "success"
	// AuditOperationCleanup identifies bounded registry cleanup.
	AuditOperationCleanup = "cleanup"
	// AuditOperationExpiry identifies lifecycle expiry.
	AuditOperationExpiry = "expiry"
	// AuditOperationUserRevocation identifies user-wide token revocation.
	AuditOperationUserRevocation = "user_revocation"
	// AuditReasonStorageFailure identifies a storage-layer audit failure reason.
	AuditReasonStorageFailure = "storage_failure"
)

// AuditEvent contains bounded security-relevant dynamic-client state.
type AuditEvent struct {
	Operation string
	Outcome   string
	Reason    string
	ClientID  string
}

// Auditor records structured dynamic-client security events.
type Auditor interface {
	Record(ctx context.Context, event AuditEvent)
}

type slogAuditor struct {
	logger *slog.Logger
}

// NewSlogAuditor creates an auditor that never emits source addresses or redirect metadata.
func NewSlogAuditor(logger *slog.Logger) Auditor {
	return &slogAuditor{logger: logger}
}

// Record writes one bounded structured audit event.
func (a *slogAuditor) Record(ctx context.Context, event AuditEvent) {
	if a == nil || a.logger == nil {
		return
	}

	a.logger.InfoContext(
		ctx,
		"OIDC dynamic client security event",
		"event", "oidc_dynamic_client_security",
		"operation", event.Operation,
		"outcome", event.Outcome,
		"reason", event.Reason,
		"origin", "dynamic",
		"profile", ProfileMailClientV1,
		"profile_version", 1,
		"client_id", event.ClientID,
	)
}

type discardAuditor struct{}

// Record intentionally discards events when no application logger is available.
func (discardAuditor) Record(context.Context, AuditEvent) {}
