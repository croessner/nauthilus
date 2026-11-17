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

package supporthistory

import (
	"context"
	"errors"
	"time"
)

// Operation names used in audit records and cursor digests.
const (
	operationAttemptSearch = "attempt_search"
	operationAttemptDetail = "attempt_detail"
	operationBanSearch     = "ban_search"
)

// Options configures a Service. Attempts is required; Bans may be nil when the deployment records no ban evidence.
type Options struct {
	Attempts AttemptStore
	Bans     BanStore
	Identity IdentityResolver
	Audit    AuditRecorder
	Prefixes PrefixSource
	Now      func() time.Time
	Timeout  time.Duration
}

// Service is the transport-independent history application service. A nil *Service answers every call with
// HISTORY_NOT_CONFIGURED, so transports can register their routes unconditionally.
type Service struct {
	attempts AttemptStore
	bans     BanStore
	identity IdentityResolver
	audit    AuditRecorder
	prefixes PrefixSource
	gate     *gate
	now      func() time.Time
	timeout  time.Duration
}

// NewService builds the process-owned service.
func NewService(options Options) (*Service, error) {
	if options.Attempts == nil {
		return nil, errors.New("support history requires an attempt store")
	}

	service := &Service{attempts: options.Attempts, bans: options.Bans, identity: options.Identity,
		audit: options.Audit, prefixes: options.Prefixes, now: options.Now, timeout: options.Timeout,
		gate: newGate(maxConcurrentOperations, maxConcurrentPerCaller)}

	if service.now == nil {
		service.now = time.Now
	}

	if service.timeout <= 0 {
		service.timeout = 15 * time.Second
	}

	return service, nil
}

// errorIs is errors.Is for a possibly nil error.
func errorIs(err, target error) bool {
	return err != nil && errors.Is(err, target)
}

// operationCall tracks one authorized operation for its audit record.
type operationCall struct {
	started time.Time
	service *Service
	caller  Caller
	entry   AuditEntry
	release func()
	cancel  context.CancelFunc
}

// begin authorizes first, then validates the request, takes a gate slot, applies the time budget, and runs the
// reader self-check; nothing touches data before authorization. Denied, invalid, and rejected calls are audited too.
func (s *Service) begin(ctx context.Context, caller Caller, operation string, need permission, subject []string, reference string, validate func() *Error) (context.Context, *operationCall, *Error) {
	if s == nil {
		if !caller.has(need) {
			return ctx, nil, newError(CodeForbidden, nil)
		}

		return ctx, nil, newError(CodeNotConfigured, nil)
	}

	call := &operationCall{started: s.now(), service: s, caller: caller, entry: AuditEntry{
		Operation: operation, CallerIdentity: caller.Identity(), CallerMethod: string(caller.Method()),
		Projection: string(caller.projection()), SubjectDigest: subjectDigest(subject...), AuditReference: boundedReference(reference),
	}}

	if !caller.has(need) {
		call.finish(ctx, 0, newError(CodeForbidden, nil))

		return ctx, nil, newError(CodeForbidden, nil)
	}

	if err := validate(); err != nil {
		call.finish(ctx, 0, err)

		return ctx, nil, err
	}

	release, gateErr := s.gate.acquire(ctx, caller.Identity())
	if gateErr != nil {
		call.finish(ctx, 0, gateErr)

		return ctx, nil, gateErr
	}

	call.release = release
	ctx, call.cancel = context.WithTimeout(ctx, s.timeout)

	if err := s.attempts.SelfCheck(ctx); err != nil {
		mapped := mapStoreError(ctx, err)
		call.finish(ctx, 0, mapped)

		return ctx, nil, mapped
	}

	return ctx, call, nil
}

// finish releases the gate and writes the audit record exactly once.
func (c *operationCall) finish(ctx context.Context, results int, err *Error) {
	if c == nil {
		return
	}

	if c.cancel != nil {
		c.cancel()
	}

	if c.release != nil {
		c.release()
	}

	c.entry.At, c.entry.Duration, c.entry.Results = c.started, c.service.now().Sub(c.started), results
	c.entry.Allowed, c.entry.ResultCode = true, "OK"

	if err != nil {
		c.entry.Allowed = err.Code != CodeForbidden
		c.entry.ResultCode = string(err.Code)
	}

	if c.service.audit != nil {
		c.service.audit.RecordHistoryAudit(context.WithoutCancel(ctx), c.entry)
	}
}

// boundedReference keeps an unvalidated audit reference out of the log unless it matches the bounded format.
func boundedReference(reference string) string {
	if validateAuditReference(reference) != nil {
		return ""
	}

	return reference
}

// mapStoreError maps store failures to stable codes; the cause stays internal.
func mapStoreError(ctx context.Context, err error) *Error {
	var serviceErr *Error

	switch {
	case errors.As(err, &serviceErr):
		return serviceErr
	case errors.Is(err, ErrBudgetExceeded):
		return newError(CodeQueryTooBroad, err)
	case errors.Is(err, ErrReaderUnsafe):
		return newError(CodeReaderUnsafe, err)
	case errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil:
		return newError(CodeTimeout, err)
	default:
		return newError(CodeSourceUnavailable, err)
	}
}
