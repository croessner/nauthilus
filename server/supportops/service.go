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

package supportops

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/croessner/nauthilus/v4/server/supportaccess"
)

// Shared limits. They live in the service so every transport gets the same bounds.
const (
	// DefaultWindow is the window of a request that names none: the last 15 minutes.
	DefaultWindow = 15 * time.Minute

	// MaxWindow is the largest accepted window.
	MaxWindow = 24 * time.Hour

	// futureSkew tolerates small clock differences for a window end in the future.
	futureSkew = time.Minute

	// maxConcurrentOperations bounds diagnostics calls of the whole process.
	maxConcurrentOperations = 4

	// maxConcurrentPerCaller bounds diagnostics calls of one principal.
	maxConcurrentPerCaller = 2

	// gateWait is how long a call waits for a free slot.
	gateWait = 2 * time.Second

	// defaultTimeout bounds one diagnostics call.
	defaultTimeout = 10 * time.Second

	operationDiagnose = "operations_diagnose"
	auditService      = "operations"
)

// Options configures a Service.
type Options struct {
	Audit      supportaccess.AuditRecorder
	Now        func() time.Time
	Sources    []Source
	Instance   string
	Deployment string
	Timeout    time.Duration
}

// Service is the transport-independent diagnostics service. A nil *Service answers every authorized call with
// OPERATIONS_NOT_CONFIGURED, so transports can register their routes and tools unconditionally.
type Service struct {
	audit      supportaccess.AuditRecorder
	now        func() time.Time
	gate       *supportaccess.Gate
	sources    map[string]Source
	instance   string
	deployment string
	timeout    time.Duration
}

// NewService builds the process-owned service.
func NewService(options Options) (*Service, error) {
	if len(options.Sources) == 0 {
		return nil, errors.New("operations diagnostics require at least one source")
	}

	service := &Service{audit: options.Audit, now: options.Now, instance: options.Instance,
		deployment: options.Deployment, timeout: options.Timeout, sources: make(map[string]Source, len(options.Sources)),
		gate: supportaccess.NewGate(maxConcurrentOperations, maxConcurrentPerCaller, gateWait)}

	for _, source := range options.Sources {
		if source == nil || !slices.Contains(SourceNames, source.Name()) {
			return nil, errors.New("operations diagnostics source has an unknown name")
		}

		service.sources[source.Name()] = source
	}

	if service.now == nil {
		service.now = time.Now
	}

	if service.timeout <= 0 {
		service.timeout = defaultTimeout
	}

	return service, nil
}

// Diagnose authorizes the caller, validates the request, asks the requested sources in parallel, and assembles
// findings, hypotheses, completeness reports, and notes. A failing source never fails the call.
func (s *Service) Diagnose(ctx context.Context, caller Caller, request DiagnosticsRequest) (*DiagnosticsResult, error) {
	if s == nil {
		if !caller.allowed {
			return nil, newError(CodeForbidden, nil)
		}

		return nil, newError(CodeNotConfigured, nil)
	}

	started := s.now()
	entry := supportaccess.AuditEntry{Service: auditService, Operation: operationDiagnose, CallerIdentity: caller.Identity(),
		CallerMethod: string(caller.Method()), AuditReference: supportaccess.BoundedAuditReference(request.AuditReference)}

	result, err := s.diagnose(ctx, caller, request, started)
	s.record(ctx, entry, started, result, err)

	if err != nil {
		return nil, err
	}

	return result, nil
}

// diagnose runs one authorized call; nothing touches a source before authorization and validation.
func (s *Service) diagnose(ctx context.Context, caller Caller, request DiagnosticsRequest, now time.Time) (*DiagnosticsResult, *Error) {
	if !caller.allowed {
		return nil, newError(CodeForbidden, nil)
	}

	plan, err := newPlan(request, now)
	if err != nil {
		return nil, err
	}

	release, acquired := s.gate.Acquire(ctx, caller.Identity())
	if !acquired {
		return nil, newError(CodeBusy, nil)
	}

	defer release()

	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	query := Query{Window: plan.window, Now: now, Components: plan.components, Instance: s.instance}

	return s.assemble(plan, query, s.collect(ctx, plan, query)), nil
}

// collect asks every requested and configured source in parallel and keeps the response order fixed.
func (s *Service) collect(ctx context.Context, plan requestPlan, query Query) []SourceResult {
	results := make([]SourceResult, len(SourceNames))

	var wait sync.WaitGroup

	for index, name := range SourceNames {
		source, configured := s.sources[name]

		switch {
		case !plan.wantsSource(name):
			results[index] = SourceResult{Report: SourceReport{Name: name, Kind: sourceKind(name), Status: SourceStatusNotRequested,
				Coverage: Coverage{Instances: []string{}}}}
		case !configured:
			results[index] = SourceResult{Report: SourceReport{Name: name, Kind: sourceKind(name), Status: SourceStatusNotConfigured,
				Coverage: Coverage{Instances: []string{}}}}
		default:
			wait.Go(func() {
				results[index] = boundedResult(ctx, source, source.Collect(ctx, query))
			})
		}
	}

	wait.Wait()

	return results
}

// boundedResult marks a source that ran out of time and normalizes its report fields.
func boundedResult(ctx context.Context, source Source, result SourceResult) SourceResult {
	result.Report.Name, result.Report.Kind = source.Name(), source.Kind()

	if result.Report.Coverage.Instances == nil {
		result.Report.Coverage.Instances = []string{}
	}

	if ctx.Err() != nil && result.Report.Status == SourceStatusOK {
		result.Report.Status = SourceStatusTimeout
	}

	return result
}

// sourceKind returns the fixed kind of a known source name.
func sourceKind(name string) SourceKind {
	if IsHistorical(name) {
		return SourceKindHistorical
	}

	return SourceKindLocalCurrent
}

// record writes the audit entry of one call exactly once.
func (s *Service) record(ctx context.Context, entry supportaccess.AuditEntry, started time.Time, result *DiagnosticsResult, err *Error) {
	if s.audit == nil {
		return
	}

	entry.At, entry.Duration = started, s.now().Sub(started)
	entry.Allowed, entry.ResultCode = true, "OK"

	if result != nil {
		entry.Results = len(result.Findings)
	}

	if err != nil {
		entry.Allowed = err.Code != CodeForbidden
		entry.ResultCode = string(err.Code)
	}

	s.audit.RecordSupportAudit(context.WithoutCancel(ctx), entry)
}
