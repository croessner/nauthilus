// Copyright (C) 2026 Christian Roessner
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

package pluginapi

import (
	"context"
	"time"
)

// AbortPolicy describes how the host handles source abort signals.
type AbortPolicy string

const (
	// AbortPolicyNone leaves later sources eligible to run.
	AbortPolicyNone AbortPolicy = "none"

	// AbortPolicySource stops later sources in the same extension plan.
	AbortPolicySource AbortPolicy = "source"

	// AbortPolicyRequest stops the request-time extension plan.
	AbortPolicyRequest AbortPolicy = "request"
)

// SourceDescriptor describes one dependency-scheduled Go source component.
// Requires and After can target local or fully qualified plugin source names;
// Lua source dependencies are not supported in v1.
type SourceDescriptor struct {
	Timeout     time.Duration
	Name        string
	Requires    []string
	After       []string
	Priority    int
	AbortPolicy AbortPolicy
}

// InitContext exposes host services to init tasks without exposing server internals.
type InitContext struct {
	Host   Host
	Config ConfigView
}

// InitTask is a named startup or worker unit registered by a plugin.
type InitTask interface {
	Name() string
	Start(context.Context, InitContext) error
	Stop(context.Context) error
}

// EnvironmentRequest is passed to pre-auth environment sources.
type EnvironmentRequest struct {
	Snapshot    RequestSnapshot
	Runtime     RuntimeContext
	Credentials CredentialProvider
}

// EnvironmentResult is returned by pre-auth environment sources.
type EnvironmentResult struct {
	Status       *StatusMessage
	Logs         []LogField
	Facts        []PolicyFact
	RuntimeDelta RuntimeDelta
	Triggered    bool
	Abort        bool
}

// EnvironmentSource emits pre-auth environment facts and runtime deltas.
type EnvironmentSource interface {
	Descriptor() SourceDescriptor
	Evaluate(context.Context, EnvironmentRequest) (EnvironmentResult, error)
}

// SubjectRequest is passed to post-backend subject sources.
type SubjectRequest struct {
	Snapshot      RequestSnapshot
	Runtime       RuntimeContext
	BackendResult BackendResult
	Credentials   CredentialProvider
}

// SubjectResult is returned by post-backend subject sources.
type SubjectResult struct {
	Status             *StatusMessage
	SelectedBackend    *BackendServerRef
	BackendResultPatch *BackendResultPatch
	Logs               []LogField
	Facts              []PolicyFact
	BackendAttributes  AttributePatch
	Response           ResponseMutation
	RuntimeDelta       RuntimeDelta
	Rejected           bool
}

// SubjectSource enriches or rejects a subject after backend evaluation.
type SubjectSource interface {
	Descriptor() SourceDescriptor
	Evaluate(context.Context, SubjectRequest) (SubjectResult, error)
}

// ObligationRequest is passed to synchronous policy obligation targets.
type ObligationRequest struct {
	Snapshot RequestSnapshot
	Runtime  RuntimeContext
	Args     ArgsView
	Facts    []PolicyFact
}

// ObligationResult is returned by synchronous policy obligation targets.
type ObligationResult struct {
	Status       *StatusMessage
	Logs         []LogField
	Facts        []PolicyFact
	Response     ResponseMutation
	RuntimeDelta RuntimeDelta
	Applied      bool
	Temporary    bool
}

// ObligationTarget executes synchronous policy-selected enforcement.
type ObligationTarget interface {
	Name() string
	Execute(context.Context, ObligationRequest) (ObligationResult, error)
}

// PostActionRequest is passed to asynchronous post-action enqueue targets.
type PostActionRequest struct {
	Snapshot     RequestSnapshot
	Runtime      RuntimeContext
	Credentials  CredentialProvider
	PasswordHash string
	Args         ArgsView
	Facts        []PolicyFact
}

// PostActionEnqueueResult is returned after detached post-action work is accepted or skipped.
type PostActionEnqueueResult struct {
	Status       *StatusMessage
	Logs         []LogField
	RuntimeDelta RuntimeDelta
	QueuedID     string
	Enqueued     bool
	Temporary    bool
}

// PostActionTarget enqueues detached post-decision work under host supervision.
type PostActionTarget interface {
	Name() string
	Enqueue(context.Context, PostActionRequest) (PostActionEnqueueResult, error)
}
