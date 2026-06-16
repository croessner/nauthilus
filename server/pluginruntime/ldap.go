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

package pluginruntime

import (
	"context"
	"errors"
	"fmt"

	pluginapi "github.com/croessner/nauthilus/pluginapi/v1"
	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/backend/priorityqueue"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"

	"github.com/go-ldap/ldap/v3"
)

var (
	// ErrInvalidLDAPScope is returned when a plugin search request uses an unsupported scope.
	ErrInvalidLDAPScope = errors.New("invalid plugin LDAP scope")

	// ErrInvalidLDAPModifyOperation is returned when a plugin modify request uses an unsupported operation.
	ErrInvalidLDAPModifyOperation = errors.New("invalid plugin LDAP modify operation")
)

var _ pluginapi.LDAP = (*LDAPFacade)(nil)

// LDAPExecutor executes API-level LDAP operations behind the host facade.
type LDAPExecutor interface {
	Search(context.Context, pluginapi.LDAPSearchRequest) (pluginapi.LDAPSearchResult, error)
	Modify(context.Context, pluginapi.LDAPModifyRequest) error
}

// LDAPQueue accepts internal LDAP lookup requests.
type LDAPQueue interface {
	Push(request *bktype.LDAPRequest, priority int)
}

// LDAPFacade validates public LDAP requests before delegating to a host executor.
type LDAPFacade struct {
	executor LDAPExecutor
}

// NewLDAPFacade returns a validating LDAP facade over a host executor.
func NewLDAPFacade(executor LDAPExecutor) *LDAPFacade {
	return &LDAPFacade{executor: executor}
}

// NewLDAPQueueExecutor returns an executor backed by the existing LDAP lookup queue.
func NewLDAPQueueExecutor(queue LDAPQueue) LDAPExecutor {
	return &ldapQueueExecutor{
		queue:    queue,
		priority: priorityqueue.PriorityLow,
	}
}

// Search validates and delegates an LDAP search request.
func (f *LDAPFacade) Search(ctx context.Context, request pluginapi.LDAPSearchRequest) (pluginapi.LDAPSearchResult, error) {
	if err := validateLDAPSearchRequest(request); err != nil {
		return pluginapi.LDAPSearchResult{}, err
	}

	if f == nil || f.executor == nil {
		return pluginapi.LDAPSearchResult{}, errors.New("plugin LDAP executor is not configured")
	}

	return f.executor.Search(ctx, cloneLDAPSearchRequest(request))
}

// Modify validates and delegates an LDAP modify request.
func (f *LDAPFacade) Modify(ctx context.Context, request pluginapi.LDAPModifyRequest) error {
	if err := validateLDAPModifyRequest(request); err != nil {
		return err
	}

	if f == nil || f.executor == nil {
		return errors.New("plugin LDAP executor is not configured")
	}

	return f.executor.Modify(ctx, cloneLDAPModifyRequest(request))
}

type ldapQueueExecutor struct {
	queue    LDAPQueue
	priority int
}

// Search submits an LDAP search to the host queue and waits for the reply.
func (e *ldapQueueExecutor) Search(ctx context.Context, request pluginapi.LDAPSearchRequest) (pluginapi.LDAPSearchResult, error) {
	if e == nil || e.queue == nil {
		return pluginapi.LDAPSearchResult{}, errors.New("LDAP queue is not configured")
	}

	ldapRequest, err := newLDAPSearchQueueRequest(ctx, request)
	if err != nil {
		return pluginapi.LDAPSearchResult{}, err
	}

	e.queue.Push(ldapRequest, e.priority)

	reply, err := waitLDAPReply(ctx, ldapRequest.LDAPReplyChan)
	if err != nil {
		return pluginapi.LDAPSearchResult{}, err
	}

	return ldapReplyToSearchResult(reply), nil
}

// Modify submits an LDAP modify request to the host queue and waits for completion.
func (e *ldapQueueExecutor) Modify(ctx context.Context, request pluginapi.LDAPModifyRequest) error {
	if e == nil || e.queue == nil {
		return errors.New("LDAP queue is not configured")
	}

	ldapRequest, err := newLDAPModifyQueueRequest(ctx, request)
	if err != nil {
		return err
	}

	e.queue.Push(ldapRequest, e.priority)

	_, err = waitLDAPReply(ctx, ldapRequest.LDAPReplyChan)

	return err
}

// validateLDAPSearchRequest checks scope and required fields.
func validateLDAPSearchRequest(request pluginapi.LDAPSearchRequest) error {
	if !validLDAPScope(request.Scope) {
		return fmt.Errorf("%w: %q", ErrInvalidLDAPScope, request.Scope)
	}

	return nil
}

// validateLDAPModifyRequest checks operation and required fields.
func validateLDAPModifyRequest(request pluginapi.LDAPModifyRequest) error {
	if !validLDAPModifyOperation(request.Operation) {
		return fmt.Errorf("%w: %q", ErrInvalidLDAPModifyOperation, request.Operation)
	}

	return nil
}

// validLDAPScope reports whether a public LDAP search scope is supported.
func validLDAPScope(scope pluginapi.LDAPScope) bool {
	switch scope {
	case pluginapi.LDAPScopeBase, pluginapi.LDAPScopeOne, pluginapi.LDAPScopeSub:
		return true
	default:
		return false
	}
}

// validLDAPModifyOperation reports whether a public LDAP modify operation is supported.
func validLDAPModifyOperation(operation pluginapi.LDAPModifyOperation) bool {
	switch operation {
	case pluginapi.LDAPModifyAdd, pluginapi.LDAPModifyDelete, pluginapi.LDAPModifyReplace:
		return true
	default:
		return false
	}
}

// newLDAPSearchQueueRequest maps a public search request to the internal queue request.
func newLDAPSearchQueueRequest(ctx context.Context, request pluginapi.LDAPSearchRequest) (*bktype.LDAPRequest, error) {
	scope, err := ldapScope(request.Scope)
	if err != nil {
		return nil, err
	}

	return &bktype.LDAPRequest{
		PoolName:          request.PoolName,
		BaseDN:            request.BaseDN,
		Filter:            request.Filter,
		Scope:             scope,
		SearchAttributes:  append([]string(nil), request.Attributes...),
		Command:           definitions.LDAPSearch,
		LDAPReplyChan:     make(chan *bktype.LDAPReply, 1),
		HTTPClientContext: ctx,
	}, nil
}

// newLDAPModifyQueueRequest maps a public modify request to the internal queue request.
func newLDAPModifyQueueRequest(ctx context.Context, request pluginapi.LDAPModifyRequest) (*bktype.LDAPRequest, error) {
	subCommand, err := ldapModifySubCommand(request.Operation)
	if err != nil {
		return nil, err
	}

	return &bktype.LDAPRequest{
		PoolName:          request.PoolName,
		ModifyDN:          request.DN,
		SubCommand:        subCommand,
		ModifyAttributes:  bktype.LDAPModifyAttributes(cloneStringSliceMap(request.Attributes)),
		Command:           definitions.LDAPModify,
		LDAPReplyChan:     make(chan *bktype.LDAPReply, 1),
		HTTPClientContext: ctx,
	}, nil
}

// ldapScope converts the API scope to the internal config scope.
func ldapScope(scope pluginapi.LDAPScope) (config.LDAPScope, error) {
	var internal config.LDAPScope
	if err := internal.Set(string(scope)); err != nil {
		return config.LDAPScope{}, fmt.Errorf("%w: %q", ErrInvalidLDAPScope, scope)
	}

	return internal, nil
}

// ldapModifySubCommand converts the API modify operation to the internal subcommand.
func ldapModifySubCommand(operation pluginapi.LDAPModifyOperation) (definitions.LDAPSubCommand, error) {
	switch operation {
	case pluginapi.LDAPModifyAdd:
		return definitions.LDAPModifyAdd, nil
	case pluginapi.LDAPModifyDelete:
		return definitions.LDAPModifyDelete, nil
	case pluginapi.LDAPModifyReplace:
		return definitions.LDAPModifyReplace, nil
	default:
		return definitions.LDAPModifyUnknown, fmt.Errorf("%w: %q", ErrInvalidLDAPModifyOperation, operation)
	}
}

// waitLDAPReply waits for a queue reply or context cancellation.
func waitLDAPReply(ctx context.Context, replyChan <-chan *bktype.LDAPReply) (*bktype.LDAPReply, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case reply := <-replyChan:
		if reply == nil {
			return nil, errors.New("LDAP queue returned nil reply")
		}

		return reply, reply.Err
	}
}

// ldapReplyToSearchResult maps internal LDAP reply data to public value objects.
func ldapReplyToSearchResult(reply *bktype.LDAPReply) pluginapi.LDAPSearchResult {
	if reply == nil {
		return pluginapi.LDAPSearchResult{}
	}

	return pluginapi.LDAPSearchResult{
		Attributes: attributeMappingToStringMap(reply.Result),
		Entries:    ldapEntriesToAPI(reply.RawResult),
	}
}

// attributeMappingToStringMap converts LDAP attribute values to string slices.
func attributeMappingToStringMap(values bktype.AttributeMapping) map[string][]string {
	if len(values) == 0 {
		return map[string][]string{}
	}

	converted := make(map[string][]string, len(values))
	for key, entries := range values {
		for _, entry := range entries {
			converted[key] = append(converted[key], fmt.Sprint(entry))
		}
	}

	return converted
}

// ldapEntriesToAPI converts raw go-ldap entries to public LDAP entries.
func ldapEntriesToAPI(entries []*ldap.Entry) []pluginapi.LDAPEntry {
	if len(entries) == 0 {
		return nil
	}

	converted := make([]pluginapi.LDAPEntry, 0, len(entries))
	for _, entry := range entries {
		if entry == nil {
			continue
		}

		converted = append(converted, pluginapi.LDAPEntry{
			DN:         entry.DN,
			Attributes: ldapEntryAttributesToMap(entry.Attributes),
		})
	}

	return converted
}

// ldapEntryAttributesToMap copies go-ldap entry attributes into public value objects.
func ldapEntryAttributesToMap(attributes []*ldap.EntryAttribute) map[string][]string {
	if len(attributes) == 0 {
		return map[string][]string{}
	}

	converted := make(map[string][]string, len(attributes))
	for _, attribute := range attributes {
		if attribute == nil {
			continue
		}

		converted[attribute.Name] = append([]string(nil), attribute.Values...)
	}

	return converted
}

// cloneLDAPSearchRequest returns an immutable copy for executor calls.
func cloneLDAPSearchRequest(request pluginapi.LDAPSearchRequest) pluginapi.LDAPSearchRequest {
	request.Attributes = append([]string(nil), request.Attributes...)

	return request
}

// cloneLDAPModifyRequest returns an immutable copy for executor calls.
func cloneLDAPModifyRequest(request pluginapi.LDAPModifyRequest) pluginapi.LDAPModifyRequest {
	request.Attributes = cloneStringSliceMap(request.Attributes)

	return request
}

// cloneStringSliceMap deep-copies a map of string slices.
func cloneStringSliceMap(values map[string][]string) map[string][]string {
	if len(values) == 0 {
		return map[string][]string{}
	}

	cloned := make(map[string][]string, len(values))
	for key, entries := range values {
		cloned[key] = append([]string(nil), entries...)
	}

	return cloned
}
