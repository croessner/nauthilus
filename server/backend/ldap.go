// Copyright (C) 2024 Christian Rößner
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

package backend

import (
	"context"
	stderrors "errors"
	"fmt"
	"sync"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib/convert"
	"github.com/croessner/nauthilus/server/util"
	"github.com/go-ldap/ldap/v3"
	"github.com/segmentio/ksuid"
	"github.com/yuin/gopher-lua"
)

// PoolRequest represents a generic interface for handling LDAP requests and responses.
// It provides a method to retrieve a channel for receiving LDAP replies.
type PoolRequest[T any] interface {
	GetLDAPReplyChan() chan *LDAPReply
}

// LDAPModifyAttributes represents a map of attribute names to their corresponding values for LDAP modify operations.
type LDAPModifyAttributes map[string][]string

// LDAPRequest represents an LDAP request.
type LDAPRequest struct {
	// GUID is the globally unique identifier for this LDAP request, optional.
	GUID *string

	// RequestID represents the globally unique identifier for an LDAP request. It is a pointer to a string.
	RequestID *string

	// Filter is the criteria that the LDAP request uses to filter during the search.
	Filter string

	// BaseDN is the base distinguished name used as the search base.
	BaseDN string

	// SearchAttributes are the attributes for which values are to be returned in the search results.
	SearchAttributes []string

	// MacroSource is the source of macros to be used, optional.
	MacroSource *util.MacroSource

	// Scope defines the scope for LDAP search (base, one, or sub).
	Scope config.LDAPScope

	// Command represents the LDAP command to be executed (add, modify, delete, or search).
	Command definitions.LDAPCommand

	// ModifyAttributes contains attributes information used in modify command.
	ModifyAttributes LDAPModifyAttributes

	// LDAPReplyChan is the channel where reply from LDAP server is sent.
	LDAPReplyChan chan *LDAPReply

	// HTTPClientContext is the context for managing HTTP requests and responses.
	HTTPClientContext context.Context
}

// GetLDAPReplyChan returns the channel where replies from the LDAP server are sent.
// It retrieves and returns the value of the `LDAPReplyChan` field of the `LDAPRequest` struct.
func (l *LDAPRequest) GetLDAPReplyChan() chan *LDAPReply {
	return l.LDAPReplyChan
}

var _ PoolRequest[LDAPRequest] = (*LDAPRequest)(nil)

// LDAPAuthRequest represents a request to authenticate with an LDAP server.
type LDAPAuthRequest struct {
	// GUID is the unique identifier for the LDAP auth request.
	// It can be nil.
	GUID *string

	// BindDN is the Distinguished Name for binding to the LDAP server.
	BindDN string

	// BindPW is the password for binding to the LDAP server.
	BindPW string

	// LDAPReplyChan is a channel where the LDAP responses will be sent.
	LDAPReplyChan chan *LDAPReply

	// HTTPClientContext is the context for the HTTP client
	// carrying the LDAP auth request.
	HTTPClientContext context.Context
}

// GetLDAPReplyChan returns the channel where LDAP responses are sent.
func (l *LDAPAuthRequest) GetLDAPReplyChan() chan *LDAPReply {
	return l.LDAPReplyChan
}

var _ PoolRequest[LDAPAuthRequest] = (*LDAPAuthRequest)(nil)

// LDAPReply represents the structure for handling responses from an LDAP operation.
// It contains the result of the operation, raw entries, and any possible error encountered.
type LDAPReply struct {
	// Result holds the outcome of a database query or LDAP operation, mapping field names or attributes to their values.
	Result DatabaseResult

	// RawResult contains a slice of raw LDAP entries retrieved from an LDAP operation. It is used for processing raw data.
	RawResult []*ldap.Entry

	// Err captures any error encountered during the LDAP operation or response parsing.
	Err error
}

// LDAPMainWorker orchestrates LDAP lookup operations, manages a connection pool, and processes incoming requests in a loop.
func LDAPMainWorker(ctx context.Context) {
	var ldapWaitGroup sync.WaitGroup

	ldapPool := NewPool(ctx, definitions.LDAPPoolLookup)
	if ldapPool == nil {
		return
	}

	// Start a background cleaner process
	go ldapPool.StartHouseKeeper()

	ldapPool.SetIdleConnections(true)

	for {
		select {
		case <-ctx.Done():
			ldapPool.Close()

			GetChannel().GetLdapChannel().GetLookupEndChan() <- Done{}

			return

		case ldapRequest := <-GetChannel().GetLdapChannel().GetLookupRequestChan():
			// Check that we have enough idle connections.
			if err := ldapPool.SetIdleConnections(true); err != nil {
				ldapRequest.LDAPReplyChan <- &LDAPReply{Err: err}
			}

			ldapPool.HandleLookupRequest(ldapRequest, &ldapWaitGroup)
		}
	}
}

// LDAPAuthWorker is responsible for handling LDAP authentication requests using a connection pool and concurrency control.
// It initializes the authentication connection pool, starts a resource management process, and handles requests or exits gracefully.
func LDAPAuthWorker(ctx context.Context) {
	var ldapWaitGroup sync.WaitGroup

	ldapPool := NewPool(ctx, definitions.LDAPPoolAuth)
	if ldapPool == nil {
		return
	}

	// Start a background cleaner process
	go ldapPool.StartHouseKeeper()

	ldapPool.SetIdleConnections(false)

	for {
		select {
		case <-ctx.Done():
			ldapPool.Close()

			GetChannel().GetLdapChannel().GetAuthEndChan() <- Done{}

			return
		case ldapAuthRequest := <-GetChannel().GetLdapChannel().GetAuthRequestChan():
			// Check that we have enough idle connections.
			if err := ldapPool.SetIdleConnections(false); err != nil {
				ldapAuthRequest.LDAPReplyChan <- &LDAPReply{Err: err}
			}

			ldapPool.HandleAuthRequest(ldapAuthRequest, &ldapWaitGroup)
		}
	}
}

// convertScopeStringToLDAP converts an LDAP scope string into an LDAPScope object.
// Returns the corresponding *config.LDAPScope and nil error if successful, or nil and an error for invalid input.
func convertScopeStringToLDAP(toString string) (*config.LDAPScope, error) {
	var err error

	scope := &config.LDAPScope{}
	if toString == "" {
		scope.Set("sub")
	} else {
		if err = scope.Set(toString); err != nil {
			return nil, stderrors.New(fmt.Sprintf("LDAP scope not detected: %s", toString))
		}
	}

	return scope, nil
}

// LuaLDAPSearch initializes and registers an LDAP search function for Lua, handling inputs, validation, and processing.
func LuaLDAPSearch(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		table := L.CheckTable(1)

		fieldValues := prepareAndValidateFields(L, table)
		if fieldValues == nil {
			return 1
		}

		scope, scopeErr := convertScopeStringToLDAP(fieldValues["scope"].String())
		if scopeErr != nil {
			L.RaiseError("%s", scopeErr.Error())

			return 1
		}

		ldapRequest := createLDAPRequest(fieldValues, scope, ctx)

		GetChannel().GetLdapChannel().GetLookupRequestChan() <- ldapRequest

		return processReply(L, ldapRequest.GetLDAPReplyChan())
	}
}

// prepareAndValidateFields validates and retrieves expected fields from a Lua table, returning a map of field values.
// Fields are matched against a predefined set of expected names and types, raising an error if a field is missing or invalid.
func prepareAndValidateFields(L *lua.LState, table *lua.LTable) map[string]lua.LValue {
	expectedFields := map[string]string{
		"session":    definitions.LuaLiteralString,
		"basedn":     definitions.LuaLiteralString,
		"filter":     definitions.LuaLiteralString,
		"scope":      definitions.LuaLiteralString,
		"attributes": definitions.LuaLiteralTable,
	}

	fieldValues := make(map[string]lua.LValue)
	for field, typeExpected := range expectedFields {
		if !validateField(L, table, field, typeExpected) {
			return nil
		}

		fieldValues[field] = L.GetField(table, field)
	}

	return fieldValues
}

// validateField checks if a given field exists in a Lua table and validates its type, raising an error if invalid.
// L represents the Lua state, table is the Lua table, fieldName is the field to verify, and fieldType is the expected data type.
// Returns true if the field exists and matches the expected type, otherwise returns false.
func validateField(L *lua.LState, table *lua.LTable, fieldName string, fieldType string) bool {
	lv := L.GetField(table, fieldName)
	if lua.LVIsFalse(lv) {
		L.RaiseError("%s is required", fieldName)

		return false
	}

	switch fieldType {
	case definitions.LuaLiteralString:
		if _, ok := lv.(lua.LString); !ok {
			L.RaiseError("%s should be a string", fieldName)
		}
	case definitions.LuaLiteralTable:
		if _, ok := lv.(*lua.LTable); !ok {
			L.RaiseError("%s should be a table", fieldName)
		}
	default:
		return false
	}

	return true
}

// createLDAPRequest initializes an LDAPRequest with provided field values, scope, and context for an LDAP search operation.
func createLDAPRequest(fieldValues map[string]lua.LValue, scope *config.LDAPScope, ctx context.Context) *LDAPRequest {
	guid := fieldValues["session"].String()
	basedn := fieldValues["basedn"].String()
	filter := fieldValues["filter"].String()
	attrTable := fieldValues["attributes"].(*lua.LTable)
	attributes := extractAttributes(attrTable)

	if guid == "" {
		guid = ksuid.New().String()
	}

	ldapReplyChan := make(chan *LDAPReply)

	ldapRequest := &LDAPRequest{
		GUID:              &guid,
		Filter:            filter,
		BaseDN:            basedn,
		SearchAttributes:  attributes,
		Scope:             *scope,
		Command:           definitions.LDAPSearch,
		LDAPReplyChan:     ldapReplyChan,
		HTTPClientContext: ctx,
	}

	return ldapRequest
}

// extractAttributes extracts string attributes from a Lua table and returns them as a slice of strings.
func extractAttributes(attrTable *lua.LTable) []string {
	attributes := make([]string, attrTable.Len())
	attrTable.ForEach(func(index lua.LValue, value lua.LValue) {
		attributes = append(attributes, value.String())
	})

	return attributes
}

// processReply processes an LDAP reply received from a channel and converts it into a Lua-compatible value or error.
func processReply(L *lua.LState, ldapReplyChan chan *LDAPReply) int {
	ldapReply := <-ldapReplyChan

	// Check if there is an error. If so, return it.
	if ldapReply.Err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(ldapReply.Err.Error()))

		return 2
	}

	// Converting DatabaseResult (map[string][]any) to map[any]any
	// which can be used in util.MapToLuaTable function
	convertedMap := make(map[any]any)
	for key, values := range ldapReply.Result {
		list := make([]any, len(values))

		for i, val := range values {
			list[i] = val
		}

		convertedMap[key] = list
	}

	resultTable := convert.GoToLuaValue(L, convertedMap)

	if resultTable == nil {
		L.Push(lua.LString("no result"))
		L.Push(lua.LNil)

		return 2
	}

	L.Push(resultTable)

	return 1
}
