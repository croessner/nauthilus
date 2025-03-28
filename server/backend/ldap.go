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

	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/backend/ldappool"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib/convert"
	"github.com/segmentio/ksuid"
	"github.com/yuin/gopher-lua"
)

// LDAPMainWorker orchestrates LDAP lookup operations, manages a connection pool, and processes incoming requests in a loop.
func LDAPMainWorker(ctx context.Context) {
	var ldapWaitGroup sync.WaitGroup

	ldapPool := ldappool.NewPool(ctx, definitions.LDAPPoolLookup)
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

			GetChannel().GetLdapChannel().GetLookupEndChan(DefaultBackendName) <- bktype.Done{}

			return

		case ldapRequest := <-GetChannel().GetLdapChannel().GetLookupRequestChan(DefaultBackendName):
			// Check that we have enough idle connections.
			if err := ldapPool.SetIdleConnections(true); err != nil {
				ldapRequest.LDAPReplyChan <- &bktype.LDAPReply{Err: err}
			}

			if err := ldapPool.HandleLookupRequest(ldapRequest, &ldapWaitGroup); err != nil {
				ldapWaitGroup.Done()

				ldapRequest.LDAPReplyChan <- &bktype.LDAPReply{Err: err}
			}
		}
	}
}

// LDAPAuthWorker is responsible for handling LDAP authentication requests using a connection pool and concurrency control.
// It initializes the authentication connection pool, starts a resource management process, and handles requests or exits gracefully.
func LDAPAuthWorker(ctx context.Context) {
	var ldapWaitGroup sync.WaitGroup

	ldapPool := ldappool.NewPool(ctx, definitions.LDAPPoolAuth)
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

			GetChannel().GetLdapChannel().GetAuthEndChan(DefaultBackendName) <- bktype.Done{}

			return
		case ldapAuthRequest := <-GetChannel().GetLdapChannel().GetAuthRequestChan(DefaultBackendName):
			// Check that we have enough idle connections.
			if err := ldapPool.SetIdleConnections(false); err != nil {
				ldapAuthRequest.LDAPReplyChan <- &bktype.LDAPReply{Err: err}
			}

			if err := ldapPool.HandleAuthRequest(ldapAuthRequest, &ldapWaitGroup); err != nil {
				ldapWaitGroup.Done()

				ldapAuthRequest.LDAPReplyChan <- &bktype.LDAPReply{Err: err}
			}
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

		GetChannel().GetLdapChannel().GetLookupRequestChan(fieldValues["pool_name"].String()) <- ldapRequest

		return processReply(L, ldapRequest.GetLDAPReplyChan())
	}
}

// prepareAndValidateFields validates and retrieves expected fields from a Lua table, returning a map of field values.
// Fields are matched against a predefined set of expected names and types, raising an error if a field is missing or invalid.
func prepareAndValidateFields(L *lua.LState, table *lua.LTable) map[string]lua.LValue {
	expectedFields := map[string]string{
		"session":    definitions.LuaLiteralString,
		"pool_name":  definitions.LuaLiteralString,
		"basedn":     definitions.LuaLiteralString,
		"filter":     definitions.LuaLiteralString,
		"scope":      definitions.LuaLiteralString,
		"attributes": definitions.LuaLiteralTable,
	}

	fieldValues := make(map[string]lua.LValue)
	for field, typeExpected := range expectedFields {
		if !validateField(L, table, field, typeExpected) {
			if field == "pool_name" {
				fieldValues[field] = lua.LString(DefaultBackendName)

				continue
			}

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
		if fieldName == "pool_name" {
			return false
		}

		L.RaiseError("%s is required", fieldName)
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
		L.RaiseError("unknown field type %s", fieldType)
	}

	return true
}

// createLDAPRequest initializes an LDAPRequest with provided field values, scope, and context for an LDAP search operation.
func createLDAPRequest(fieldValues map[string]lua.LValue, scope *config.LDAPScope, ctx context.Context) *bktype.LDAPRequest {
	guid := fieldValues["session"].String()
	basedn := fieldValues["basedn"].String()
	filter := fieldValues["filter"].String()
	attrTable := fieldValues["attributes"].(*lua.LTable)
	attributes := extractAttributes(attrTable)

	if guid == "" {
		guid = ksuid.New().String()
	}

	ldapReplyChan := make(chan *bktype.LDAPReply)

	ldapRequest := &bktype.LDAPRequest{
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
func processReply(L *lua.LState, ldapReplyChan chan *bktype.LDAPReply) int {
	ldapReply := <-ldapReplyChan

	// Check if there is an error. If so, return it.
	if ldapReply.Err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(ldapReply.Err.Error()))

		return 2
	}

	// Converting AttributeMapping (map[string][]any) to map[any]any
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
