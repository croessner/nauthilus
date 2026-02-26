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
	"fmt"
	"log/slog"
	"sync"

	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/backend/ldappool"
	"github.com/croessner/nauthilus/server/backend/priorityqueue"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib/convert"
	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/yuin/gopher-lua"
	"go.opentelemetry.io/otel/attribute"
)

var (
	trOps = monittrace.New("nauthilus/ldap_ops")
	trLua = monittrace.New("nauthilus/ldap_lua")
)

// LDAPMainWorker orchestrates LDAP lookup operations, manages a connection pool, and processes incoming requests in a loop.
// It now uses a priority queue instead of channels for better request handling.
func LDAPMainWorker(ctx context.Context, cfg config.File, logger *slog.Logger, channel Channel, poolName string, deps LDAPWorkerDeps) {
	queue := deps.ldapQueue()
	poolFactory := deps.poolFactory()
	// Ensure the LDAP-scoped shared TTL cache is initialized and its janitor is
	// bound to this worker's lifecycle. This avoids running the TTL janitor when
	// no LDAP backend is active.
	ldappool.StartSharedTTLCache(ctx)

	ldapPool := poolFactory.NewPool(ctx, cfg, logger, definitions.LDAPPoolLookup, poolName)

	// Start a background cleaner process
	go ldapPool.StartHouseKeeper()

	ldapPool.SetIdleConnections(true)

	// Add the pool name to the queue
	queue.AddPoolName(poolName)

	// Configure queue length limit from config (0 = unlimited)
	lookupLimit := 0
	if poolName == definitions.DefaultBackendName {
		if ldapCfg := cfg.GetLDAP().GetConfig(); ldapCfg != nil {
			if c, ok := ldapCfg.(*config.LDAPConf); ok {
				lookupLimit = c.GetLookupQueueLength()
			}
		}
	} else {
		pools := cfg.GetLDAP().GetOptionalLDAPPools()
		if pools != nil {
			if pc := pools[poolName]; pc != nil {
				lookupLimit = pc.GetLookupQueueLength()
			}
		}
	}

	queue.SetMaxQueueLength(poolName, lookupLimit)

	runLDAPWorkerLoop(ctx, ldapPool, poolName, ldapWorkerCallbacks{
		spanName:   "ldap.worker.process",
		idleExpand: true,
		popRequest: func() (guid string, httpCtx context.Context, replyChan chan *bktype.LDAPReply, handle func() error) {
			req := queue.PopWithContext(ctx, poolName)
			if req == nil {
				return "", nil, nil, nil
			}

			return req.GUID, req.HTTPClientContext, req.LDAPReplyChan, func() error {
				return ldapPool.HandleLookupRequest(req)
			}
		},
		doneChan: channel.GetLdapChannel().GetLookupEndChan(poolName),
	})
}

// LDAPAuthWorker is responsible for handling LDAP authentication requests using a connection pool and concurrency control.
// It initializes the authentication connection pool, starts a resource management process, and handles requests or exits gracefully.
// It now uses a priority queue instead of channels for better request handling.
func LDAPAuthWorker(ctx context.Context, cfg config.File, logger *slog.Logger, channel Channel, poolName string, deps LDAPWorkerDeps) {
	authQueue := deps.ldapAuthQueue()
	poolFactory := deps.poolFactory()

	ldapPool := poolFactory.NewPool(ctx, cfg, logger, definitions.LDAPPoolAuth, poolName)

	// Start a background cleaner process
	go ldapPool.StartHouseKeeper()

	ldapPool.SetIdleConnections(false)

	// Add the pool name to the queue
	authQueue.AddPoolName(poolName)

	// Configure auth queue length limit from config (0 = unlimited)
	authLimit := 0
	if poolName == definitions.DefaultBackendName {
		if ldapCfg := cfg.GetLDAP().GetConfig(); ldapCfg != nil {
			if c, ok := ldapCfg.(*config.LDAPConf); ok {
				authLimit = c.GetAuthQueueLength()
			}
		}
	} else {
		pools := cfg.GetLDAP().GetOptionalLDAPPools()
		if pools != nil {
			if pc := pools[poolName]; pc != nil {
				authLimit = pc.GetAuthQueueLength()
			}
		}
	}

	authQueue.SetMaxQueueLength(poolName, authLimit)

	runLDAPWorkerLoop(ctx, ldapPool, poolName, ldapWorkerCallbacks{
		spanName:   "ldap.worker.process_auth",
		idleExpand: false,
		popRequest: func() (guid string, httpCtx context.Context, replyChan chan *bktype.LDAPReply, handle func() error) {
			req := authQueue.PopWithContext(ctx, poolName)
			if req == nil {
				return "", nil, nil, nil
			}

			return req.GUID, req.HTTPClientContext, req.LDAPReplyChan, func() error {
				return ldapPool.HandleAuthRequest(req)
			}
		},
		doneChan: channel.GetLdapChannel().GetAuthEndChan(poolName),
	})
}

// ldapWorkerCallbacks holds the per-worker-type callbacks for runLDAPWorkerLoop.
type ldapWorkerCallbacks struct {
	// popRequest pops the next request from the queue and returns its fields.
	// A nil handle return signals the queue is closed.
	popRequest func() (guid string, httpCtx context.Context, replyChan chan *bktype.LDAPReply, handle func() error)
	doneChan   chan bktype.Done
	spanName   string
	idleExpand bool
}

// runLDAPWorkerLoop starts worker goroutines that pop requests from a queue and process them.
// It is shared between LDAPMainWorker and LDAPAuthWorker to avoid duplicating the loop logic.
func runLDAPWorkerLoop(ctx context.Context, ldapPool ldappool.LDAPPool, poolName string, cb ldapWorkerCallbacks) {
	var wg sync.WaitGroup

	for i := 0; i < ldapPool.GetNumberOfWorkers(); i++ {

		wg.Go(func() {
			for {
				select {
				case <-ctx.Done():
					ldapPool.Close()

					return
				default:
				}

				guid, httpCtx, replyChan, handle := cb.popRequest()
				if handle == nil {
					ldapPool.Close()

					return
				}

				func() {
					_, span := trOps.Start(httpCtx, cb.spanName,
						attribute.String("pool", poolName),
						attribute.String("guid", guid),
					)
					defer span.End()

					if err := ldapPool.SetIdleConnections(cb.idleExpand); err != nil {
						replyChan <- &bktype.LDAPReply{Err: err}

						return
					}

					if err := handle(); err != nil {
						replyChan <- &bktype.LDAPReply{Err: err}
					}
				}()
			}
		})
	}

	go func() {
		wg.Wait()
		TrySignalDone(cb.doneChan)
	}()
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
			return nil, fmt.Errorf("LDAP scope not detected: %s", toString)
		}
	}

	return scope, nil
}

// LuaLDAPSearch initializes and registers an LDAP search function for Lua, handling inputs, validation, and processing.
func LuaLDAPSearch(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		callCtx := ctx
		cancel := func() {}

		if callCtx != nil {
			if _, has := callCtx.Deadline(); !has {
				callCtx, cancel = context.WithTimeout(callCtx, definitions.LuaLDAPReplyTimeout)
			}
		}

		defer cancel()
		table := L.CheckTable(1)

		trCtx, span := trLua.Start(callCtx, "ldap.lua.search")
		defer span.End()

		_, pSpan := trLua.Start(trCtx, "ldap.lua.search.prepare")
		fieldValues := prepareAndValidateSearchFields(L, table)
		if fieldValues == nil {
			pSpan.End()
			L.RaiseError("invalid search fields")

			return 0
		}

		setDefaultPoolName(fieldValues)
		pSpan.End()

		ldapRequest := createLDAPRequest(L, fieldValues, trCtx, definitions.LDAPSearch)

		// Determine priority (using low priority for Lua-initiated requests)
		priority := priorityqueue.PriorityLow

		// Use priority queue instead of channel
		_, qSpan := trLua.Start(trCtx, "ldap.lua.search.enqueue")
		luaLDAPQueue.Push(ldapRequest, priority)
		qSpan.End()

		return processReply(trCtx, L, ldapRequest.GetLDAPReplyChan())
	}
}

// LuaLDAPModify is a function that modifies LDAP entries based on the given Lua table input.
// It validates the input table, creates an LDAP modification request, and sends it via priority queue.
// The function returns results via Lua stack, "OK" on success, or an error message if the operation fails.
func LuaLDAPModify(ctx context.Context) lua.LGFunction {
	return func(L *lua.LState) int {
		callCtx := ctx
		cancel := func() {}

		if callCtx != nil {
			if _, has := callCtx.Deadline(); !has {
				callCtx, cancel = context.WithTimeout(callCtx, definitions.LuaLDAPReplyTimeout)
			}
		}

		defer cancel()
		table := L.CheckTable(1)

		trCtx, span := trLua.Start(callCtx, "ldap.lua.modify")
		defer span.End()

		_, pSpan := trLua.Start(trCtx, "ldap.lua.modify.prepare")
		fieldValues := prepareAndValidateModifyFields(L, table)
		if fieldValues == nil {
			pSpan.End()
			L.RaiseError("invalid modify fields")

			return 0
		}

		setDefaultPoolName(fieldValues)
		pSpan.End()

		ldapRequest := createLDAPRequest(L, fieldValues, trCtx, definitions.LDAPModify)

		// Determine priority (using low priority for Lua-initiated requests)
		priority := priorityqueue.PriorityLow

		// Use priority queue instead of channel
		_, qSpan := trLua.Start(trCtx, "ldap.lua.modify.enqueue")
		luaLDAPQueue.Push(ldapRequest, priority)
		qSpan.End()

		var ldapReply *bktype.LDAPReply
		_, wSpan := trLua.Start(trCtx, "ldap.lua.modify.wait")
		defer wSpan.End()

		select {
		case <-callCtx.Done():
			L.Push(lua.LNil)
			L.Push(lua.LString(callCtx.Err().Error()))

			return 2
		case ldapReply = <-ldapRequest.GetLDAPReplyChan():
		}

		if ldapReply.Err != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(ldapReply.Err.Error()))

			return 2
		}

		L.Push(lua.LString("OK"))

		return 1
	}
}

// prepareAndValidateSearchFields validates and retrieves expected fields from a Lua table, returning a map of field values.
// Fields are matched against a predefined set of expected names and types, raising an error if a field is missing or invalid.
// It also accepts an optional "raw_result" boolean field to indicate if the raw LDAP result should be returned.
func prepareAndValidateSearchFields(L *lua.LState, table *lua.LTable) map[string]lua.LValue {
	expectedFields := map[string]string{
		"pool_name":  definitions.LuaLiteralString,
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

	// Check for optional raw_result field
	rawResult := L.GetField(table, "raw_result")
	if rawResult != lua.LNil {
		if _, ok := rawResult.(lua.LBool); !ok {
			L.RaiseError("raw_result should be a boolean")

			return nil
		}

		fieldValues["raw_result"] = rawResult
	}

	return fieldValues
}

// prepareAndValidateModifyFields processes a Lua table, validates required fields, and returns a map of field values.
// L is the Lua state, table is the Lua table containing field data to validate and extract values from.
// Mandatory fields are checked for presence and type; a default value is applied for "pool_name" if not provided.
// Returns a map of extracted field values on success or nil if validation fails.
func prepareAndValidateModifyFields(L *lua.LState, table *lua.LTable) map[string]lua.LValue {
	expectedFields := map[string]string{
		"pool_name":  definitions.LuaLiteralString,
		"session":    definitions.LuaLiteralString,
		"operation":  definitions.LuaLiteralString,
		"dn":         definitions.LuaLiteralString,
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

// setDefaultPoolName sets a default pool name if the "pool_name" field in the provided map is an empty string.
func setDefaultPoolName(fieldValues map[string]lua.LValue) {
	if fieldValues["pool_name"].String() == "default" {
		fieldValues["pool_name"] = lua.LString(definitions.DefaultBackendName)
	}
}

// validateField checks if a given field exists in a Lua table and validates its type, raising an error if invalid.
// L represents the Lua state, table is the Lua table, fieldName is the field to verify, and fieldType is the expected data type.
// Returns true if the field exists and matches the expected type, otherwise returns false.
func validateField(L *lua.LState, table *lua.LTable, fieldName string, fieldType string) bool {
	lv := L.GetField(table, fieldName)

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
func createLDAPRequest(L *lua.LState, fieldValues map[string]lua.LValue, ctx context.Context, command definitions.LDAPCommand) *bktype.LDAPRequest {
	var (
		basedn           string
		filter           string
		operation        string
		dn               string
		searchAttributes []string
		subCommand       definitions.LDAPSubCommand
		modifyAttributes bktype.LDAPModifyAttributes
	)

	scope := &config.LDAPScope{}

	guid := fieldValues["session"].String()
	attrTable := fieldValues["attributes"].(*lua.LTable)

	switch command {
	case definitions.LDAPSearch:
		basedn = fieldValues["basedn"].String()
		filter = fieldValues["filter"].String()

		if ldapScope, err := convertScopeStringToLDAP(fieldValues["scope"].String()); err != nil {
			L.RaiseError("%s", err.Error())

			return nil
		} else {
			scope = ldapScope
		}

		searchAttributes = extractAttributes(attrTable)
	case definitions.LDAPModify:
		dn = fieldValues["dn"].String()
		operation = fieldValues["operation"].String()

		switch operation {
		case "add":
			subCommand = definitions.LDAPModifyAdd
		case "delete":
			subCommand = definitions.LDAPModifyDelete
		case "replace":
			subCommand = definitions.LDAPModifyReplace
		default:
			L.RaiseError("unknown operation %s", operation)

			return nil
		}

		modifyAttributes = make(bktype.LDAPModifyAttributes)
		attrTable.ForEach(func(key lua.LValue, value lua.LValue) {
			modifyAttributes[key.String()] = []string{value.String()}
		})
	}

	ldapReplyChan := make(chan *bktype.LDAPReply)

	poolName := fieldValues["pool_name"].String()

	ldapRequest := &bktype.LDAPRequest{
		// Common fields
		GUID:              guid,
		RequestID:         "",
		PoolName:          poolName,
		LDAPReplyChan:     ldapReplyChan,
		HTTPClientContext: ctx,

		// Search
		Filter:           filter,
		BaseDN:           basedn,
		Scope:            *scope,
		Command:          command,
		SubCommand:       subCommand,
		SearchAttributes: searchAttributes,

		// Modify
		ModifyDN:         dn,
		ModifyAttributes: modifyAttributes,
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
// If raw_result is true, it returns the raw LDAP entries instead of the processed result.
//
// It is context-aware to avoid hanging the caller indefinitely.
func processReply(ctx context.Context, L *lua.LState, ldapReplyChan chan *bktype.LDAPReply) int {
	var ldapReply *bktype.LDAPReply

	_, span := trLua.Start(ctx, "ldap.lua.search.wait")
	defer span.End()

	select {
	case <-ctx.Done():
		L.Push(lua.LNil)
		L.Push(lua.LString(ctx.Err().Error()))

		return 2
	case ldapReply = <-ldapReplyChan:
	}

	// Check if there is an error. If so, return it.
	if ldapReply.Err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(ldapReply.Err.Error()))

		return 2
	}

	// Get the raw_result parameter from the first argument (table)
	table := L.CheckTable(1)
	rawResultValue := L.GetField(table, "raw_result")
	rawResult := rawResultValue != lua.LNil && rawResultValue.(lua.LBool) == lua.LTrue

	if rawResult && len(ldapReply.RawResult) > 0 {
		// Convert raw LDAP entries to Lua table
		rawResultTable := L.NewTable()

		for i, entry := range ldapReply.RawResult {
			entryTable := L.NewTable()

			// Add DN
			entryTable.RawSetString("dn", convert.GoToLuaValue(L, entry.DN))

			// Add attributes
			attributesTable := L.NewTable()
			for _, attr := range entry.Attributes {
				attrValuesTable := L.NewTable()
				for _, val := range attr.Values {
					attrValuesTable.Append(convert.GoToLuaValue(L, val))
				}

				attributesTable.RawSetString(attr.Name, attrValuesTable)
			}

			entryTable.RawSetString("attributes", attributesTable)

			rawResultTable.RawSetInt(i+1, entryTable)
		}

		L.Push(rawResultTable)

		return 1
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
