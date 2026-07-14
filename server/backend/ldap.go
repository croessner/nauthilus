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
	"strings"
	"sync"

	"github.com/croessner/nauthilus/v3/server/backend/bktype"
	"github.com/croessner/nauthilus/v3/server/backend/ldappool"
	"github.com/croessner/nauthilus/v3/server/backend/priorityqueue"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/log/level"
	"github.com/croessner/nauthilus/v3/server/lualib"
	"github.com/croessner/nauthilus/v3/server/lualib/convert"
	monittrace "github.com/croessner/nauthilus/v3/server/monitoring/trace"
	"github.com/go-ldap/ldap/v3"
	"github.com/yuin/gopher-lua"
	"go.opentelemetry.io/otel/attribute"
)

var (
	trOps = monittrace.New("nauthilus/ldap_ops")
	trLua = monittrace.New("nauthilus/ldap_lua")
)

const (
	luaLDAPFieldAttributes  = "attributes"
	luaLDAPFieldAllowedBase = "allowed_base_dn"
	luaLDAPFieldBaseDN      = "basedn"
	luaLDAPFieldFilter      = "filter"
	luaLDAPFieldFilterAttr  = "filter_attr"
	luaLDAPFieldFilterValue = "filter_value"
	luaLDAPFieldTrusted     = "trusted"
	luaLDAPFieldPoolName    = "pool_name"
	luaLDAPFieldSession     = "session"
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

	if err := ldapPool.SetIdleConnections(true); err != nil {
		level.Error(logger).Log(definitions.LogKeyMsg, "Failed to initialize LDAP lookup idle connections", definitions.LogKeyLDAPPoolName, poolName, definitions.LogKeyError, err)

		return
	}

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
		popRequest: lookupPopRequest(ctx, queue, ldapPool, poolName),
		doneChan:   channel.GetLdapChannel().GetLookupEndChan(poolName),
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

	if err := ldapPool.SetIdleConnections(false); err != nil {
		level.Error(logger).Log(definitions.LogKeyMsg, "Failed to initialize LDAP auth idle connections", definitions.LogKeyLDAPPoolName, poolName, definitions.LogKeyError, err)

		return
	}

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
		popRequest: authPopRequest(ctx, authQueue, ldapPool, poolName),
		doneChan:   channel.GetLdapChannel().GetAuthEndChan(poolName),
	})
}

// ldapWorkerCallbacks holds the per-worker-type callbacks for runLDAPWorkerLoop.
type ldapWorkerCallbacks struct {
	// popRequest pops the next request from the queue and returns its fields.
	// A nil handle return signals the queue is closed.
	popRequest ldapPopRequestFunc
	doneChan   chan bktype.Done
	spanName   string
	idleExpand bool
}

// ldapPopRequestFunc adapts queue-specific LDAP requests for the shared worker loop.
type ldapPopRequestFunc func() (guid string, httpCtx context.Context, replyChan chan *bktype.LDAPReply, handle func() error)

// lookupPopRequest adapts lookup queue items for the shared worker loop.
func lookupPopRequest(ctx context.Context, queue LDAPQueue, pool ldappool.LDAPPool, poolName string) ldapPopRequestFunc {
	return typedLDAPPopRequest(func() *bktype.LDAPRequest {
		return queue.PopWithContext(ctx, poolName)
	}, pool.HandleLookupRequest)
}

// authPopRequest adapts authentication queue items for the shared worker loop.
func authPopRequest(ctx context.Context, queue LDAPAuthQueue, pool ldappool.LDAPPool, poolName string) ldapPopRequestFunc {
	return typedLDAPPopRequest(func() *bktype.LDAPAuthRequest {
		return queue.PopWithContext(ctx, poolName)
	}, pool.HandleAuthRequest)
}

type ldapQueueRequest interface {
	bktype.LDAPRequest | bktype.LDAPAuthRequest
}

type ldapRequestFields struct {
	httpCtx   context.Context
	replyChan chan *bktype.LDAPReply
	handle    func() error
	guid      string
}

// typedLDAPPopRequest adapts concrete LDAP queue requests to the shared worker-loop callback shape.
func typedLDAPPopRequest[T ldapQueueRequest](pop func() *T, handleRequest func(*T) error) ldapPopRequestFunc {
	return func() (guid string, httpCtx context.Context, replyChan chan *bktype.LDAPReply, dispatch func() error) {
		req := pop()
		if req == nil {
			return "", nil, nil, nil
		}

		fields := ldapRequestFieldsFrom(req, handleRequest)

		return fields.guid, fields.httpCtx, fields.replyChan, fields.handle
	}
}

// ldapRequestFieldsFrom extracts worker-loop fields from the supported LDAP request variants.
func ldapRequestFieldsFrom[T ldapQueueRequest](req *T, handle func(*T) error) ldapRequestFields {
	switch typed := any(req).(type) {
	case *bktype.LDAPRequest:
		return ldapRequestFieldsFor(typed.HTTPClientContext, typed.GUID, typed.LDAPReplyChan, func() error {
			return handle(req)
		})
	case *bktype.LDAPAuthRequest:
		return ldapRequestFieldsFor(typed.HTTPClientContext, typed.GUID, typed.LDAPReplyChan, func() error {
			return handle(req)
		})
	default:
		return ldapRequestFields{}
	}
}

// ldapRequestFieldsFor groups the common request fields used by LDAP worker dispatch.
func ldapRequestFieldsFor(httpCtx context.Context, guid string, replyChan chan *bktype.LDAPReply, handle func() error) ldapRequestFields {
	return ldapRequestFields{
		httpCtx:   httpCtx,
		replyChan: replyChan,
		handle:    handle,
		guid:      guid,
	}
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
		if err = scope.Set("sub"); err != nil {
			return nil, fmt.Errorf("LDAP scope not detected: sub")
		}
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
		_ = ctx

		callCtx := lualib.RequireRuntimeContext(L, definitions.LuaModLDAP)
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
		ldapRequest := createLDAPRequest(trCtx, L, fieldValues, definitions.LDAPSearch)

		pSpan.End()

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
		_ = ctx

		callCtx, cancel := luaLDAPRuntimeContext(L)
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
		ldapRequest := createLDAPRequest(trCtx, L, fieldValues, definitions.LDAPModify)

		pSpan.End()

		enqueueLuaLDAPRequest(trCtx, "ldap.lua.modify.enqueue", ldapRequest)

		return processModifyReply(trCtx, L, ldapRequest.GetLDAPReplyChan())
	}
}

// luaLDAPRuntimeContext returns the request context used by Lua LDAP operations.
func luaLDAPRuntimeContext(L *lua.LState) (context.Context, context.CancelFunc) {
	callCtx := lualib.RequireRuntimeContext(L, definitions.LuaModLDAP)
	cancel := func() {}

	if callCtx != nil {
		if _, has := callCtx.Deadline(); !has {
			callCtx, cancel = context.WithTimeout(callCtx, definitions.LuaLDAPReplyTimeout)
		}
	}

	return callCtx, cancel
}

// enqueueLuaLDAPRequest pushes a Lua LDAP request into the low-priority queue with tracing.
func enqueueLuaLDAPRequest(ctx context.Context, spanName string, ldapRequest *bktype.LDAPRequest) {
	_, qSpan := trLua.Start(ctx, spanName)

	luaLDAPQueue.Push(ldapRequest, priorityqueue.PriorityLow)
	qSpan.End()
}

// processModifyReply waits for a modify reply and pushes the Lua result tuple.
func processModifyReply(ctx context.Context, L *lua.LState, ldapReplyChan chan *bktype.LDAPReply) int {
	ldapReply, ok := waitLDAPReply(ctx, L, ldapReplyChan, "ldap.lua.modify.wait")
	if !ok {
		return 2
	}

	if ldapReply.Err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(ldapReply.Err.Error()))

		return 2
	}

	L.Push(lua.LString("OK"))

	return 1
}

// prepareAndValidateSearchFields validates and retrieves expected fields from a Lua table, returning a map of field values.
// Fields are matched against a predefined set of expected names and types, raising an error if a field is missing or invalid.
// It also accepts an optional "raw_result" boolean field to indicate if the raw LDAP result should be returned.
func prepareAndValidateSearchFields(L *lua.LState, table *lua.LTable) map[string]lua.LValue {
	expectedFields := map[string]string{
		luaLDAPFieldPoolName:   definitions.LuaLiteralString,
		luaLDAPFieldSession:    definitions.LuaLiteralString,
		luaLDAPFieldBaseDN:     definitions.LuaLiteralString,
		"scope":                definitions.LuaLiteralString,
		luaLDAPFieldAttributes: definitions.LuaLiteralTable,
	}

	fieldValues := make(map[string]lua.LValue)

	for field, typeExpected := range expectedFields {
		if !validateField(L, table, field, typeExpected) {
			return nil
		}

		fieldValues[field] = L.GetField(table, field)
	}

	if !collectOptionalLDAPStringFields(L, table, fieldValues,
		luaLDAPFieldFilter,
		luaLDAPFieldFilterAttr,
		luaLDAPFieldFilterValue,
		luaLDAPFieldAllowedBase,
	) {
		return nil
	}

	if !collectOptionalLDAPBoolField(L, table, fieldValues, luaLDAPFieldTrusted) {
		return nil
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
		luaLDAPFieldPoolName:   definitions.LuaLiteralString,
		luaLDAPFieldSession:    definitions.LuaLiteralString,
		"operation":            definitions.LuaLiteralString,
		"dn":                   definitions.LuaLiteralString,
		luaLDAPFieldAttributes: definitions.LuaLiteralTable,
	}

	fieldValues := make(map[string]lua.LValue)

	for field, typeExpected := range expectedFields {
		if !validateField(L, table, field, typeExpected) {
			return nil
		}

		fieldValues[field] = L.GetField(table, field)
	}

	if !collectOptionalLDAPStringFields(L, table, fieldValues, luaLDAPFieldAllowedBase) {
		return nil
	}

	if !collectOptionalLDAPBoolField(L, table, fieldValues, luaLDAPFieldTrusted) {
		return nil
	}

	return fieldValues
}

// collectOptionalLDAPStringFields validates optional LDAP string fields.
func collectOptionalLDAPStringFields(L *lua.LState, table *lua.LTable, fieldValues map[string]lua.LValue, fields ...string) bool {
	for _, field := range fields {
		value := L.GetField(table, field)
		if value == lua.LNil {
			continue
		}

		if _, ok := value.(lua.LString); !ok {
			L.RaiseError("%s should be a string", field)

			return false
		}

		fieldValues[field] = value
	}

	return true
}

// collectOptionalLDAPBoolField validates one optional LDAP boolean field.
func collectOptionalLDAPBoolField(L *lua.LState, table *lua.LTable, fieldValues map[string]lua.LValue, field string) bool {
	value := L.GetField(table, field)
	if value == lua.LNil {
		return true
	}

	if _, ok := value.(lua.LBool); !ok {
		L.RaiseError("%s should be a boolean", field)

		return false
	}

	fieldValues[field] = value

	return true
}

// setDefaultPoolName maps public LDAP pool aliases to worker pool names.
func setDefaultPoolName(fieldValues map[string]lua.LValue) {
	fieldValues[luaLDAPFieldPoolName] = lua.LString(LDAPWorkerPoolName(fieldValues[luaLDAPFieldPoolName].String()))
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
func createLDAPRequest(ctx context.Context, L *lua.LState, fieldValues map[string]lua.LValue, command definitions.LDAPCommand) *bktype.LDAPRequest {
	ldapRequest := newBaseLDAPRequest(ctx, fieldValues, command)

	switch command {
	case definitions.LDAPSearch:
		if !applyLDAPSearchRequestFields(L, ldapRequest, fieldValues) {
			return nil
		}
	case definitions.LDAPModify:
		if !applyLDAPModifyRequestFields(L, ldapRequest, fieldValues) {
			return nil
		}
	}

	return ldapRequest
}

// newBaseLDAPRequest creates the common request fields for LDAP search and modify operations.
func newBaseLDAPRequest(ctx context.Context, fieldValues map[string]lua.LValue, command definitions.LDAPCommand) *bktype.LDAPRequest {
	return &bktype.LDAPRequest{
		GUID:              fieldValues["session"].String(),
		RequestID:         "",
		PoolName:          fieldValues["pool_name"].String(),
		LDAPReplyChan:     make(chan *bktype.LDAPReply),
		HTTPClientContext: ctx,
		Command:           command,
	}
}

// applyLDAPSearchRequestFields fills search-specific request fields.
func applyLDAPSearchRequestFields(L *lua.LState, ldapRequest *bktype.LDAPRequest, fieldValues map[string]lua.LValue) bool {
	ldapScope, err := convertScopeStringToLDAP(fieldValues["scope"].String())
	if err != nil {
		L.RaiseError("%s", err.Error())

		return false
	}

	ldapRequest.BaseDN = fieldValues["basedn"].String()
	if err := enforceLuaLDAPSubtree(ldapRequest.BaseDN, luaStringField(fieldValues, luaLDAPFieldAllowedBase), luaBoolField(fieldValues, luaLDAPFieldTrusted)); err != nil {
		L.RaiseError("%s", err.Error())

		return false
	}

	filter, err := buildLuaLDAPSearchFilter(fieldValues)
	if err != nil {
		L.RaiseError("%s", err.Error())

		return false
	}

	ldapRequest.Filter = filter
	ldapRequest.Scope = *ldapScope
	ldapRequest.SearchAttributes = extractAttributes(fieldValues["attributes"].(*lua.LTable))

	return true
}

// applyLDAPModifyRequestFields fills modify-specific request fields.
func applyLDAPModifyRequestFields(L *lua.LState, ldapRequest *bktype.LDAPRequest, fieldValues map[string]lua.LValue) bool {
	subCommand, ok := ldapModifySubCommand(L, fieldValues["operation"].String())
	if !ok {
		return false
	}

	ldapRequest.ModifyDN = fieldValues["dn"].String()
	if err := enforceLuaLDAPSubtree(ldapRequest.ModifyDN, luaStringField(fieldValues, luaLDAPFieldAllowedBase), luaBoolField(fieldValues, luaLDAPFieldTrusted)); err != nil {
		L.RaiseError("%s", err.Error())

		return false
	}

	ldapRequest.SubCommand = subCommand
	ldapRequest.ModifyAttributes = extractModifyAttributes(fieldValues["attributes"].(*lua.LTable))

	return true
}

// buildLuaLDAPSearchFilter returns a trusted raw filter or a safely escaped equality filter.
func buildLuaLDAPSearchFilter(fieldValues map[string]lua.LValue) (string, error) {
	if rawFilter := luaStringField(fieldValues, luaLDAPFieldFilter); rawFilter != "" {
		if !luaBoolField(fieldValues, luaLDAPFieldTrusted) {
			return "", fmt.Errorf("raw LDAP filter requires trusted=true")
		}

		return rawFilter, nil
	}

	attribute := luaStringField(fieldValues, luaLDAPFieldFilterAttr)
	if !isSafeLDAPAttributeName(attribute) {
		return "", fmt.Errorf("filter_attr must be a safe LDAP attribute name")
	}

	return fmt.Sprintf("(%s=%s)", attribute, ldap.EscapeFilter(luaStringField(fieldValues, luaLDAPFieldFilterValue))), nil
}

// enforceLuaLDAPSubtree verifies that a Lua LDAP DN stays under its allowed subtree.
func enforceLuaLDAPSubtree(candidateDN, allowedBaseDN string, trusted bool) error {
	if strings.TrimSpace(allowedBaseDN) == "" {
		if trusted {
			return nil
		}

		return fmt.Errorf("allowed_base_dn is required for untrusted LDAP operations")
	}

	candidate, err := ldap.ParseDN(candidateDN)
	if err != nil {
		return fmt.Errorf("invalid LDAP DN: %w", err)
	}

	allowed, err := ldap.ParseDN(allowedBaseDN)
	if err != nil {
		return fmt.Errorf("invalid allowed_base_dn: %w", err)
	}

	if allowed.EqualFold(candidate) || allowed.AncestorOfFold(candidate) {
		return nil
	}

	return fmt.Errorf("LDAP DN is outside allowed_base_dn")
}

// isSafeLDAPAttributeName accepts conservative LDAP attribute names and options.
func isSafeLDAPAttributeName(attribute string) bool {
	if attribute == "" {
		return false
	}

	parts := strings.Split(attribute, ";")
	if len(parts) == 0 || !isLDAPAttributeDescriptionPart(parts[0], true) {
		return false
	}

	for _, part := range parts[1:] {
		if !isLDAPAttributeDescriptionPart(part, false) {
			return false
		}
	}

	return true
}

// isLDAPAttributeDescriptionPart validates one LDAP attribute description segment.
func isLDAPAttributeDescriptionPart(part string, requireLeadingAlpha bool) bool {
	if part == "" {
		return false
	}

	for index, char := range part {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' {
			continue
		}

		if index == 0 && requireLeadingAlpha {
			return false
		}

		if char >= '0' && char <= '9' || char == '-' {
			continue
		}

		return false
	}

	return true
}

// luaStringField returns the optional string value for a prepared Lua LDAP field.
func luaStringField(fieldValues map[string]lua.LValue, field string) string {
	value, ok := fieldValues[field]
	if !ok || value == lua.LNil {
		return ""
	}

	return value.String()
}

// luaBoolField returns the optional boolean value for a prepared Lua LDAP field.
func luaBoolField(fieldValues map[string]lua.LValue, field string) bool {
	value, ok := fieldValues[field].(lua.LBool)
	if !ok {
		return false
	}

	return bool(value)
}

// ldapModifySubCommand maps Lua modify operations to backend subcommands.
func ldapModifySubCommand(L *lua.LState, operation string) (definitions.LDAPSubCommand, bool) {
	switch operation {
	case "add":
		return definitions.LDAPModifyAdd, true
	case "delete":
		return definitions.LDAPModifyDelete, true
	case "replace":
		return definitions.LDAPModifyReplace, true
	default:
		L.RaiseError("unknown operation %s", operation)

		return definitions.LDAPModifyUnknown, false
	}
}

// extractModifyAttributes converts a Lua attribute table into LDAP modify attributes.
func extractModifyAttributes(attrTable *lua.LTable) bktype.LDAPModifyAttributes {
	modifyAttributes := make(bktype.LDAPModifyAttributes)

	attrTable.ForEach(func(key lua.LValue, value lua.LValue) {
		modifyAttributes[key.String()] = []string{value.String()}
	})

	return modifyAttributes
}

// extractAttributes extracts string attributes from a Lua table and returns them as a slice of strings.
func extractAttributes(attrTable *lua.LTable) []string {
	attributes := make([]string, 0, attrTable.Len())
	attrTable.ForEach(func(_ lua.LValue, value lua.LValue) {
		attributes = append(attributes, value.String())
	})

	return attributes
}

// processReply processes an LDAP reply received from a channel and converts it into a Lua-compatible value or error.
// If raw_result is true, it returns the raw LDAP entries instead of the processed result.
//
// It is context-aware to avoid hanging the caller indefinitely.
func processReply(ctx context.Context, L *lua.LState, ldapReplyChan chan *bktype.LDAPReply) int {
	ldapReply, ok := waitLDAPReply(ctx, L, ldapReplyChan, "ldap.lua.search.wait")
	if !ok {
		return 2
	}

	if ldapReply.Err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(ldapReply.Err.Error()))

		return 2
	}

	if rawResultRequested(L) && len(ldapReply.RawResult) > 0 {
		L.Push(rawLDAPEntriesToLuaTable(L, ldapReply.RawResult))

		return 1
	}

	return pushLDAPAttributeResult(L, ldapReply)
}

// waitLDAPReply waits for an LDAP reply or pushes the context error tuple.
func waitLDAPReply(ctx context.Context, L *lua.LState, ldapReplyChan chan *bktype.LDAPReply, spanName string) (*bktype.LDAPReply, bool) {
	_, span := trLua.Start(ctx, spanName)
	defer span.End()

	select {
	case <-ctx.Done():
		L.Push(lua.LNil)
		L.Push(lua.LString(ctx.Err().Error()))

		return nil, false
	case ldapReply := <-ldapReplyChan:
		return ldapReply, true
	}
}

// rawResultRequested reads the raw_result flag from the current Lua call table.
func rawResultRequested(L *lua.LState) bool {
	rawResultValue := L.GetField(L.CheckTable(1), "raw_result")

	return rawResultValue != lua.LNil && rawResultValue.(lua.LBool) == lua.LTrue
}

// rawLDAPEntriesToLuaTable converts raw LDAP entries into a Lua table.
func rawLDAPEntriesToLuaTable(L *lua.LState, entries []*ldap.Entry) *lua.LTable {
	rawResultTable := L.NewTable()

	for i, entry := range entries {
		rawResultTable.RawSetInt(i+1, rawLDAPEntryToLuaTable(L, entry))
	}

	return rawResultTable
}

// rawLDAPEntryToLuaTable converts one raw LDAP entry into a Lua table.
func rawLDAPEntryToLuaTable(L *lua.LState, entry *ldap.Entry) *lua.LTable {
	entryTable := L.NewTable()
	entryTable.RawSetString("dn", convert.GoToLuaValue(L, entry.DN))
	entryTable.RawSetString("attributes", rawLDAPAttributesToLuaTable(L, entry.Attributes))

	return entryTable
}

// rawLDAPAttributesToLuaTable converts LDAP entry attributes into a Lua table.
func rawLDAPAttributesToLuaTable(L *lua.LState, attributes []*ldap.EntryAttribute) *lua.LTable {
	attributesTable := L.NewTable()
	for _, attr := range attributes {
		attrValuesTable := L.NewTable()
		for _, val := range attr.Values {
			attrValuesTable.Append(convert.GoToLuaValue(L, val))
		}

		attributesTable.RawSetString(attr.Name, attrValuesTable)
	}

	return attributesTable
}

// pushLDAPAttributeResult converts AttributeMapping into a Lua table and pushes it.
func pushLDAPAttributeResult(L *lua.LState, ldapReply *bktype.LDAPReply) int {
	convertedMap := make(map[any]any)
	for key, values := range ldapReply.Result {
		list := make([]any, len(values))

		copy(list, values)

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
