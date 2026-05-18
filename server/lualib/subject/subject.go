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

// Package subject executes Lua subject source scripts.
package subject

import (
	"context"
	stderrs "errors"
	"fmt"
	"log/slog"
	"maps"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/lualib"
	bflib "github.com/croessner/nauthilus/server/lualib/bruteforce"
	"github.com/croessner/nauthilus/server/lualib/connmgr"
	"github.com/croessner/nauthilus/server/lualib/luapool"
	"github.com/croessner/nauthilus/server/lualib/luastack"
	"github.com/croessner/nauthilus/server/lualib/pipeline"
	"github.com/croessner/nauthilus/server/lualib/policyschedule"
	"github.com/croessner/nauthilus/server/lualib/redislib"
	"github.com/croessner/nauthilus/server/lualib/vmpool"
	"github.com/croessner/nauthilus/server/monitoring"
	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/croessner/nauthilus/server/policy"
	policycollection "github.com/croessner/nauthilus/server/policy/collection"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/svcctx"
	"github.com/croessner/nauthilus/server/util"

	"github.com/gin-gonic/gin"
	lua "github.com/yuin/gopher-lua"
	"go.opentelemetry.io/otel/attribute"
	"golang.org/x/sync/errgroup"
)

// LuaSubjectSources holds pre-compiled Lua scripts for use across the application.
// It allows faster access and execution of frequently used scripts.
var LuaSubjectSources *PreCompiledLuaSubjectSources

// BackendManager manages backend operations for Lua subject sources.
type BackendManager struct {
	*lualib.BaseManager
	request                 *Request
	backendResult           **lualib.LuaBackendResult
	removeAttributes        *[]string
	currentBackendResult    *lualib.LuaBackendResult
	currentRemoveAttributes []string
}

// NewBackendManager creates a new BackendManager.
func NewBackendManager(ctx context.Context, cfg config.File, logger *slog.Logger, request *Request, backendResult **lualib.LuaBackendResult, removeAttributes *[]string) *BackendManager {
	return NewBackendManagerWithCurrent(ctx, cfg, logger, request, backendResult, removeAttributes, nil, nil)
}

// NewBackendManagerWithCurrent creates a new BackendManager with cumulative input snapshots.
func NewBackendManagerWithCurrent(ctx context.Context, cfg config.File, logger *slog.Logger, request *Request, backendResult **lualib.LuaBackendResult, removeAttributes *[]string, currentBackendResult *lualib.LuaBackendResult, currentRemoveAttributes []string) *BackendManager {
	return &BackendManager{
		BaseManager:             lualib.NewBaseManager(ctx, cfg, logger),
		request:                 request,
		backendResult:           backendResult,
		removeAttributes:        removeAttributes,
		currentBackendResult:    cloneLuaBackendResult(currentBackendResult),
		currentRemoveAttributes: append([]string(nil), currentRemoveAttributes...),
	}
}

func bindSubjectModuleIntoReq(L *lua.LState, moduleName string, loader lua.LGFunction) {
	if loader == nil {
		return
	}

	_ = loader(L)

	if mod, ok := L.Get(-1).(*lua.LTable); ok {
		L.Pop(1)
		luapool.BindModuleIntoReq(L, moduleName, mod)

		return
	}

	L.Pop(1)
}

// LoaderModBackend initializes and returns a Lua module containing backend-related functionalities for LuaState.
func LoaderModBackend(ctx context.Context, cfg config.File, logger *slog.Logger, request *Request, backendResult **lualib.LuaBackendResult, removeAttributes *[]string) lua.LGFunction {
	return LoaderModBackendWithCurrent(ctx, cfg, logger, request, backendResult, removeAttributes, nil, nil)
}

// LoaderModBackendWithCurrent initializes the backend module with cumulative input snapshots.
func LoaderModBackendWithCurrent(ctx context.Context, cfg config.File, logger *slog.Logger, request *Request, backendResult **lualib.LuaBackendResult, removeAttributes *[]string, currentBackendResult *lualib.LuaBackendResult, currentRemoveAttributes []string) lua.LGFunction {
	return func(L *lua.LState) int {
		stack := luastack.NewManager(L)
		manager := NewBackendManagerWithCurrent(ctx, cfg, logger, request, backendResult, removeAttributes, currentBackendResult, currentRemoveAttributes)

		mod := L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{
			definitions.LuaFnGetBackendServers:           manager.getBackendServers,
			definitions.LuaFnSelectBackendServer:         manager.selectBackendServer,
			definitions.LuaFnGetCurrentBackendResult:     manager.getCurrentBackendResult,
			definitions.LuaFnGetSelectedBackendServer:    manager.getSelectedBackendServer,
			definitions.LuaFnCheckBackendConnection:      lualib.LoaderModConnection(ctx, cfg, logger, monitoring.NewMonitor(cfg, logger)),
			definitions.LuaFnApplyBackendResult:          manager.applyBackendResult,
			definitions.LuaFnRemoveFromBackendResult:     manager.removeFromBackendResult,
			definitions.LuaFnGetRemovedBackendAttributes: manager.getRemovedBackendAttributes,
		})

		return stack.PushResult(mod)
	}
}

// PreCompileLuaSubjectSources prepares and pre-compiles Lua subject sources based on the configuration, ensuring optimized subject source execution.
// Returns an error if pre-compilation fails or configuration is missing.
// Initializes or resets the global LuaSubjectSources container, adding compiled Lua subject sources sequentially.
func PreCompileLuaSubjectSources(cfgFile config.File) (err error) {
	tr := monittrace.New("nauthilus/subject")
	ctx, sp := tr.Start(svcctx.Get(), "subject_sources.precompile_all",
		attribute.Int("configured", func() int {
			if cfgFile.HaveLuaSubjectSources() {
				return len(cfgFile.GetLua().GetSubjectSources())
			}

			return 0
		}()),
	)

	_ = ctx

	defer sp.End()

	if cfgFile.HaveLuaSubjectSources() {
		if LuaSubjectSources == nil {
			LuaSubjectSources = &PreCompiledLuaSubjectSources{}
		} else {
			LuaSubjectSources.Reset()
		}

		sources := cfgFile.GetLua().GetSubjectSources()
		for index := range sources {
			var luaSubjectSource *LuaSubjectSource

			cfg := sources[index]

			luaSubjectSource, err = NewLuaSubjectSource(cfg.Name, cfg.ScriptPath)
			if err != nil {
				sp.RecordError(err)

				return err
			}

			LuaSubjectSources.Add(luaSubjectSource)
		}

		if err = LuaSubjectSources.RebuildPlans(); err != nil {
			sp.RecordError(err)

			return err
		}
	}

	return nil
}

// PreCompiledLuaSubjectSources represents a collection of precompiled Lua scripts
// along with a mutex for handling concurrent access to the script data.
type PreCompiledLuaSubjectSources struct {
	// LuaScripts is a slice of pointers to LuaSubjectSource,
	// each of which represents a precompiled Lua script.
	LuaScripts []*LuaSubjectSource

	// plans contains per-request-mode dependency plans built during precompile.
	plans pipeline.Plans

	// Mu is a read/write mutex used to allow safe concurrent access to the LuaScripts.
	Mu sync.RWMutex
}

// Add appends a LuaSubjectSource to the LuaScripts slice while ensuring thread-safe access using a mutex.
func (a *PreCompiledLuaSubjectSources) Add(luaSubjectSource *LuaSubjectSource) {
	a.Mu.Lock()

	defer a.Mu.Unlock()

	a.LuaScripts = append(a.LuaScripts, luaSubjectSource)
	a.plans = nil
}

// Reset clears the LuaScripts slice of a PreCompiledLuaSubjectSources object.The method also prevents race conditions
// by Locking the Mutex before executing, and Unlocking once it has finished. Existing entries in the slice are discarded.
func (a *PreCompiledLuaSubjectSources) Reset() {
	a.Mu.Lock()

	defer a.Mu.Unlock()

	a.LuaScripts = make([]*LuaSubjectSource, 0)
	a.plans = nil
}

// RebuildPlans validates all subject source dependencies and caches per-mode execution plans.
func (a *PreCompiledLuaSubjectSources) RebuildPlans() error {
	a.Mu.Lock()

	defer a.Mu.Unlock()

	plans, err := pipeline.BuildPlans(subjectPipelineNodes(a.LuaScripts))
	if err != nil {
		return err
	}

	a.plans = plans

	return nil
}

func (a *PreCompiledLuaSubjectSources) planForMode(mode pipeline.ModeMask) (pipeline.Plan, bool, error) {
	if a.plans != nil {
		if plan, ok := a.plans[mode]; ok {
			return plan, true, nil
		}
	}

	plan, err := pipeline.BuildPlan(subjectPipelineNodes(a.LuaScripts), mode)
	if err != nil {
		return pipeline.Plan{}, false, err
	}

	return plan, false, nil
}

// LuaSubjectSource represents a struct for managing Lua subject sources.
// It contains fields for subject source name and a compiled Lua script.
type LuaSubjectSource struct {
	// Name is a string that represents the name of the Lua subject source.
	Name string

	// CompiledScript is a pointer to a FunctionProto struct from the go-lua package.
	// It represents a compiled Lua function that can be executed by a Lua VM.
	CompiledScript *lua.FunctionProto

	Dependencies []string
	Modes        pipeline.ModeMask
}

// NewLuaSubjectSource creates a new LuaSubjectSource with the provided name and scriptPath by compiling the Lua script.
// Returns an error if the name or scriptPath is empty, or if there is a failure during script compilation.
func NewLuaSubjectSource(name string, scriptPath string) (*LuaSubjectSource, error) {
	if name == "" {
		return nil, errors.ErrSubjectSourceLuaNameMissing
	}

	if scriptPath == "" {
		return nil, errors.ErrSubjectSourceLuaScriptPathEmpty
	}

	compiledScript, err := lualib.CompileLua(scriptPath)
	if err != nil {
		return nil, err
	}

	return &LuaSubjectSource{
		Name:           name,
		CompiledScript: compiledScript,
		Modes:          pipeline.ModeAuthenticated | pipeline.ModeUnauthenticated,
	}, nil
}

func subjectPipelineNodes(sources []*LuaSubjectSource) []pipeline.Node {
	nodes := make([]pipeline.Node, 0, len(sources))

	for index, source := range sources {
		nodes = append(nodes, pipeline.Node{
			Name:      source.Name,
			DependsOn: append([]string(nil), source.Dependencies...),
			Index:     index,
			Modes:     source.Modes,
			Value:     source,
		})
	}

	return nodes
}

func requestSubjectMode(r *Request) pipeline.ModeMask {
	if r != nil && r.CommonRequest != nil && r.NoAuth {
		return pipeline.ModeNoAuth
	}

	if r != nil && r.CommonRequest != nil && r.Authenticated {
		return pipeline.ModeAuthenticated
	}

	return pipeline.ModeUnauthenticated
}

func cloneLuaBackendResult(source *lualib.LuaBackendResult) *lualib.LuaBackendResult {
	if source == nil {
		return &lualib.LuaBackendResult{Attributes: make(map[any]any)}
	}

	clone := *source
	clone.WebAuthnCredentials = append([]string(nil), source.WebAuthnCredentials...)
	clone.Groups = append([]string(nil), source.Groups...)
	clone.GroupDNs = append([]string(nil), source.GroupDNs...)

	if source.Attributes != nil {
		clone.Attributes = make(map[any]any, len(source.Attributes))
		maps.Copy(clone.Attributes, source.Attributes)
	} else {
		clone.Attributes = make(map[any]any)
	}

	return &clone
}

// Request represents a structure used for handling and processing requests within the system.
type Request struct {
	Session              string
	Username             string
	Password             []byte
	ClientIP             string
	AccountName          string
	AdditionalAttributes map[string]any

	// BackendServers holds a list of backend server configurations that are used for handling requests.
	BackendServers []*config.BackendServer

	// UsedBackendAddr indicates the specific backend server address selected for processing the current request.
	UsedBackendAddr *string

	// UsedBackendPort represents the port of the backend server that was used for the current request execution.
	UsedBackendPort *int

	// Log is used to capture logging information.
	Logs *lualib.CustomLogKeyValue

	// Context includes context data from the caller.
	*lualib.Context

	// CommonRequest represents a common request object with various properties used in different functionalities.
	*lualib.CommonRequest

	ScriptRecorder policycollection.ScriptRecorder
	PolicyContext  *policycollection.DecisionContext
}

// handleError logs Lua execution errors for subject sources with stacktrace when available,
// stops the running timer and cancels the Lua context to abort pending operations.
func (r *Request) handleError(logger *slog.Logger, luaCancel context.CancelFunc, diagnostics lualib.RuntimeCancellationDiagnostics, err error, scriptName string, stopTimer func()) {
	// Try to include Lua stacktrace for easier diagnostics
	if ae, ok := stderrs.AsType[*lua.ApiError](err); ok && ae != nil {
		keyvals := []any{
			definitions.LogKeyGUID, func() string {
				if r != nil && r.CommonRequest != nil {
					return r.CommonRequest.Session
				}

				return ""
			}(),
			"name", scriptName,
			definitions.LogKeyMsg, "Lua subject source failed",
			definitions.LogKeyError, ae.Error(),
			"stacktrace", ae.StackTrace,
		}

		if r != nil && r.CommonRequest != nil && r.HealthCheck {
			keyvals = append(keyvals, definitions.LogKeyHealthCheck, true)
		}

		keyvals = append(keyvals, diagnostics.LogValues()...)

		_ = level.Error(logger).Log(keyvals...)
	}

	if stopTimer != nil {
		stopTimer()
	}

	if luaCancel != nil {
		luaCancel()
	}
}

// The userData constellation method:
func newLuaBackendServer(userData *lua.LUserData) *config.BackendServer {
	if v, ok := userData.Value.(*config.BackendServer); ok {
		return v
	}

	return nil
}

// The metamethod for the __index field of the metatable
func indexMethod(L *lua.LState) int {
	stack := luastack.NewManager(L)

	userData := stack.CheckUserData(1)
	if userData == nil {
		stack.L.ArgError(1, "backend_server expected")

		return 0
	}

	field := stack.CheckString(2)

	server := newLuaBackendServer(userData)
	if server == nil {
		stack.L.ArgError(1, "backend_server expected")

		return 0
	}

	switch field {
	case "protocol":
		return stack.PushResult(lua.LString(server.Protocol))
	case "host":
		return stack.PushResult(lua.LString(server.Host))
	case "port":
		return stack.PushResult(lua.LNumber(server.Port))
	case "request_uri":
		return stack.PushResult(lua.LString(server.RequestURI))
	case "test_username":
		return stack.PushResult(lua.LString(server.TestUsername))
	case "test_password":
		return stack.PushResult(lua.LString(server.TestPassword))
	case "haproxy_v2":
		return stack.PushResult(lua.LBool(server.HAProxyV2))
	case "tls":
		return stack.PushResult(lua.LBool(server.TLS))
	case "tls_skip_verify":
		return stack.PushResult(lua.LBool(server.TLSSkipVerify))
	case "deep_check":
		return stack.PushResult(lua.LBool(server.DeepCheck))
	default:
		return 0 // The field does not exist
	}
}

// getBackendServers returns a table of backend server configurations as userdata.
func (m *BackendManager) getBackendServers(L *lua.LState) int {
	stack := luastack.NewManager(L)
	servers := L.NewTable()

	// Create the metatable
	mt := L.NewTypeMetatable(definitions.LuaBackendServerTypeName)

	L.SetField(mt, "__index", L.NewFunction(indexMethod))

	for _, backendServer := range m.request.BackendServers {
		if backendServer == nil {
			continue
		}

		// Create an userdata and set its metatable
		serverUserData := L.NewUserData()
		serverUserData.Value = backendServer

		L.SetMetatable(serverUserData, L.GetTypeMetatable(definitions.LuaBackendServerTypeName))

		// Add userdata into the servers table
		servers.Append(serverUserData)
	}

	return stack.PushResult(servers)
}

// selectBackendServer assigns a server address and port from Lua state arguments.
func (m *BackendManager) selectBackendServer(L *lua.LState) int {
	stack := luastack.NewManager(L)

	if stack.GetTop() != 2 {
		stack.L.ArgError(2, "expected server (string) and port (number)")

		return 0
	}

	serverValue := stack.CheckString(1)
	portValue := stack.CheckInt(2)

	if m.request.UsedBackendAddr != nil {
		*m.request.UsedBackendAddr = serverValue
	} else {
		m.request.UsedBackendAddr = &serverValue
	}

	if m.request.UsedBackendPort != nil {
		*m.request.UsedBackendPort = portValue
	} else {
		m.request.UsedBackendPort = &portValue
	}

	return 0
}

func (m *BackendManager) getCurrentBackendResult(L *lua.LState) int {
	stack := luastack.NewManager(L)
	userData := L.NewUserData()
	userData.Value = cloneLuaBackendResult(m.currentBackendResult)
	L.SetMetatable(userData, L.GetTypeMetatable(definitions.LuaBackendResultTypeName))

	return stack.PushResult(userData)
}

func (m *BackendManager) getSelectedBackendServer(L *lua.LState) int {
	stack := luastack.NewManager(L)

	if m.request == nil || m.request.UsedBackendAddr == nil || m.request.UsedBackendPort == nil {
		return stack.PushResults(lua.LNil, lua.LNil)
	}

	return stack.PushResults(lua.LString(*m.request.UsedBackendAddr), lua.LNumber(*m.request.UsedBackendPort))
}

// applyBackendResult merges attributes from the provided Lua userdata into the existing backendResult.
func (m *BackendManager) applyBackendResult(L *lua.LState) int {
	stack := luastack.NewManager(L)

	userData := stack.CheckUserData(1)
	if userData == nil {
		stack.L.ArgError(1, "lua backend_result expected")

		return 0
	}

	luaBackendResult, ok := userData.Value.(*lualib.LuaBackendResult)
	if !ok || luaBackendResult == nil {
		stack.L.ArgError(1, "lua backend_result expected")

		return 0
	}

	// Ensure destination exists
	if *m.backendResult == nil {
		*m.backendResult = &lualib.LuaBackendResult{
			Attributes: make(map[any]any),
			Groups:     []string{},
			GroupDNs:   []string{},
		}
	}

	if (*m.backendResult).Attributes == nil {
		(*m.backendResult).Attributes = make(map[any]any)
	}

	// Merge attributes (overwrite on conflict)
	maps.Copy((*m.backendResult).Attributes, luaBackendResult.Attributes)
	(*m.backendResult).Groups = mergeSortedUniqueStrings((*m.backendResult).Groups, luaBackendResult.Groups)
	(*m.backendResult).GroupDNs = mergeSortedUniqueStrings((*m.backendResult).GroupDNs, luaBackendResult.GroupDNs)

	return 0
}

// removeFromBackendResult populates a given slice with strings from a Lua table passed as an argument.
func (m *BackendManager) removeFromBackendResult(L *lua.LState) int {
	stack := luastack.NewManager(L)
	if m.removeAttributes == nil {
		return 0
	}

	attributeTable := stack.CheckTable(1)

	attributeTable.ForEach(func(_, value lua.LValue) {
		*m.removeAttributes = append(*m.removeAttributes, value.String())
	})

	return 0
}

func (m *BackendManager) getRemovedBackendAttributes(L *lua.LState) int {
	stack := luastack.NewManager(L)
	table := L.NewTable()

	for _, attribute := range m.currentRemoveAttributes {
		table.Append(lua.LString(attribute))
	}

	return stack.PushResult(table)
}

// mergeMaps merges 2 maps into one. If same key exists in both maps, value from m2 is used.
func mergeMaps(m1, m2 map[any]any) map[any]any {
	result := make(map[any]any)

	maps.Copy(result, m1)

	maps.Copy(result, m2)

	return result
}

func mergeSortedUniqueStrings(base []string, values ...[]string) []string {
	seen := make(map[string]struct{}, len(base))
	merged := make([]string, 0, len(base))

	for _, value := range base {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}

		if _, ok := seen[trimmed]; ok {
			continue
		}

		seen[trimmed] = struct{}{}
		merged = append(merged, trimmed)
	}

	for _, list := range values {
		for _, value := range list {
			trimmed := strings.TrimSpace(value)
			if trimmed == "" {
				continue
			}

			if _, ok := seen[trimmed]; ok {
				continue
			}

			seen[trimmed] = struct{}{}
			merged = append(merged, trimmed)
		}
	}

	sort.Strings(merged)

	return merged
}

// CallSubjectLua executes Lua subject source scripts in parallel. It merges backend results and remove-attributes
// from all subject sources, returns action=true if any subject source requested action, and returns the first error if any.
//
//nolint:gocyclo,funlen
func (r *Request) CallSubjectLua(ctx *gin.Context, cfg config.File, logger *slog.Logger, redisClient rediscli.Client) (action bool, backendResult *lualib.LuaBackendResult, removeAttributes []string, err error) {
	tr := monittrace.New("nauthilus/subject")
	fctx, fsp := tr.Start(ctx.Request.Context(), "subject_sources.call",
		attribute.String("service", func() string {
			if r != nil && r.CommonRequest != nil {
				return r.Service
			}

			return ""
		}()),
		attribute.String("username", func() string {
			if r != nil && r.CommonRequest != nil {
				return r.Username
			}

			return ""
		}()),
		attribute.Int("subject_sources", func() int {
			if LuaSubjectSources != nil {
				return len(LuaSubjectSources.LuaScripts)
			}

			return 0
		}()),
	)

	// propagate context for downstream
	ctx.Request = ctx.Request.WithContext(fctx)

	defer func() {
		fsp.SetAttributes(
			attribute.Bool("result", action),
			attribute.Int("removed_attrs", len(removeAttributes)),
		)

		if err != nil {
			fsp.RecordError(err)
		}

		fsp.End()
	}()

	startTime := time.Now()

	defer func() {
		latency := time.Since(startTime)
		if r.Logs == nil {
			r.Logs = new(lualib.CustomLogKeyValue)
		}

		r.Logs.Set(definitions.LogKeySubjectLatency, util.FormatDurationMs(latency))
	}()

	if LuaSubjectSources == nil || len(LuaSubjectSources.LuaScripts) == 0 {
		return false, nil, nil, errors.ErrNoSubjectSourcesDefined
	}

	LuaSubjectSources.Mu.RLock()
	defer LuaSubjectSources.Mu.RUnlock()

	modeMask := requestSubjectMode(r)
	mode := subjectModeText(modeMask)
	authState := requestPolicyAuthState(r)
	scriptPlan := policySubjectScriptPlan(r, authState)
	runnable := countSubjectSourcesForMode(LuaSubjectSources.LuaScripts, modeMask)
	if scriptPlan.Configured {
		runnable = len(scriptPlan.Schedules)
	}

	// Trace selection of applicable subject sources for the current mode
	sctx, selSpan := tr.Start(fctx, "subject_sources.select_applicable")
	_ = sctx

	selSpan.SetAttributes(
		attribute.String("mode", mode),
		attribute.Int("configured_total", len(LuaSubjectSources.LuaScripts)),
		attribute.Int("runnable", runnable),
		attribute.Bool("policy_schedule", scriptPlan.Configured),
	)
	selSpan.End()

	if r.Logs == nil {
		r.Logs = new(lualib.CustomLogKeyValue)
	}

	r.Logs.Set("subject_mode", mode)

	if r.Context == nil {
		r.Context = lualib.NewContext()
	}

	// Structure to collect per-subject-source results
	type subjectResult struct {
		name            string
		scriptIdx       int
		action          bool
		ret             int
		logs            lualib.CustomLogKeyValue
		statusText      **string
		backendResult   *lualib.LuaBackendResult
		removeAttrsList []string
		selectedAddress *string
		selectedPort    *int
		selectedSet     bool
		contextDelta    lualib.ContextDelta
	}

	pctx, pspan := tr.Start(fctx, "subject_sources.plan.lookup")
	_ = pctx

	plan, cached, err := subjectPlanForScripts(scriptPlan, modeMask)
	plannedCount := pipeline.PlannedNodeCount(plan)
	pspan.SetAttributes(
		attribute.Bool("cached", cached),
		attribute.Int("levels", len(plan.Levels)),
		attribute.Int("scripts", plannedCount),
		attribute.String("mode", mode),
	)
	if err != nil {
		pspan.RecordError(err)
		pspan.End()

		return false, nil, nil, err
	}

	pspan.End()

	// If no scripts should run in this mode, return early with empty aggregates.
	if plannedCount == 0 {
		mergedBackendResult := &lualib.LuaBackendResult{
			Attributes: make(map[any]any),
			Groups:     []string{},
			GroupDNs:   []string{},
		}

		return false, mergedBackendResult, nil, nil
	}

	results := make([]*subjectResult, 0, plannedCount)

	pool := vmpool.GetManager().GetOrCreate("subject:default", vmpool.PoolOptions{MaxVMs: cfg.GetLuaSubjectSourceVMPoolSize(), Config: cfg})

	mergedBackendResult := &lualib.LuaBackendResult{
		Attributes: make(map[any]any),
		Groups:     []string{},
		GroupDNs:   []string{},
	}
	mergedRemoveAttributes := config.NewStringSet()

	var statusSet bool

	for levelIndex, level := range plan.Levels {
		var (
			mu           sync.Mutex
			levelResults = make([]*subjectResult, 0, len(level))
		)

		g, egCtx := errgroup.WithContext(fctx)

		pstartCtx, pstart := tr.Start(fctx, "subject_sources.parallel.start",
			attribute.Int("runnable", len(level)),
			attribute.Int("level", levelIndex),
			attribute.String("mode", mode),
		)
		_ = pstartCtx

		for _, planned := range level {
			idx := planned.Index
			sc := planned.Value.(*LuaSubjectSource)
			g.Go(func() error {
				scriptStarted := time.Now()
				// Per-script span
				sCtx, sSpan := tr.Start(fctx, "subject_sources.script",
					attribute.String("name", sc.Name),
					attribute.String("mode", mode),
					attribute.Int("level", levelIndex),
				)
				_ = sCtx
				scriptTrace := lualib.NewLuaScriptTrace(lualib.LuaScriptTraceOptions{
					Kind:       lualib.LuaScriptKindSubject,
					ScriptName: sc.Name,
					Mode:       mode,
					Level:      levelIndex,
				})

				// Per-subject-source state from bounded vmpool
				actx, asp := tr.Start(egCtx, "subject_sources.vm.acquire",
					attribute.String("name", sc.Name),
					attribute.String("mode", mode),
					attribute.Int("level", levelIndex),
				)
				Llocal, acqErr := pool.Acquire(actx)
				asp.End()

				if acqErr != nil {
					sSpan.RecordError(acqErr)
					sSpan.End()
					r.recordSubjectScriptResult(egCtx, sc.Name, false, "", time.Since(scriptStarted), acqErr)

					return acqErr
				}

				replaceVM := false
				defer func() {
					if r := recover(); r != nil {
						replaceVM = true
					}

					if replaceVM {
						pool.Replace(Llocal)
					} else {
						pool.Release(Llocal)
					}

					sSpan.End()
				}()

				localContext := r.Clone()
				contextBefore := localContext.Snapshot()

				// Local log and status to avoid races on r.Logs / r.StatusMessage
				localLogs := new(lualib.CustomLogKeyValue)
				var localStatus *string

				// Local backend result and remove-attributes that this subject source may set
				localBackendResult := cloneLuaBackendResult(mergedBackendResult)
				localRemoveAttrs := make([]string, 0)
				var localUsedBackendAddr *string
				var localUsedBackendPort *int

				if r.UsedBackendAddr != nil {
					addrValue := *r.UsedBackendAddr
					localUsedBackendAddr = &addrValue
				}

				if r.UsedBackendPort != nil {
					portValue := *r.UsedBackendPort
					localUsedBackendPort = &portValue
				}

				localRequest := *r
				localRequest.UsedBackendAddr = localUsedBackendAddr
				localRequest.UsedBackendPort = localUsedBackendPort
				localRequest.Context = localContext
				originalBackendAddrPtr := localRequest.UsedBackendAddr
				originalBackendPortPtr := localRequest.UsedBackendPort
				originalBackendAddrSet := localRequest.UsedBackendAddr != nil
				originalBackendPortSet := localRequest.UsedBackendPort != nil
				originalBackendAddrValue := ""
				originalBackendPortValue := 0

				if originalBackendAddrSet {
					originalBackendAddrValue = *localRequest.UsedBackendAddr
				}

				if originalBackendPortSet {
					originalBackendPortValue = *localRequest.UsedBackendPort
				}

				// Environment preparation span
				envCtx, envSpan := tr.Start(fctx, "subject_sources.env.prepare",
					attribute.String("name", sc.Name),
					attribute.String("mode", mode),
					attribute.Int("level", levelIndex),
				)
				_ = envCtx

				// 6) nauthilus_backend_result
				lualib.LoaderModBackendResult(ctx, cfg, logger)(Llocal)

				if mod, ok := Llocal.Get(-1).(*lua.LTable); ok {
					Llocal.Pop(1)
					Llocal.SetGlobal(definitions.LuaBackendResultTypeName, mod)
					luapool.BindModuleIntoReq(Llocal, definitions.LuaBackendResultTypeName, mod)
				} else {
					Llocal.Pop(1)
				}

				// Globals for this state
				lualib.SetBuiltinTableForSubject(
					Llocal,
					lualib.NewLoggingManager(ctx, cfg, logger, localLogs).AddCustomLog,
					&localStatus,
				)

				// Build request table
				request := Llocal.NewTable()

				localRequest.SetupRequest(Llocal, cfg, request)

				// Set local override fields from Request struct
				if r.Session != "" {
					request.RawSetString(definitions.LuaRequestSession, lua.LString(r.Session))
				}

				if r.Username != "" {
					request.RawSetString(definitions.LuaRequestUsername, lua.LString(r.Username))
				}

				if len(r.Password) > 0 {
					request.RawSetString(definitions.LuaRequestPassword, lua.LString(string(r.Password)))
				}

				if r.ClientIP != "" {
					request.RawSetString(definitions.LuaRequestClientIP, lua.LString(r.ClientIP))
				}

				if r.AccountName != "" {
					request.RawSetString(definitions.LuaRequestAccount, lua.LString(r.AccountName))
				}

				// Timing and context
				stopTimer := stats.PrometheusTimer(cfg, definitions.PromSubject, sc.Name, ctx.FullPath())

				luaCtx, luaCancel := context.WithTimeout(egCtx, cfg.GetServer().GetTimeouts().GetLuaScript())
				defer luaCancel()

				Llocal.SetContext(luaCtx)

				// Prepare per-request environment so that request-local globals and module bindings are visible
				_, mspan := tr.Start(envCtx, "subject_sources.env.modules",
					attribute.String("name", sc.Name),
					attribute.String("mode", mode),
					attribute.Int("level", levelIndex),
				)
				luapool.PrepareRequestEnv(Llocal)

				// Bind request-scoped modules into reqEnv so that require() resolves correctly.
				// 1) nauthilus_context
				if loader := lualib.LoaderModContext(localRequest.Context); loader != nil {
					_ = loader(Llocal)

					if mod, ok := Llocal.Get(-1).(*lua.LTable); ok {
						Llocal.Pop(1)
						luapool.BindModuleIntoReq(Llocal, definitions.LuaModContext, mod)
					} else {
						Llocal.Pop(1)
					}
				}

				// 2) nauthilus_cbor
				bindSubjectModuleIntoReq(Llocal, definitions.LuaModCBOR, lualib.LoaderModCBOR())

				// 3) nauthilus_http_request
				if ctx != nil && ctx.Request != nil {
					loader := lualib.LoaderModHTTP(lualib.NewHTTPMetaFromRequest(ctx.Request))
					_ = loader(Llocal)

					if mod, ok := Llocal.Get(-1).(*lua.LTable); ok {
						Llocal.Pop(1)
						luapool.BindModuleIntoReq(Llocal, definitions.LuaModHTTPRequest, mod)
					} else {
						Llocal.Pop(1)
					}
				}

				// 4) nauthilus_http_response
				if ctx != nil {
					loader := lualib.LoaderModHTTPResponse(ctx)
					_ = loader(Llocal)

					if mod, ok := Llocal.Get(-1).(*lua.LTable); ok {
						Llocal.Pop(1)
						luapool.BindModuleIntoReq(Llocal, definitions.LuaModHTTPResponse, mod)
					} else {
						Llocal.Pop(1)
					}
				}

				// 5) nauthilus_redis
				if loader := redislib.LoaderModRedis(luaCtx, cfg, redisClient); loader != nil {
					_ = loader(Llocal)

					if mod, ok := Llocal.Get(-1).(*lua.LTable); ok {
						Llocal.Pop(1)
						luapool.BindModuleIntoReq(Llocal, definitions.LuaModRedis, mod)
					} else {
						Llocal.Pop(1)
					}
				}

				// 6) nauthilus_ldap (optional)
				if cfg.HaveLDAPBackend() {
					loader := backend.LoaderModLDAP(luaCtx, cfg)
					_ = loader(Llocal)

					if mod, ok := Llocal.Get(-1).(*lua.LTable); ok {
						Llocal.Pop(1)
						luapool.BindModuleIntoReq(Llocal, definitions.LuaModLDAP, mod)
					} else {
						Llocal.Pop(1)
					}
				}

				// 7) nauthilus_psnet (connection monitoring)
				if loader := connmgr.LoaderModPsnet(luaCtx, cfg, logger); loader != nil {
					_ = loader(Llocal)

					if mod, ok := Llocal.Get(-1).(*lua.LTable); ok {
						Llocal.Pop(1)
						luapool.BindModuleIntoReq(Llocal, definitions.LuaModPsnet, mod)
					} else {
						Llocal.Pop(1)
					}
				}

				// 8) nauthilus_dns (DNS lookups)
				if loader := lualib.LoaderModDNS(luaCtx, cfg, logger); loader != nil {
					_ = loader(Llocal)

					if mod, ok := Llocal.Get(-1).(*lua.LTable); ok {
						Llocal.Pop(1)
						luapool.BindModuleIntoReq(Llocal, definitions.LuaModDNS, mod)
					} else {
						Llocal.Pop(1)
					}
				}

				// 9) nauthilus_opentelemetry (OTel helpers for Lua)
				{
					var loader lua.LGFunction

					if cfg.GetServer().GetInsights().GetTracing().IsEnabled() {
						loader = lualib.LoaderModOTEL(luaCtx, cfg, logger)
					} else {
						loader = lualib.LoaderOTELStateless()
					}

					if loader != nil {
						_ = loader(Llocal)
						if mod, ok := Llocal.Get(-1).(*lua.LTable); ok {
							Llocal.Pop(1)
							luapool.BindModuleIntoReq(Llocal, definitions.LuaModOpenTelemetry, mod)
						} else {
							Llocal.Pop(1)
						}
					}
				}

				// 10) nauthilus_brute_force (toleration and blocking helpers)
				if loader := bflib.LoaderModBruteForce(luaCtx, cfg, logger, redisClient, tolerate.GetTolerate()); loader != nil {
					_ = loader(Llocal)

					if mod, ok := Llocal.Get(-1).(*lua.LTable); ok {
						Llocal.Pop(1)
						luapool.BindModuleIntoReq(Llocal, definitions.LuaModBruteForce, mod)
					} else {
						Llocal.Pop(1)
					}
				}

				// 11) nauthilus_policy
				bindSubjectModuleIntoReq(
					Llocal,
					definitions.LuaModPolicy,
					lualib.LoaderModPolicy(localRequest.PolicyContext, policy.StageSubjectAnalysis),
				)

				// 12) nauthilus_backend (preload stateless placeholder, then request-bound)
				Llocal.PreloadModule(definitions.LuaModBackend, lualib.LoaderBackendStateless())
				{
					loader := LoaderModBackendWithCurrent(luaCtx, cfg, logger, &localRequest, &localBackendResult, &localRemoveAttrs, mergedBackendResult, mergedRemoveAttributes.GetStringSlice())
					_ = loader(Llocal)

					if mod, ok := Llocal.Get(-1).(*lua.LTable); ok {
						Llocal.Pop(1)
						luapool.BindModuleIntoReq(Llocal, definitions.LuaModBackend, mod)
					} else {
						Llocal.Pop(1)
					}
				}

				mspan.End()
				envSpan.End()

				fr := &subjectResult{name: sc.Name, scriptIdx: idx, statusText: &localStatus, backendResult: localBackendResult}

				// Execute script
				execCtx, execSpan := tr.Start(fctx, "subject_sources.execute",
					attribute.String("name", sc.Name),
					attribute.String("mode", mode),
					attribute.Int("level", levelIndex),
				)

				_, packagePathSpan := scriptTrace.Start(execCtx, "lua.script.package_path")
				if e := lualib.PackagePath(Llocal, cfg); e != nil {
					r.handleError(logger, luaCancel, lualib.NewRuntimeCancellationDiagnostics(luaCtx, egCtx, fctx), e, sc.Name, stopTimer)
					packagePathSpan.RecordError(e)
					packagePathSpan.End()
					execSpan.RecordError(e)
					execSpan.End()
					r.recordSubjectScriptResult(egCtx, sc.Name, false, subjectStatusText(localStatus), time.Since(scriptStarted), e)

					return e
				}

				packagePathSpan.End()

				_, loadSpan := scriptTrace.Start(execCtx, "lua.script.load_chunk")
				if e := lualib.DoCompiledFile(Llocal, sc.CompiledScript); e != nil {
					r.handleError(logger, luaCancel, lualib.NewRuntimeCancellationDiagnostics(luaCtx, egCtx, fctx), e, sc.Name, stopTimer)
					loadSpan.RecordError(e)
					loadSpan.End()
					execSpan.RecordError(e)
					execSpan.End()
					r.recordSubjectScriptResult(egCtx, sc.Name, false, subjectStatusText(localStatus), time.Since(scriptStarted), e)

					return e
				}

				loadSpan.End()

				// Call subject source function (reqEnv-first lookup)
				_, lookupSpan := scriptTrace.Start(execCtx, "lua.script.lookup_entrypoint",
					attribute.String("lua.entrypoint", definitions.LuaFnCallSubject),
				)
				subjectFunc := lua.LNil
				if v := Llocal.GetGlobal("__NAUTH_REQ_ENV"); v != nil && v.Type() == lua.LTTable {
					if fn := Llocal.GetField(v, definitions.LuaFnCallSubject); fn != nil {
						subjectFunc = fn
					}
				}

				if subjectFunc == lua.LNil {
					subjectFunc = Llocal.GetGlobal(definitions.LuaFnCallSubject)
				}

				if subjectFunc.Type() != lua.LTFunction {
					e := fmt.Errorf("entry function '%s' is not defined in Lua subject source %s", definitions.LuaFnCallSubject, sc.Name)
					r.handleError(logger, luaCancel, lualib.NewRuntimeCancellationDiagnostics(luaCtx, egCtx, fctx), e, sc.Name, stopTimer)
					lookupSpan.SetAttributes(attribute.Bool("lua.entrypoint.found", false))
					lookupSpan.RecordError(e)
					lookupSpan.End()
					execSpan.RecordError(e)
					execSpan.End()
					r.recordSubjectScriptResult(egCtx, sc.Name, false, subjectStatusText(localStatus), time.Since(scriptStarted), e)

					return e
				}

				lookupSpan.SetAttributes(attribute.Bool("lua.entrypoint.found", true))
				lookupSpan.End()

				_, callSpan := scriptTrace.Start(execCtx, "lua.script.call",
					attribute.String("lua.entrypoint", definitions.LuaFnCallSubject),
				)
				if e := Llocal.CallByParam(lua.P{Fn: subjectFunc, NRet: 2, Protect: true}, request); e != nil {
					r.handleError(logger, luaCancel, lualib.NewRuntimeCancellationDiagnostics(luaCtx, egCtx, fctx), e, sc.Name, stopTimer)
					callSpan.RecordError(e)
					callSpan.End()
					execSpan.RecordError(e)
					execSpan.End()
					r.recordSubjectScriptResult(egCtx, sc.Name, false, subjectStatusText(localStatus), time.Since(scriptStarted), e)

					return e
				}

				callSpan.End()

				_, decodeSpan := scriptTrace.Start(execCtx, "lua.script.decode_result")
				ret := Llocal.ToInt(-1)
				Llocal.Pop(1)
				takeAction := Llocal.ToBool(-1)
				Llocal.Pop(1)
				fr.ret = ret
				fr.action = takeAction

				execSpan.SetAttributes(
					attribute.Int("result", ret),
					attribute.Bool("action", takeAction),
				)
				decodeSpan.SetAttributes(
					attribute.Int("lua.result", ret),
					attribute.Bool("lua.action", takeAction),
				)
				decodeSpan.End()

				execSpan.End()

				// Snapshot local logs and remove-attrs for aggregation
				fr.logs = *localLogs
				fr.removeAttrsList = localRemoveAttrs
				fr.contextDelta = localRequest.Diff(contextBefore)

				selectedChanged := localRequest.UsedBackendAddr != originalBackendAddrPtr || localRequest.UsedBackendPort != originalBackendPortPtr
				if !selectedChanged {
					if localRequest.UsedBackendAddr != nil {
						selectedChanged = !originalBackendAddrSet || *localRequest.UsedBackendAddr != originalBackendAddrValue
					}

					if !selectedChanged && localRequest.UsedBackendPort != nil {
						selectedChanged = !originalBackendPortSet || *localRequest.UsedBackendPort != originalBackendPortValue
					}
				}

				if selectedChanged {
					fr.selectedSet = true
					fr.selectedAddress = localRequest.UsedBackendAddr
					fr.selectedPort = localRequest.UsedBackendPort
				}

				// Emit debug log for this subject source
				logs := []any{definitions.LogKeyGUID, r.Session, "name", sc.Name, definitions.LogKeyMsg, "Lua subject source finished", "action", fr.action, "result", func() string {
					switch fr.ret {
					case 0:
						return "ok"
					case 1:
						return "fail"
					default:
						return fmt.Sprintf("unknown(%d)", fr.ret)
					}
				}()}

				if len(fr.logs) > 0 {
					for i := range fr.logs {
						logs = append(logs, fr.logs[i])
					}
				}

				util.DebugModuleWithCfg(fctx, cfg, logger, definitions.DbgSubject, logs...)

				if stopTimer != nil {
					stopTimer()
				}

				r.recordSubjectScriptResult(egCtx, sc.Name, fr.action, subjectStatusText(localStatus), time.Since(scriptStarted), nil)

				mu.Lock()
				levelResults = append(levelResults, fr)
				mu.Unlock()

				return nil
			})
		}

		// End parallel start span after scheduling all goroutines
		pstart.End()

		// Wait span to cover synchronization
		wctx, wspan := tr.Start(fctx, "subject_sources.parallel.wait",
			attribute.Int("level", levelIndex),
			attribute.Int("runnable", len(level)),
			attribute.String("mode", mode),
		)
		_ = wctx

		if e := g.Wait(); e != nil {
			wspan.RecordError(e)
			wspan.End()

			return false, nil, nil, e
		}

		wspan.SetAttributes(attribute.Int("completed", len(levelResults)))
		wspan.End()

		sort.Slice(levelResults, func(i, j int) bool {
			return levelResults[i].scriptIdx < levelResults[j].scriptIdx
		})

		mctx, mspan := tr.Start(fctx, "subject_sources.level.merge",
			attribute.Int("level", levelIndex),
			attribute.Int("scripts", len(levelResults)),
			attribute.String("mode", mode),
		)
		_ = mctx

		for _, fr := range levelResults {
			if fr.action {
				action = true
			}

			if fr.backendResult != nil && len(fr.backendResult.Attributes) > 0 {
				mergedBackendResult.Attributes = mergeMaps(mergedBackendResult.Attributes, fr.backendResult.Attributes)
			}

			if fr.backendResult != nil {
				mergedBackendResult.Groups = mergeSortedUniqueStrings(mergedBackendResult.Groups, fr.backendResult.Groups)
				mergedBackendResult.GroupDNs = mergeSortedUniqueStrings(mergedBackendResult.GroupDNs, fr.backendResult.GroupDNs)
			}

			for _, attr := range fr.removeAttrsList {
				mergedRemoveAttributes.Set(attr)
			}

			if fr.selectedSet {
				r.UsedBackendAddr = fr.selectedAddress
				r.UsedBackendPort = fr.selectedPort
			}

			r.ApplyDelta(fr.contextDelta)
			lualib.MergeStatusAndLogs(&statusSet, &r.Logs, &r.StatusMessage, *fr.statusText, fr.logs)
		}

		results = append(results, levelResults...)

		mspan.SetAttributes(
			attribute.Int("merged_attrs", len(mergedBackendResult.Attributes)),
			attribute.Int("removed_attrs_unique", len(mergedRemoveAttributes.GetStringSlice())),
		)
		mspan.End()
	}

	// After aggregating results, log rejected subject sources and per-subject-source return codes
	if r.Logs == nil {
		r.Logs = new(lualib.CustomLogKeyValue)
	}

	rejectedSubjectSources := make([]string, 0)
	resultPairs := make([]string, 0, len(results))

	for _, fr := range results {
		if fr.action {
			rejectedSubjectSources = append(rejectedSubjectSources, fr.name)
		}

		var status string

		switch fr.ret {
		case 0:
			status = "ok"
		case 1:
			status = "fail"
		default:
			status = fmt.Sprintf("unknown(%d)", fr.ret)
		}

		resultPairs = append(resultPairs, fmt.Sprintf("%s:%s", fr.name, status))
	}

	if len(rejectedSubjectSources) > 0 {
		r.Logs.Set(definitions.LogKeyRejectedSubjectSources, strings.Join(rejectedSubjectSources, ","))
	}

	if len(resultPairs) > 0 {
		r.Logs.Set(definitions.LogKeySubjectResults, strings.Join(resultPairs, ","))
	}

	_, finalMergeSpan := tr.Start(fctx, "subject_sources.merge.final")
	finalMergeSpan.SetAttributes(
		attribute.Int("merged_attrs", len(mergedBackendResult.Attributes)),
		attribute.Int("removed_attrs_unique", len(mergedRemoveAttributes.GetStringSlice())),
		attribute.Int("rejected_count", len(rejectedSubjectSources)),
	)
	finalMergeSpan.End()

	backendResult = mergedBackendResult
	removeAttributes = mergedRemoveAttributes.GetStringSlice()

	return action, backendResult, removeAttributes, nil
}

func (r *Request) recordSubjectScriptResult(ctx context.Context, name string, action bool, message string, duration time.Duration, err error) {
	if r == nil || r.ScriptRecorder == nil {
		return
	}

	r.ScriptRecorder.RecordScriptResult(ctx, policycollection.ScriptResult{
		Err:           err,
		Kind:          policycollection.ScriptKindSubject,
		Name:          name,
		StatusMessage: message,
		Duration:      duration,
		Action:        action,
	})
}

func subjectPlanForScripts(scriptPlan policycollection.ScriptSchedulePlan, mode pipeline.ModeMask) (pipeline.Plan, bool, error) {
	if !scriptPlan.Configured {
		return LuaSubjectSources.planForMode(mode)
	}

	plan, err := policyschedule.BuildPlan(subjectPipelineNodes(LuaSubjectSources.LuaScripts), scriptPlan, mode)

	return plan, false, err
}

func policySubjectScriptPlan(r *Request, authState policycollection.AuthState) policycollection.ScriptSchedulePlan {
	if r == nil || r.ScriptRecorder == nil {
		return policycollection.ScriptSchedulePlan{}
	}

	return r.ScriptRecorder.ScriptPlan(policycollection.ScriptKindSubject, authState)
}

func countSubjectSourcesForMode(sources []*LuaSubjectSource, mode pipeline.ModeMask) int {
	count := 0

	for _, source := range sources {
		if source != nil && source.Modes&mode != 0 {
			count++
		}
	}

	return count
}

func subjectModeText(mode pipeline.ModeMask) string {
	return pipeline.ModeText(mode)
}

func requestPolicyAuthState(r *Request) policycollection.AuthState {
	if r != nil && r.CommonRequest != nil && r.Authenticated {
		return policycollection.AuthStateAuthenticated
	}

	return policycollection.AuthStateUnauthenticated
}

func subjectStatusText(status *string) string {
	if status == nil {
		return ""
	}

	return *status
}
