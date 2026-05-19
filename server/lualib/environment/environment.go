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

// Package environment executes Lua environment source scripts.
package environment

import (
	"context"
	stderrors "errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/bruteforce/tolerate"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/log/level"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/luamod"
	"github.com/croessner/nauthilus/server/lualib/luapool"
	"github.com/croessner/nauthilus/server/lualib/pipeline"
	"github.com/croessner/nauthilus/server/lualib/policyschedule"
	"github.com/croessner/nauthilus/server/lualib/vmpool"
	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"github.com/croessner/nauthilus/server/policy"
	policycollection "github.com/croessner/nauthilus/server/policy/collection"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"

	"github.com/gin-gonic/gin"
	lua "github.com/yuin/gopher-lua"
	"go.opentelemetry.io/otel/attribute"
	"golang.org/x/sync/errgroup"
)

// LuaEnvironmentSources holds pre-compiled Lua environment sources for the application.
var LuaEnvironmentSources *PreCompiledLuaEnvironmentSources

// PreCompileLuaEnvironmentSources pre-compiles Lua environment sources listed in the configuration.
// Returns an error if the pre-compilation process or Lua environment source initialization fails, otherwise returns nil.
func PreCompileLuaEnvironmentSources(cfg config.File, _ *slog.Logger) (err error) {
	if cfg.HaveLuaEnvironmentSources() {
		if LuaEnvironmentSources == nil {
			LuaEnvironmentSources = &PreCompiledLuaEnvironmentSources{}
		} else {
			LuaEnvironmentSources.Reset()
		}

		sources := cfg.GetLua().GetEnvironmentSources()
		for index := range sources {
			var luaEnvironmentSource *LuaEnvironmentSource

			cfgSource := sources[index]
			luaEnvironmentSource, err = NewLuaEnvironmentSource(cfgSource.Name, cfgSource.ScriptPath)
			if err != nil {
				return err
			}

			LuaEnvironmentSources.Add(luaEnvironmentSource)
		}

		if err = LuaEnvironmentSources.RebuildPlans(); err != nil {
			return err
		}
	}

	return nil
}

// PreCompiledLuaEnvironmentSources represents a collection of pre-compiled Lua environment sources.
// It contains an array of LuaEnvironmentSource objects and a read-write mutex for synchronization.
type PreCompiledLuaEnvironmentSources struct {
	LuaScripts []*LuaEnvironmentSource
	plans      pipeline.Plans
	Mu         sync.RWMutex
}

// Add appends the given LuaEnvironmentSource to the slice of LuaScripts in PreCompiledLuaEnvironmentSources.
func (a *PreCompiledLuaEnvironmentSources) Add(luaEnvironmentSource *LuaEnvironmentSource) {
	a.Mu.Lock()

	defer a.Mu.Unlock()

	a.LuaScripts = append(a.LuaScripts, luaEnvironmentSource)
	a.plans = nil
}

// Reset clears the LuaScripts slice and resets it to an empty state while ensuring thread-safe access via locking.
func (a *PreCompiledLuaEnvironmentSources) Reset() {
	a.Mu.Lock()

	defer a.Mu.Unlock()

	a.LuaScripts = make([]*LuaEnvironmentSource, 0)
	a.plans = nil
}

// RebuildPlans validates all environment source dependencies and caches per-mode execution plans.
func (a *PreCompiledLuaEnvironmentSources) RebuildPlans() error {
	a.Mu.Lock()

	defer a.Mu.Unlock()

	plans, err := pipeline.BuildPlans(environmentPipelineNodes(a.LuaScripts))
	if err != nil {
		return err
	}

	a.plans = plans

	return nil
}

func (a *PreCompiledLuaEnvironmentSources) planForMode(mode pipeline.ModeMask) (pipeline.Plan, bool, error) {
	if a.plans != nil {
		if plan, ok := a.plans[mode]; ok {
			return plan, true, nil
		}
	}

	plan, err := pipeline.BuildPlan(environmentPipelineNodes(a.LuaScripts), mode)
	if err != nil {
		return pipeline.Plan{}, false, err
	}

	return plan, false, nil
}

func (a *PreCompiledLuaEnvironmentSources) planForRequest(r *Request, mode pipeline.ModeMask) (pipeline.Plan, bool, error) {
	if r != nil && r.ScriptRecorder != nil {
		scriptPlan := r.ScriptRecorder.ScriptPlan(policycollection.ScriptKindEnvironment, requestEnvironmentAuthState(r))
		if scriptPlan.Configured {
			plan, err := policyschedule.BuildPlan(environmentPipelineNodes(a.LuaScripts), scriptPlan, mode)

			return plan, false, err
		}
	}

	return a.planForMode(mode)
}

// LuaEnvironmentSource represents a Lua environment source that has been compiled.
// It contains a name identifying the environment source and the compiled Lua script.
type LuaEnvironmentSource struct {
	Name           string
	CompiledScript *lua.FunctionProto
	Dependencies   []string
	Modes          pipeline.ModeMask
}

// NewLuaEnvironmentSource creates a new LuaEnvironmentSource instance by compiling the Lua script found at the given path and assigning its name.
// Returns the LuaEnvironmentSource instance or an error if either the name or scriptPath is empty, or if script compilation fails.
func NewLuaEnvironmentSource(name string, scriptPath string) (*LuaEnvironmentSource, error) {
	if name == "" {
		return nil, errors.ErrEnvironmentSourceLuaNameMissing
	}

	if scriptPath == "" {
		return nil, errors.ErrEnvironmentSourceLuaScriptPathEmpty
	}

	compiledScript, err := lualib.CompileLua(scriptPath)
	if err != nil {
		return nil, err
	}

	return &LuaEnvironmentSource{
		Name:           name,
		CompiledScript: compiledScript,
		Modes:          pipeline.ModeAuthenticated | pipeline.ModeUnauthenticated,
	}, nil
}

func environmentPipelineNodes(sources []*LuaEnvironmentSource) []pipeline.Node {
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

func requestEnvironmentMode(r *Request) pipeline.ModeMask {
	if r != nil && r.NoAuth {
		return pipeline.ModeNoAuth
	}

	if r != nil && r.Authenticated {
		return pipeline.ModeAuthenticated
	}

	return pipeline.ModeUnauthenticated
}

func requestEnvironmentAuthState(r *Request) policycollection.AuthState {
	if r != nil && r.Authenticated {
		return policycollection.AuthStateAuthenticated
	}

	return policycollection.AuthStateUnauthenticated
}

// Request represents a request data structure with all the necessary information about a connection and SSL usage.
type Request struct {
	Session              string
	Username             string
	Password             []byte
	ClientIP             string
	AccountName          string
	UsedBackendPort      *int
	AdditionalAttributes map[string]any

	// Logs holds the custom log key-value pairs.
	Logs *lualib.CustomLogKeyValue

	// Context contains additional context data.
	*lualib.Context

	*lualib.CommonRequest

	HTTPClientContext *gin.Context
	HTTPClientRequest *http.Request
	ScriptRecorder    policycollection.ScriptRecorder
	PolicyContext     *policycollection.DecisionContext
	Authenticated     bool
	NoAuth            bool
	BruteForceCounter uint
	MasterUserMode    bool
}

// CallEnvironmentLua executes Lua environment source scripts within the context of a request.
// It returns whether an environment source was triggered, whether later sources should be aborted, and any execution error.
func (r *Request) CallEnvironmentLua(ctx *gin.Context, cfg config.File, logger *slog.Logger, redisClient rediscli.Client) (triggered bool, skipRemainingEnvironment bool, err error) {
	startTime := time.Now()
	defer func() {
		latency := time.Since(startTime)
		if r.Logs == nil {
			r.Logs = new(lualib.CustomLogKeyValue)
		}

		r.Logs.Set(definitions.LogKeyEnvironmentLatency, util.FormatDurationMs(latency))
	}()

	if LuaEnvironmentSources == nil || len(LuaEnvironmentSources.LuaScripts) == 0 {
		return
	}

	LuaEnvironmentSources.Mu.RLock()

	defer LuaEnvironmentSources.Mu.RUnlock()

	pool := vmpool.GetManager().GetOrCreate("environment:default", vmpool.PoolOptions{
		MaxVMs: cfg.GetLuaEnvironmentSourceVMPoolSize(),
		Config: cfg,
	})

	triggered, skipRemainingEnvironment, err = r.executeScripts(ctx, cfg, logger, redisClient, pool)

	return
}

// executeScripts executes all Lua environment source scripts in parallel. It waits for all to finish,
// then aggregates their results considering error, abort, and triggered semantics.
//
//nolint:gocyclo,funlen
func (r *Request) executeScripts(ctx *gin.Context, cfg config.File, logger *slog.Logger, redisClient rediscli.Client, pool *vmpool.Pool) (triggered bool, skipRemainingEnvironment bool, err error) {
	type environmentResult struct {
		name         string
		scriptIdx    int
		triggered    bool
		abort        bool
		ret          int
		err          error
		logs         lualib.CustomLogKeyValue
		statusText   **string
		contextDelta lualib.ContextDelta
	}

	if ctx.Err() != nil {
		return false, false, ctx.Err()
	}

	if r.Context == nil {
		r.Context = lualib.NewContext()
	}

	tr := monittrace.New("nauthilus/environment")
	mode := requestEnvironmentMode(r)
	modeText := pipeline.ModeText(mode)
	pctx, pspan := tr.Start(ctx.Request.Context(), "environment.plan.lookup")
	_ = pctx

	plan, cached, err := LuaEnvironmentSources.planForRequest(r, mode)
	pspan.SetAttributes(
		attribute.Bool("cached", cached),
		attribute.Int("levels", len(plan.Levels)),
		attribute.Int("scripts", pipeline.PlannedNodeCount(plan)),
		attribute.String("mode", modeText),
	)
	if err != nil {
		pspan.RecordError(err)
		pspan.End()

		return false, false, err
	}

	pspan.End()

	var statusSet bool

	traceCtx := ctx.Request.Context()

	for levelIndex, level := range plan.Levels {
		var (
			mu           sync.Mutex
			levelResults = make([]*environmentResult, 0, len(level))
		)

		g, egCtx := errgroup.WithContext(traceCtx)

		pstartCtx, pstart := tr.Start(traceCtx, "environment_sources.parallel.start",
			attribute.Int("runnable", len(level)),
			attribute.Int("level", levelIndex),
			attribute.String("mode", modeText),
		)
		_ = pstartCtx

		for _, planned := range level {
			idx := planned.Index
			source := planned.Value.(*LuaEnvironmentSource)

			g.Go(func() (err error) {
				scriptStarted := time.Now()
				sCtx, sSpan := tr.Start(traceCtx, "environment_sources.script",
					attribute.String("name", source.Name),
					attribute.String("mode", modeText),
					attribute.Int("level", levelIndex),
				)
				_ = sCtx
				scriptTrace := lualib.NewLuaScriptTrace(lualib.LuaScriptTraceOptions{
					Kind:       lualib.LuaScriptKindEnvironment,
					ScriptName: source.Name,
					Mode:       modeText,
					Level:      levelIndex,
				})

				util.DebugModuleWithCfg(egCtx, cfg, logger, definitions.DbgEnvironment,
					definitions.LogKeyGUID, r.Session,
					definitions.LogKeyMsg, "Executing environment source script",
					"name", source.Name,
				)

				actx, asp := tr.Start(egCtx, "environment_sources.vm.acquire",
					attribute.String("name", source.Name),
					attribute.String("mode", modeText),
					attribute.Int("level", levelIndex),
				)
				lease, acqErr := pool.AcquireLease(actx)

				asp.End()

				if acqErr != nil {
					sSpan.RecordError(acqErr)
					sSpan.End()
					r.recordEnvironmentScriptResult(egCtx, source.Name, false, false, "", time.Since(scriptStarted), acqErr)

					return acqErr
				}

				Llocal := lease.State()

				defer sSpan.End()
				defer lease.ReleaseRecoveringOnError(&err)

				localContext := r.Clone()
				contextBefore := localContext.Snapshot()
				localLogs := new(lualib.CustomLogKeyValue)

				var localStatus *string

				envCtx, envSpan := tr.Start(traceCtx, "environment_sources.env.prepare",
					attribute.String("name", source.Name),
					attribute.String("mode", modeText),
					attribute.Int("level", levelIndex),
				)
				_ = envCtx

				lualib.SetBuiltinTableForEnvironment(
					Llocal,
					lualib.NewLoggingManager(ctx, cfg, logger, localLogs).AddCustomLog,
					&localStatus,
				)

				localRequest := *r
				localRequest.Context = localContext

				request := Llocal.NewTable()

				localRequest.SetupRequest(Llocal, cfg, request)

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

				stopTimer := stats.PrometheusTimer(cfg, definitions.PromEnvironment, source.Name, ctx.FullPath())

				luaCtx, luaCancel := context.WithTimeout(egCtx, cfg.GetServer().GetTimeouts().GetLuaScript())
				defer luaCancel()

				Llocal.SetContext(luaCtx)

				_, mspan := tr.Start(envCtx, "environment_sources.env.modules",
					attribute.String("name", source.Name),
					attribute.String("mode", modeText),
					attribute.Int("level", levelIndex),
				)
				luapool.PrepareRequestEnv(Llocal)

				modManager := luamod.NewModuleManager(ctx, cfg, logger, redisClient)

				modManager.BindAllDefault(Llocal, localRequest.Context, luaCtx, tolerate.GetTolerate())
				modManager.BindModule(
					Llocal,
					definitions.LuaModPolicy,
					lualib.LoaderModPolicy(localRequest.PolicyContext, policy.StagePreAuth),
				)

				if ctx != nil && ctx.Request != nil {
					modManager.BindHTTP(Llocal, lualib.NewHTTPMetaFromRequest(ctx.Request))
				}

				modManager.BindHTTPResponse(Llocal, ctx)
				modManager.BindLDAP(Llocal, backend.LoaderModLDAP(luaCtx, cfg))
				mspan.End()
				envSpan.End()

				fr := &environmentResult{name: source.Name, scriptIdx: idx, statusText: &localStatus}

				execCtx, execSpan := tr.Start(traceCtx, "environment_sources.execute",
					attribute.String("name", source.Name),
					attribute.String("mode", modeText),
					attribute.Int("level", levelIndex),
				)

				_, packagePathSpan := scriptTrace.Start(execCtx, "lua.script.package_path")
				if e := lualib.PackagePath(Llocal, cfg); e != nil {
					r.handleError(logger, luaCancel, lualib.NewRuntimeCancellationDiagnostics(luaCtx, egCtx, ctx), e, source.Name, stopTimer)
					packagePathSpan.RecordError(e)
					packagePathSpan.End()
					execSpan.RecordError(e)
					execSpan.End()
					r.recordEnvironmentScriptResult(egCtx, source.Name, false, false, statusText(localStatus), time.Since(scriptStarted), e)

					return e
				}

				packagePathSpan.End()

				_, loadSpan := scriptTrace.Start(execCtx, "lua.script.load_chunk")
				if e := lualib.DoCompiledFile(Llocal, source.CompiledScript); e != nil {
					r.handleError(logger, luaCancel, lualib.NewRuntimeCancellationDiagnostics(luaCtx, egCtx, ctx), e, source.Name, stopTimer)
					loadSpan.RecordError(e)
					loadSpan.End()
					execSpan.RecordError(e)
					execSpan.End()
					r.recordEnvironmentScriptResult(egCtx, source.Name, false, false, statusText(localStatus), time.Since(scriptStarted), e)

					return e
				}

				loadSpan.End()

				_, lookupSpan := scriptTrace.Start(execCtx, "lua.script.lookup_entrypoint",
					attribute.String("lua.entrypoint", definitions.LuaFnCallEnvironment),
				)
				callEnvironmentFunc := lua.LNil
				if v := Llocal.GetGlobal("__NAUTH_REQ_ENV"); v != nil && v.Type() == lua.LTTable {
					if fn := Llocal.GetField(v, definitions.LuaFnCallEnvironment); fn != nil {
						callEnvironmentFunc = fn
					}
				}

				if callEnvironmentFunc == lua.LNil {
					callEnvironmentFunc = Llocal.GetGlobal(definitions.LuaFnCallEnvironment)
				}

				if callEnvironmentFunc.Type() != lua.LTFunction {
					e := fmt.Errorf("entry function '%s' is not defined in Lua environment source %s", definitions.LuaFnCallEnvironment, source.Name)
					r.handleError(logger, luaCancel, lualib.NewRuntimeCancellationDiagnostics(luaCtx, egCtx, ctx), e, source.Name, stopTimer)
					lookupSpan.SetAttributes(attribute.Bool("lua.entrypoint.found", false))
					lookupSpan.RecordError(e)
					lookupSpan.End()
					execSpan.RecordError(e)
					execSpan.End()
					r.recordEnvironmentScriptResult(egCtx, source.Name, false, false, statusText(localStatus), time.Since(scriptStarted), e)

					return e
				}

				lookupSpan.SetAttributes(attribute.Bool("lua.entrypoint.found", true))
				lookupSpan.End()

				_, callSpan := scriptTrace.Start(execCtx, "lua.script.call",
					attribute.String("lua.entrypoint", definitions.LuaFnCallEnvironment),
				)
				if e := Llocal.CallByParam(lua.P{Fn: callEnvironmentFunc, NRet: 3, Protect: true}, request); e != nil {
					r.handleError(logger, luaCancel, lualib.NewRuntimeCancellationDiagnostics(luaCtx, egCtx, ctx), e, source.Name, stopTimer)
					callSpan.RecordError(e)
					callSpan.End()
					execSpan.RecordError(e)
					execSpan.End()
					r.recordEnvironmentScriptResult(egCtx, source.Name, false, false, statusText(localStatus), time.Since(scriptStarted), e)

					return e
				}

				callSpan.End()

				_, decodeSpan := scriptTrace.Start(execCtx, "lua.script.decode_result")
				ret := Llocal.ToInt(-1)
				Llocal.Pop(1)
				ab := Llocal.ToBool(-1)
				Llocal.Pop(1)
				tr := Llocal.ToBool(-1)
				Llocal.Pop(1)
				fr.ret = ret
				fr.abort = ab
				fr.triggered = tr
				execSpan.SetAttributes(
					attribute.Int("result", ret),
					attribute.Bool("abort", ab),
					attribute.Bool("triggered", tr),
				)
				decodeSpan.SetAttributes(
					attribute.Int("lua.result", ret),
					attribute.Bool("lua.abort", ab),
					attribute.Bool("lua.triggered", tr),
				)
				decodeSpan.End()
				execSpan.End()

				fr.logs = *localLogs
				fr.contextDelta = localRequest.Diff(contextBefore)
				logs := []any{
					definitions.LogKeyGUID, r.Session,
					"name", source.Name,
					definitions.LogKeyMsg, "Lua environment source finished",
					"triggered", fr.triggered,
					"abort_environment_sources", fr.abort,
					"result", func() string { return r.formatResult(fr.ret) }(),
				}

				if len(fr.logs) > 0 {
					for i := range fr.logs {
						logs = append(logs, fr.logs[i])
					}
				}

				util.DebugModuleWithCfg(egCtx, cfg, logger, definitions.DbgEnvironment, logs...)

				if stopTimer != nil {
					stopTimer()
				}

				r.recordEnvironmentScriptResult(egCtx, source.Name, fr.triggered, fr.abort, statusText(localStatus), time.Since(scriptStarted), nil)

				mu.Lock()
				levelResults = append(levelResults, fr)
				mu.Unlock()

				return nil
			})
		}

		pstart.End()

		wctx, wspan := tr.Start(traceCtx, "environment_sources.parallel.wait",
			attribute.Int("level", levelIndex),
			attribute.Int("runnable", len(level)),
			attribute.String("mode", modeText),
		)
		_ = wctx

		if e := g.Wait(); e != nil {
			wspan.RecordError(e)
			wspan.End()

			return false, false, e
		}

		wspan.SetAttributes(attribute.Int("completed", len(levelResults)))
		wspan.End()

		mctx, mspan := tr.Start(traceCtx, "environment_sources.level.merge",
			attribute.Int("level", levelIndex),
			attribute.Int("scripts", len(levelResults)),
			attribute.String("mode", modeText),
		)
		_ = mctx

		sort.Slice(levelResults, func(i, j int) bool {
			return levelResults[i].scriptIdx < levelResults[j].scriptIdx
		})

		for _, fr := range levelResults {
			if fr.err != nil {
				mspan.RecordError(fr.err)
				mspan.End()

				return false, false, fr.err
			}

			if fr.abort {
				skipRemainingEnvironment = true
			}

			if fr.triggered {
				triggered = true
			}

			r.ApplyDelta(fr.contextDelta)
			lualib.MergeStatusAndLogs(&statusSet, &r.Logs, &r.StatusMessage, *fr.statusText, fr.logs)
		}

		mspan.SetAttributes(
			attribute.Bool("triggered", triggered),
			attribute.Bool("skip_remaining", skipRemainingEnvironment),
		)
		mspan.End()
	}

	return triggered, skipRemainingEnvironment, nil
}

func (r *Request) recordEnvironmentScriptResult(ctx context.Context, name string, triggered bool, abort bool, message string, duration time.Duration, err error) {
	if r == nil || r.ScriptRecorder == nil {
		return
	}

	r.ScriptRecorder.RecordScriptResult(ctx, policycollection.ScriptResult{
		Err:           err,
		Kind:          policycollection.ScriptKindEnvironment,
		Name:          name,
		StatusMessage: message,
		Duration:      duration,
		Triggered:     triggered,
		Abort:         abort,
	})
}

func statusText(status *string) string {
	if status == nil {
		return ""
	}

	return *status
}

// handleError logs the error message and cancels the Lua context.
func (r *Request) handleError(logger *slog.Logger, luaCancel context.CancelFunc, diagnostics lualib.RuntimeCancellationDiagnostics, err error, scriptName string, stopTimer func()) {
	// Include Lua stacktrace when available for better diagnostics
	if ae, ok := stderrors.AsType[*lua.ApiError](err); ok && ae != nil {
		keyvals := []any{
			definitions.LogKeyGUID, r.Session,
			"name", scriptName,
			definitions.LogKeyMsg, "Lua environment source failed",
			definitions.LogKeyError, ae.Error(),
			"stacktrace", ae.StackTrace,
		}

		if r.CommonRequest != nil && r.HealthCheck {
			keyvals = append(keyvals, definitions.LogKeyHealthCheck, true)
		}

		keyvals = append(keyvals, diagnostics.LogValues()...)

		_ = level.Error(logger).Log(keyvals...)
	}

	if stopTimer != nil {
		stopTimer()
	}

	luaCancel()
}

// formatResult returns a string representation of the given integer result.
// It maps 0 to "success", 1 to "fail", and any other value to the string "unknown(<value>)".
func (r *Request) formatResult(ret int) string {
	resultMap := map[int]string{
		0: definitions.LuaSuccess,
		1: definitions.LuaFail,
	}

	if ret == 0 || ret == 1 {
		return resultMap[ret]
	}

	return fmt.Sprintf("unknown(%d)", ret)
}
