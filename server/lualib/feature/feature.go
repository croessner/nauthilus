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

package feature

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
	"github.com/croessner/nauthilus/server/lualib/vmpool"
	"github.com/croessner/nauthilus/server/rediscli"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"

	"github.com/gin-gonic/gin"
	lua "github.com/yuin/gopher-lua"
	"golang.org/x/sync/errgroup"
)

// LuaFeatures is a global variable that holds a collection of pre-compiled Lua features for the application.
var LuaFeatures *PreCompiledLuaFeatures

// PreCompileLuaFeatures pre-compiles Lua features listed in the configuration and initializes the global `LuaFeatures` variable.
// Returns an error if the pre-compilation process or Lua feature initialization fails, otherwise returns nil.
func PreCompileLuaFeatures(cfg config.File, _ *slog.Logger) (err error) {
	if cfg.HaveLuaFeatures() {
		if LuaFeatures == nil {
			LuaFeatures = &PreCompiledLuaFeatures{}
		} else {
			LuaFeatures.Reset()
		}

		for index := range cfg.GetLua().Features {
			var luaFeature *LuaFeature

			luaFeature, err = NewLuaFeature(cfg.GetLua().Features[index].Name, cfg.GetLua().Features[index].ScriptPath)
			if err != nil {
				return err
			}

			// Apply execution flags with sane defaults for backward compatibility
			wa := cfg.GetLua().Features[index].WhenAuthenticated
			wu := cfg.GetLua().Features[index].WhenUnauthenticated
			wn := cfg.GetLua().Features[index].WhenNoAuth

			if !wa && !wu && !wn {
				// No flags specified in config → run in authenticated and unauthenticated by default
				wa = true
				wu = true
			}

			luaFeature.WhenAuthenticated = wa
			luaFeature.WhenUnauthenticated = wu
			luaFeature.WhenNoAuth = wn
			luaFeature.DependsOn = append([]string(nil), cfg.GetLua().Features[index].DependsOn...)

			// Add compiled Lua features.
			LuaFeatures.Add(luaFeature)
		}

		if err = validateFeatureDependencies(LuaFeatures.LuaScripts); err != nil {
			return err
		}
	}

	return nil
}

// PreCompiledLuaFeatures represents a collection of pre-compiled Lua features.
// It contains an array of LuaFeature objects and a read-write mutex for synchronization.
type PreCompiledLuaFeatures struct {
	LuaScripts []*LuaFeature
	Mu         sync.RWMutex
}

// Add appends the given LuaFeature to the slice of LuaScripts in PreCompiledLuaFeatures.
func (a *PreCompiledLuaFeatures) Add(luaFeature *LuaFeature) {
	a.Mu.Lock()

	defer a.Mu.Unlock()

	a.LuaScripts = append(a.LuaScripts, luaFeature)
}

// Reset clears the LuaScripts slice and resets it to an empty state while ensuring thread-safe access via locking.
func (a *PreCompiledLuaFeatures) Reset() {
	a.Mu.Lock()

	defer a.Mu.Unlock()

	a.LuaScripts = make([]*LuaFeature, 0)
}

// LuaFeature represents a Lua feature that has been compiled.
// It contains a name identifying the feature and the compiled Lua script.
type LuaFeature struct {
	Name                string
	CompiledScript      *lua.FunctionProto
	DependsOn           []string
	WhenAuthenticated   bool
	WhenUnauthenticated bool
	WhenNoAuth          bool
}

// NewLuaFeature creates a new LuaFeature instance by compiling the Lua script found at the given path and assigning its name.
// Returns the LuaFeature instance or an error if either the name or scriptPath is empty, or if script compilation fails.
func NewLuaFeature(name string, scriptPath string) (*LuaFeature, error) {
	if name == "" {
		return nil, errors.ErrFeatureLuaNameMissing
	}

	if scriptPath == "" {
		return nil, errors.ErrFeatureLuaScriptPathEmpty
	}

	compiledScript, err := lualib.CompileLua(scriptPath)
	if err != nil {
		return nil, err
	}

	return &LuaFeature{
		Name:           name,
		CompiledScript: compiledScript,
	}, nil
}

func validateFeatureDependencies(features []*LuaFeature) error {
	return pipeline.ValidateStatic(featurePipelineNodes(features))
}

func featurePipelineNodes(features []*LuaFeature) []pipeline.Node {
	nodes := make([]pipeline.Node, 0, len(features))

	for index, feature := range features {
		nodes = append(nodes, pipeline.Node{
			Name:      feature.Name,
			DependsOn: append([]string(nil), feature.DependsOn...),
			Index:     index,
			Modes:     featureModeMask(feature),
			Value:     feature,
		})
	}

	return nodes
}

func featureModeMask(feature *LuaFeature) pipeline.ModeMask {
	var modes pipeline.ModeMask

	if feature.WhenAuthenticated {
		modes |= pipeline.ModeAuthenticated
	}

	if feature.WhenUnauthenticated {
		modes |= pipeline.ModeUnauthenticated
	}

	if feature.WhenNoAuth {
		modes |= pipeline.ModeNoAuth
	}

	return modes
}

func requestFeatureMode(r *Request) pipeline.ModeMask {
	if r != nil && r.NoAuth {
		return pipeline.ModeNoAuth
	}

	if r != nil && r.Authenticated {
		return pipeline.ModeAuthenticated
	}

	return pipeline.ModeUnauthenticated
}

// Request represents a request data structure with all the necessary information about a connection and SSL usage.
type Request struct {
	Session            string
	Username           string
	Password           []byte
	ClientIP           string
	AccountName        string
	UsedBackendPort    *int
	AdditionalFeatures map[string]any

	// Logs holds the custom log key-value pairs.
	Logs *lualib.CustomLogKeyValue

	// Context contains additional context data.
	*lualib.Context

	*lualib.CommonRequest

	HTTPClientContext *gin.Context
	HTTPClientRequest *http.Request
	Authenticated     bool
	NoAuth            bool
	BruteForceCounter uint
	MasterUserMode    bool
}

// CallFeatureLua executes Lua scripts associated with features within the context of a request.
// It triggers actions or aborts features based on script results.
// Returns whether a feature was triggered, if features should be aborted, and any execution error.
func (r *Request) CallFeatureLua(ctx *gin.Context, cfg config.File, logger *slog.Logger, redisClient rediscli.Client) (triggered bool, abortFeatures bool, err error) {
	startTime := time.Now()
	defer func() {
		latency := time.Since(startTime)
		if r.Logs == nil {
			r.Logs = new(lualib.CustomLogKeyValue)
		}

		r.Logs.Set(definitions.LogKeyFeatureLatency, util.FormatDurationMs(latency))
	}()

	if LuaFeatures == nil || len(LuaFeatures.LuaScripts) == 0 {
		return
	}

	LuaFeatures.Mu.RLock()

	defer LuaFeatures.Mu.RUnlock()

	pool := vmpool.GetManager().GetOrCreate("feature:default", vmpool.PoolOptions{
		MaxVMs: cfg.GetLuaFeatureVMPoolSize(),
		Config: cfg,
	})

	triggered, abortFeatures, err = r.executeScripts(ctx, cfg, logger, redisClient, pool)

	return
}

// executeScripts executes all Lua feature scripts in parallel. It waits for all to finish,
// then aggregates their results considering error, abort, and triggered semantics.
func (r *Request) executeScripts(ctx *gin.Context, cfg config.File, logger *slog.Logger, redisClient rediscli.Client, pool *vmpool.Pool) (triggered bool, abortFeatures bool, err error) {
	type featResult struct {
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

	plan, err := pipeline.BuildPlan(featurePipelineNodes(LuaFeatures.LuaScripts), requestFeatureMode(r))
	if err != nil {
		return false, false, err
	}

	var statusSet bool
	for _, level := range plan.Levels {
		var (
			mu           sync.Mutex
			levelResults = make([]*featResult, 0, len(level))
		)

		g, egCtx := errgroup.WithContext(ctx)

		for _, planned := range level {
			idx := planned.Index
			feature := planned.Value.(*LuaFeature)

			g.Go(func() error {
				util.DebugModuleWithCfg(egCtx, cfg, logger, definitions.DbgFeature,
					definitions.LogKeyGUID, r.Session,
					definitions.LogKeyMsg, "Executing feature script",
					"name", feature.Name,
				)

				Llocal, acqErr := pool.Acquire(egCtx)
				if acqErr != nil {
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
				}()

				localContext := r.Clone()
				contextBefore := localContext.Snapshot()
				localLogs := new(lualib.CustomLogKeyValue)

				var localStatus *string

				lualib.SetBuiltinTableForFeature(
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

				stopTimer := stats.PrometheusTimer(cfg, definitions.PromFeature, feature.Name, ctx.FullPath())

				luaCtx, luaCancel := context.WithTimeout(egCtx, cfg.GetServer().GetTimeouts().GetLuaScript())
				defer luaCancel()

				Llocal.SetContext(luaCtx)

				luapool.PrepareRequestEnv(Llocal)

				modManager := luamod.NewModuleManager(ctx, cfg, logger, redisClient)

				modManager.BindAllDefault(Llocal, localRequest.Context, luaCtx, tolerate.GetTolerate())

				if ctx != nil && ctx.Request != nil {
					modManager.BindHTTP(Llocal, lualib.NewHTTPMetaFromRequest(ctx.Request))
				}

				modManager.BindHTTPResponse(Llocal, ctx)
				modManager.BindLDAP(Llocal, backend.LoaderModLDAP(luaCtx, cfg))

				fr := &featResult{name: feature.Name, scriptIdx: idx, statusText: &localStatus}

				if e := lualib.PackagePath(Llocal, cfg); e != nil {
					r.handleError(logger, luaCancel, e, feature.Name, stopTimer)

					return e
				}

				if e := lualib.DoCompiledFile(Llocal, feature.CompiledScript); e != nil {
					r.handleError(logger, luaCancel, e, feature.Name, stopTimer)

					return e
				}

				callFeaturesFunc := lua.LNil
				if v := Llocal.GetGlobal("__NAUTH_REQ_ENV"); v != nil && v.Type() == lua.LTTable {
					if fn := Llocal.GetField(v, definitions.LuaFnCallFeature); fn != nil {
						callFeaturesFunc = fn
					}
				}

				if callFeaturesFunc == lua.LNil {
					callFeaturesFunc = Llocal.GetGlobal(definitions.LuaFnCallFeature)
				}

				if callFeaturesFunc.Type() == lua.LTFunction {
					if e := Llocal.CallByParam(lua.P{Fn: callFeaturesFunc, NRet: 3, Protect: true}, request); e != nil {
						r.handleError(logger, luaCancel, e, feature.Name, stopTimer)

						return e
					}

					ret := Llocal.ToInt(-1)
					Llocal.Pop(1)
					ab := Llocal.ToBool(-1)
					Llocal.Pop(1)
					tr := Llocal.ToBool(-1)
					Llocal.Pop(1)
					fr.ret = ret
					fr.abort = ab
					fr.triggered = tr
				}

				fr.logs = *localLogs
				fr.contextDelta = localRequest.Diff(contextBefore)
				logs := []any{
					definitions.LogKeyGUID, r.Session,
					"name", feature.Name,
					definitions.LogKeyMsg, "Lua feature finished",
					"triggered", fr.triggered,
					"abort_features", fr.abort,
					"result", func() string { return r.formatResult(fr.ret) }(),
				}

				if len(fr.logs) > 0 {
					for i := range fr.logs {
						logs = append(logs, fr.logs[i])
					}
				}

				util.DebugModuleWithCfg(egCtx, cfg, logger, definitions.DbgFeature, logs...)

				if stopTimer != nil {
					stopTimer()
				}

				mu.Lock()
				levelResults = append(levelResults, fr)
				mu.Unlock()

				return nil
			})
		}

		if e := g.Wait(); e != nil {
			return false, false, e
		}

		sort.Slice(levelResults, func(i, j int) bool {
			return levelResults[i].scriptIdx < levelResults[j].scriptIdx
		})

		for _, fr := range levelResults {
			if fr.err != nil {
				return false, false, fr.err
			}

			if fr.abort {
				abortFeatures = true
			}

			if fr.triggered {
				triggered = true
			}

			r.ApplyDelta(fr.contextDelta)
			lualib.MergeStatusAndLogs(&statusSet, &r.Logs, &r.StatusMessage, *fr.statusText, fr.logs)
		}
	}

	return triggered, abortFeatures, nil
}

// handleError logs the error message and cancels the Lua context.
func (r *Request) handleError(logger *slog.Logger, luaCancel context.CancelFunc, err error, scriptName string, stopTimer func()) {
	// Include Lua stacktrace when available for better diagnostics
	if ae, ok := stderrors.AsType[*lua.ApiError](err); ok && ae != nil {
		level.Error(logger).Log(
			definitions.LogKeyGUID, r.Session,
			"name", scriptName,
			definitions.LogKeyMsg, "Lua feature failed",
			definitions.LogKeyError, ae.Error(),
			"stacktrace", ae.StackTrace,
		)
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
