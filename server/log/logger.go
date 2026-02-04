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

package log

import (
	"context"
	"io"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"

	"github.com/croessner/nauthilus/server/definitions"
	logcolor "github.com/croessner/nauthilus/server/log/color"
)

var (
	mu         sync.Mutex
	rootLogger *dynamicHandlerRoot

	// Logger is used for all messages that are printed to stdout
	Logger *slog.Logger
)

func init() {
	SetupLogging(definitions.LogLevelInfo, false, true, false, "")
}

// GetLogger returns the global logger instance.
func GetLogger() *slog.Logger {
	return Logger
}

type dynamicHandlerRoot struct {
	inner    atomic.Value // stores *handlerHolder
	instance atomic.Value // stores *stringHolder
	levelVar slog.LevelVar
}

type handlerHolder struct {
	h slog.Handler
}

type stringHolder struct {
	s string
}

type dynamicHandler struct {
	root   *dynamicHandlerRoot
	attrs  []slog.Attr
	groups []string

	cachedHandler slog.Handler
	cachedRootVal any
}

func (h *dynamicHandler) Enabled(ctx context.Context, level slog.Level) bool {
	cur := h.current()
	if cur == nil {
		return false
	}

	return cur.Enabled(ctx, level)
}

func (h *dynamicHandler) Handle(ctx context.Context, r slog.Record) error {
	cur := h.current()
	if cur == nil {
		return nil
	}

	if h.root != nil {
		if v := h.root.instance.Load(); v != nil {
			if inst, ok := v.(*stringHolder); ok && inst != nil && inst.s != "" {
				r.AddAttrs(slog.String(definitions.LogKeyInstance, inst.s))
			}
		}
	}

	return cur.Handle(ctx, r)
}

func (h *dynamicHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}

	next := &dynamicHandler{
		root:   h.root,
		groups: h.groups,
		attrs:  make([]slog.Attr, 0, len(h.attrs)+len(attrs)),
	}

	next.attrs = append(next.attrs, h.attrs...)
	next.attrs = append(next.attrs, attrs...)

	return next
}

func (h *dynamicHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}

	next := &dynamicHandler{
		root:  h.root,
		attrs: h.attrs,
	}

	if len(h.groups) > 0 {
		next.groups = make([]string, 0, len(h.groups)+1)
		next.groups = append(next.groups, h.groups...)
		next.groups = append(next.groups, name)
	} else {
		next.groups = []string{name}
	}

	return next
}

func (h *dynamicHandler) current() slog.Handler {
	if h == nil || h.root == nil {
		return nil
	}

	v := h.root.inner.Load()
	if v == nil {
		return nil
	}

	if v == h.cachedRootVal && h.cachedHandler != nil {
		return h.cachedHandler
	}

	holder, ok := v.(*handlerHolder)
	if !ok || holder == nil || holder.h == nil {
		return nil
	}

	cur := holder.h

	for _, g := range h.groups {
		cur = cur.WithGroup(g)
	}

	if len(h.attrs) > 0 {
		cur = cur.WithAttrs(h.attrs)
	}

	h.cachedHandler = cur
	h.cachedRootVal = v

	return cur
}

// SetupLogging initializes the global "Logger" object.
// It is safe to call multiple times; subsequent calls reconfigure the logger.
func SetupLogging(configLogLevel int, formatJSON bool, useColor bool, addSource bool, instance string) {
	mu.Lock()
	defer mu.Unlock()

	// Map configLogLevel to slog level
	var minLevel slog.Level

	switch configLogLevel {
	case definitions.LogLevelNone:
		// Level value is irrelevant when output is discarded; keep a sane default
		minLevel = slog.LevelInfo
	case definitions.LogLevelError:
		minLevel = slog.LevelError
	case definitions.LogLevelWarn:
		minLevel = slog.LevelWarn
	case definitions.LogLevelNotice:
		// Custom NOTICE sits between info and warn
		minLevel = slog.LevelInfo + definitions.SlogNoticeLevelOffset
	case definitions.LogLevelInfo:
		minLevel = slog.LevelInfo
	case definitions.LogLevelDebug:
		minLevel = slog.LevelDebug
	default:
		minLevel = slog.LevelInfo
	}

	// ReplaceAttr maps custom level values to well-known names (e.g., NOTICE instead of INFO+2).
	replaceAttr := func(groups []string, a slog.Attr) slog.Attr {
		if a.Key == slog.LevelKey {
			if lv, ok := a.Value.Any().(slog.Level); ok {
				if lv == slog.LevelInfo+definitions.SlogNoticeLevelOffset {
					a.Value = slog.StringValue("NOTICE")
				}
			}
		}

		return a
	}

	if rootLogger == nil {
		rootLogger = &dynamicHandlerRoot{}
	}

	rootLogger.levelVar.Set(minLevel)
	rootLogger.instance.Store(&stringHolder{s: instance})

	handlerOpts := &slog.HandlerOptions{Level: &rootLogger.levelVar, AddSource: addSource, ReplaceAttr: replaceAttr}

	// Choose output target: for LogLevelNone, discard everything using io.Discard
	var out io.Writer = os.Stdout
	if configLogLevel == definitions.LogLevelNone {
		out = io.Discard
	}

	var handler slog.Handler

	termTheme := os.Getenv("NAUTHILUS_TERM_THEME")

	if formatJSON {
		// JSON output should never be colored
		handler = slog.NewJSONHandler(out, handlerOpts)
	} else if useColor && configLogLevel != definitions.LogLevelNone {
		// Use wrapper to preserve TextHandler format while coloring full line; theme-aware colors
		colors := logcolor.ThemeColorMap(termTheme)
		handler = logcolor.NewLineWrapper(out, handlerOpts, colors)
	} else {
		handler = slog.NewTextHandler(out, handlerOpts)
	}

	rootLogger.inner.Store(&handlerHolder{h: handler})
	if Logger == nil {
		Logger = slog.New(&dynamicHandler{root: rootLogger})
	}
}
