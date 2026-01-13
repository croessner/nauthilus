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

// Package level is a thin compatibility wrapper that mimics common go-kit/log/level
// usage patterns while delegating to the Go standard library's log/slog package.
//
// It enables transitional code like: level.Info(logger).Log("msg", "hello", "k", 1)
// to continue working while using slog levels and structured attributes under the hood.
package level

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/croessner/nauthilus/server/definitions"
	monittrace "github.com/croessner/nauthilus/server/monitoring/trace"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// lazyFormat implements slog.LogValuer to defer expensive reflection and formatting
// until the logger actually handles the log record.
type lazyFormat struct {
	val any
}

// LogValue returns a slog.Value representation of the wrapped value, deferring expensive formatting until needed.
func (l lazyFormat) LogValue() slog.Value {
	rt := reflect.TypeOf(l.val)
	if rt == nil {
		return slog.StringValue("<nil>")
	}

	rv := reflect.ValueOf(l.val)

	switch rt.Kind() {
	case reflect.Slice:
		return slog.StringValue(fmt.Sprintf("<slice %s len=%d>", rt.String(), rv.Len()))
	case reflect.Map:
		return slog.StringValue(fmt.Sprintf("<map %s len=%d>", rt.String(), rv.Len()))
	default:
		return slog.StringValue(fmt.Sprintf("<unsupported %T>", l.val))
	}
}

// Logger is an interface for logging key-value pairs with a flexible and customizable structure.
type Logger interface {
	Log(keyvals ...any) error
}

// slogLevelLogger is a structured logger that logs messages at a specified slog.Level with additional configuration.
// It wraps a slog.Logger, supports optional context, and allows source information to be included in log entries.
type slogLevelLogger struct {
	l         *slog.Logger
	lvl       slog.Level
	ctx       context.Context
	addSource bool
}

// defaultAddSource determines if source information (e.g., file and line) is included in log records by default.
var globalAddSource atomic.Bool

// ApplyGlobalConfig sets the global configuration for including source information in log records.
func ApplyGlobalConfig(addSource bool) {
	globalAddSource.Store(addSource)
}

// WithContext allows attaching a context to the logger used for emission.
// The returned logger uses LevelInfo by default.
func WithContext(ctx context.Context, l *slog.Logger) Logger {
	return &slogLevelLogger{l: l, lvl: slog.LevelInfo, ctx: ctx, addSource: globalAddSource.Load()}
}

// Debug returns a Logger that logs at slog.LevelDebug.
func Debug(l *slog.Logger) Logger {
	return &slogLevelLogger{l: l, lvl: slog.LevelDebug, addSource: globalAddSource.Load()}
}

// Info returns a Logger that logs at slog.LevelInfo.
func Info(l *slog.Logger) Logger {
	return &slogLevelLogger{l: l, lvl: slog.LevelInfo, addSource: globalAddSource.Load()}
}

// Notice returns a Logger that logs at a custom NOTICE level placed between info and warn (INFO+2).
// The numeric value aligns with slog.LevelInfo + definitions.SlogNoticeLevelOffset.
func Notice(l *slog.Logger) Logger {
	return &slogLevelLogger{l: l, lvl: slog.LevelInfo + definitions.SlogNoticeLevelOffset, addSource: globalAddSource.Load()}
}

// Warn returns a Logger that logs at slog.LevelWarn.
func Warn(l *slog.Logger) Logger {
	return &slogLevelLogger{l: l, lvl: slog.LevelWarn, addSource: globalAddSource.Load()}
}

// Error returns a Logger that logs at slog.LevelError.
func Error(l *slog.Logger) Logger {
	return &slogLevelLogger{l: l, lvl: slog.LevelError, addSource: globalAddSource.Load()}
}

// Log implements Logger. It parses the keyvals, extracts an optional "msg"
// string, and forwards the remaining pairs as attributes to slog on the
// configured level. Unknown or invalid key/value pairs are skipped.
func (s *slogLevelLogger) Log(keyvals ...any) (err error) {
	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	tracer := monittrace.New("nauthilus/log/level")
	spCtx, sp := tracer.Start(ctx, "level.Log")

	defer sp.End()

	defer func() {
		if r := recover(); r != nil {
			sp.RecordError(errors.New(fmt.Sprint(r)))
			sp.SetStatus(codes.Error, "recovered from panic")

			// Minimal like go-kit: emit only the callsite, drop the problematic entry
			pc, file, line, _ := runtime.Caller(2)
			fn := runtime.FuncForPC(pc)
			fnName := "?"

			if fn != nil {
				fnName = fn.Name()
			}

			fmt.Fprintf(os.Stderr, "[logger-recover] %s at %s:%d (%s)\n",
				time.Now().Format(time.RFC3339Nano), file, line, fnName)

			err = fmt.Errorf("logger panic recovered")
		}
	}()

	// Ensure we have a logger and context first
	l := s.l
	if l == nil {
		l = slog.Default()
	}

	// Early-out if level is disabled: do no work
	if !l.Enabled(spCtx, s.lvl) {
		return nil
	}

	var msg string

	// Search only for "msg" to avoid full iteration if possible
	// and collect attributes directly.
	pc := uintptr(0)
	if s.addSource {
		if p, _, _, ok := runtime.Caller(2); ok {
			pc = p
		}
	}

	record := slog.NewRecord(time.Now(), s.lvl, "", pc)

	for i := 0; i < len(keyvals); i += 2 {
		k, ok := keyvals[i].(string)
		if !ok {
			continue
		}

		if i+1 >= len(keyvals) {
			break
		}

		v := keyvals[i+1]

		if k == "msg" {
			if vs, ok := v.(string); ok {
				msg = vs

				continue
			}
		}

		// Instead of a massive switch, we only handle our
		// "Special Formatting" cases and let slog.Record.AddAttrs handle the rest.
		// slog.Any is extremely optimized when called via Record.AddAttrs.
		switch vv := v.(type) {
		case string, bool, int, int64, uint64, float64, time.Time, time.Duration:
			// No reflection here! Direct pass-through to slog.
			record.AddAttrs(slog.Any(k, vv))
		case error:
			if vv == nil {
				record.AddAttrs(slog.String(k, "<nil error>"))
			} else {
				record.AddAttrs(slog.String(k, vv.Error()))
			}
		case fmt.Stringer:
			if vv == nil {
				record.AddAttrs(slog.String(k, "<nil Stringer>"))
			} else {
				record.AddAttrs(slog.String(k, vv.String()))
			}
		case nil:
			record.AddAttrs(slog.String(k, "<nil>"))
		default:
			// Use a custom Valuer for Slices/Maps to defer fmt.Sprintf
			// until the log is actually written.
			rt := reflect.TypeOf(vv)
			if rt != nil && (rt.Kind() == reflect.Slice || rt.Kind() == reflect.Map) {
				record.AddAttrs(slog.Any(k, lazyFormat{vv}))
			} else {
				record.AddAttrs(slog.Any(k, v))
			}
		}
	}

	if msg == "" {
		msg = levelToDefaultMessage(s.lvl, sp)
	}

	record.Message = msg

	return l.Handler().Handle(ctx, record)
}

func levelToDefaultMessage(lvl slog.Level, sp trace.Span) string {
	switch lvl {
	case slog.LevelDebug:
		sp.AddEvent("debug")
		sp.SetAttributes(attribute.String("level", "debug"))

		return "debug"
	case slog.LevelInfo:
		sp.AddEvent("info")
		sp.SetAttributes(attribute.String("level", "info"))

		return "info"
	case slog.LevelInfo + definitions.SlogNoticeLevelOffset:
		sp.AddEvent("notice")
		sp.SetAttributes(attribute.String("level", "notice"))

		return "notice"
	case slog.LevelWarn:
		sp.AddEvent("warn")
		sp.SetAttributes(attribute.String("level", "warn"))

		return "warn"
	case slog.LevelError:
		sp.AddEvent("error")
		sp.SetAttributes(attribute.String("level", "error"))

		return "error"
	default:
		sp.AddEvent("log")
		sp.SetAttributes(attribute.String("level", "log"))

		return "log"
	}
}
