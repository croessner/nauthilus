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
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/svcctx"
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
	WithContext(context.Context) Logger
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

// WithContext returns a new Logger instance bound to the specified context for contextual logging.
func (s *slogLevelLogger) WithContext(ctx context.Context) Logger {
	return &slogLevelLogger{l: s.l, lvl: s.lvl, ctx: ctx, addSource: s.addSource}
}

// Log implements Logger. It parses the keyvals, extracts an optional "msg"
// string, and forwards the remaining pairs as attributes to slog on the
// configured level. Unknown or invalid key/value pairs are skipped.
func (s *slogLevelLogger) Log(keyvals ...any) (err error) {
	ctx := s.ctx
	if ctx == nil {
		ctx = svcctx.Get()
	}

	defer recoverLoggerPanic(&err)

	// Ensure we have a logger and context first
	l := s.l
	if l == nil {
		l = slog.Default()
	}

	// Early-out if level is disabled: do no work
	if !l.Enabled(ctx, s.lvl) {
		return nil
	}

	record, msg := s.logRecordFromKeyvals(keyvals)

	if msg == "" {
		msg = levelToDefaultMessage(s.lvl)
	}

	record.Message = msg

	return l.Handler().Handle(ctx, record)
}

// recoverLoggerPanic records logger panics and emits a minimal recovery line.
func recoverLoggerPanic(err *error) {
	if r := recover(); r != nil {
		pc, file, line, _ := runtime.Caller(2)
		fn := runtime.FuncForPC(pc)

		fnName := "?"
		if fn != nil {
			fnName = fn.Name()
		}

		fmt.Fprintf(os.Stderr, "[logger-recover] %s at %s:%d (%s)\n",
			time.Now().Format(time.RFC3339Nano), file, line, fnName)

		*err = fmt.Errorf("logger panic recovered")
	}
}

// logRecordFromKeyvals builds a slog record and extracts the optional message.
func (s *slogLevelLogger) logRecordFromKeyvals(keyvals []any) (slog.Record, string) {
	pc := uintptr(0)

	if s.addSource {
		if p, _, _, ok := runtime.Caller(2); ok {
			pc = p
		}
	}

	record := slog.NewRecord(time.Now(), s.lvl, "", pc)
	msg := ""
	attrs := make([]slog.Attr, 0, len(keyvals)/2)

	for i := 0; i < len(keyvals); i += 2 {
		if i+1 >= len(keyvals) {
			break
		}

		k, ok := keyvals[i].(string)
		if !ok {
			continue
		}

		if setLogMessage(&msg, k, keyvals[i+1]) {
			continue
		}

		attrs = append(attrs, logAttr(k, keyvals[i+1]))
	}

	record.AddAttrs(attrs...)

	return record, msg
}

// setLogMessage extracts the special msg field.
func setLogMessage(msg *string, key string, value any) bool {
	if key != "msg" {
		return false
	}

	if valueString, ok := value.(string); ok {
		*msg = valueString

		return true
	}

	return false
}

// logAttr converts a key/value pair into a slog attribute.
func logAttr(key string, value any) slog.Attr {
	switch typed := value.(type) {
	case string, bool, int, int64, uint64, float64, time.Time, time.Duration:
		return slog.Any(key, typed)
	case error:
		return errorLogAttr(key, typed)
	case fmt.Stringer:
		return stringerLogAttr(key, typed)
	case nil:
		return slog.String(key, "<nil>")
	default:
		return defaultLogAttr(key, value)
	}
}

// errorLogAttr converts an error value into a slog attribute.
func errorLogAttr(key string, value error) slog.Attr {
	if value == nil {
		return slog.String(key, "<nil error>")
	}

	return slog.String(key, value.Error())
}

// stringerLogAttr converts a Stringer value into a slog attribute.
func stringerLogAttr(key string, value fmt.Stringer) slog.Attr {
	if value == nil {
		return slog.String(key, "<nil Stringer>")
	}

	return slog.String(key, value.String())
}

// defaultLogAttr converts maps and slices lazily while passing through other values.
func defaultLogAttr(key string, value any) slog.Attr {
	rt := reflect.TypeOf(value)
	if rt != nil && (rt.Kind() == reflect.Slice || rt.Kind() == reflect.Map) {
		return slog.Any(key, lazyFormat{value})
	}

	return slog.Any(key, value)
}

// levelToDefaultMessage maps a slog level to the compatibility message used when msg is absent.
func levelToDefaultMessage(lvl slog.Level) string {
	switch lvl {
	case slog.LevelDebug:
		return "debug"
	case slog.LevelInfo:
		return "info"
	case slog.LevelInfo + definitions.SlogNoticeLevelOffset:
		return "notice"
	case slog.LevelWarn:
		return "warn"
	case slog.LevelError:
		return "error"
	default:
		return "log"
	}
}

var _ Logger = (*slogLevelLogger)(nil)
