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
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"runtime"
	"runtime/debug"
	"time"
)

// Logger is compatible with the minimal subset of the go-kit Logger interface
// that is used together with go-kit/log/level: a Log method accepting keyvals.
//
// The Log method accepts alternating key/value pairs (like slog and go-kit).
// Non-string keys are ignored. If a key "msg" with a string value is present,
// it will be used as the record message; otherwise a level-specific default is used.
// The remaining pairs are emitted as structured attributes via slog.
// An odd trailing key without value is ignored.
//
// Example:
//
//	level.Warn(slogLogger).Log("msg", "deprecated", "feature", "x")
//	level.Debug(slogLogger).Log("k", 1, "x", 2) // message defaults to "debug"
//
// Note: The emitted level is provided by slog and shouldn't be redundantly stored
// as an attribute named "level".
//
// This package is intended for migration only. Prefer direct slog use over time.
type Logger interface {
	Log(keyvals ...any) error
}

type slogLevelLogger struct {
	l   *slog.Logger
	lvl slog.Level
	ctx context.Context
}

// WithContext allows attaching a context to the logger used for emission.
// The returned logger uses LevelInfo by default.
func WithContext(ctx context.Context, l *slog.Logger) Logger {
	return &slogLevelLogger{l: l, lvl: slog.LevelInfo, ctx: ctx}
}

// Debug returns a Logger that logs at slog.LevelDebug.
func Debug(l *slog.Logger) Logger {
	return &slogLevelLogger{l: l, lvl: slog.LevelDebug}
}

// Info returns a Logger that logs at slog.LevelInfo.
func Info(l *slog.Logger) Logger {
	return &slogLevelLogger{l: l, lvl: slog.LevelInfo}
}

// Warn returns a Logger that logs at slog.LevelWarn.
func Warn(l *slog.Logger) Logger {
	return &slogLevelLogger{l: l, lvl: slog.LevelWarn}
}

// Error returns a Logger that logs at slog.LevelError.
func Error(l *slog.Logger) Logger {
	return &slogLevelLogger{l: l, lvl: slog.LevelError}
}

// Log implements Logger. It parses the keyvals, extracts an optional "msg"
// string, and forwards the remaining pairs as attributes to slog on the
// configured level. Unknown or invalid key/value pairs are skipped.
func (s *slogLevelLogger) Log(keyvals ...any) (err error) {
	defer func() {
		if r := recover(); r != nil {
			var buf bytes.Buffer
			fmt.Fprintf(&buf, "[logger-recover] %s panic: %v\n", time.Now().Format(time.RFC3339Nano), r)
			fmt.Fprintf(&buf, "keyvals=%#v\n", keyvals)
			buf.Write(debug.Stack())
			_, _ = os.Stderr.Write(buf.Bytes())

			// Safe best-effort:
			_ = slog.Default().With("logger", "recover").
				Handler().Handle(context.Background(), slog.Record{Time: time.Now(), Level: slog.LevelError, Message: "logger panic recovered"})

			err = fmt.Errorf("logger panic: %v", r)
		}
	}()

	var msg string

	attrs := make([]slog.Attr, 0, len(keyvals))
	for i := 0; i+1 < len(keyvals); i += 2 {
		k, ok := keyvals[i].(string)
		if !ok {
			continue
		}

		v := keyvals[i+1]

		if k == "msg" {
			if vs, ok := v.(string); ok {
				msg = vs

				continue
			}
		}

		// Point 2: lightweight detection of problematic values to pinpoint callsite
		if rv, ok := v.(reflect.Value); ok {
			if !rv.IsValid() {
				logDetect(k, "invalid reflect.Value")
			}
		}

		if _, ok := v.(fmt.Stringer); ok {
			if isTypedNil(v) { // typed-nil that would panic if String() is called
				logDetect(k, "typed-nil fmt.Stringer")
			}
		}

		if _, ok := v.(fmt.GoStringer); ok {
			if isTypedNil(v) { // typed-nil that would panic if GoString() is called
				logDetect(k, "typed-nil fmt.GoStringer")
			}
		}

		// Guard against typed-nil values that can make slog.Any panic.
		if isTypedNil(v) {
			attrs = append(attrs, slog.String(k, "<nil>"))

			continue
		}

		switch vv := v.(type) {
		case string:
			attrs = append(attrs, slog.String(k, vv))
		default:
			attrs = append(attrs, slog.Any(k, vv))
		}
	}

	if msg == "" {
		msg = levelToDefaultMessage(s.lvl)
	}

	// Ensure we have a logger and a non-nil context to avoid panics
	l := s.l
	if l == nil {
		l = slog.Default()
	}

	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	l.LogAttrs(ctx, s.lvl, msg, attrs...)

	return nil
}

// isTypedNil reports whether v is nil or a typed-nil (e.g., (*T)(nil), []T(nil), map[K]V(nil)).
func isTypedNil(v any) bool {
	if v == nil {
		return true
	}

	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Map, reflect.Pointer, reflect.Interface, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}

func levelToDefaultMessage(lvl slog.Level) string {
	switch lvl {
	case slog.LevelDebug:
		return "debug"
	case slog.LevelInfo:
		return "info"
	case slog.LevelWarn:
		return "warn"
	case slog.LevelError:
		return "error"
	default:
		return "log"
	}
}

// logDetect writes a minimal, panic-safe diagnostic line to stderr identifying
// the callsite and the problematic key when suspicious values are observed.
// It intentionally avoids invoking any user code (e.g., String()/GoString()).
func logDetect(key, what string) {
	defer func() { _ = recover() }()
	pc, file, line, _ := runtime.Caller(2)
	fn := runtime.FuncForPC(pc)
	fnName := "?"

	if fn != nil {
		fnName = fn.Name()
	}

	// Keep it one line and simple to make it grep-friendly.
	fmt.Fprintf(os.Stderr, "[logger-detect] %s key=%q issue=%s at %s:%d (%s)\n",
		time.Now().Format(time.RFC3339Nano), key, what, file, line, fnName)
}
