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

	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	// Early-out if level is disabled: do no work
	if !l.Enabled(ctx, s.lvl) {
		return nil
	}

	// Ensure even number of elements; drop a trailing key w/o value
	if len(keyvals)%2 == 1 {
		keyvals = keyvals[:len(keyvals)-1]
	}

	var msg string
	attrs := make([]slog.Attr, 0, len(keyvals))

	for i := 0; i < len(keyvals); i += 2 {
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

		switch vv := v.(type) {
		case nil:
			attrs = append(attrs, slog.String(k, "<nil>"))
		case string:
			attrs = append(attrs, slog.String(k, vv))
		case bool:
			attrs = append(attrs, slog.Bool(k, vv))
		case int:
			attrs = append(attrs, slog.Int(k, vv))
		case int8:
			attrs = append(attrs, slog.Int(k, int(vv)))
		case int16:
			attrs = append(attrs, slog.Int(k, int(vv)))
		case int32:
			attrs = append(attrs, slog.Int(k, int(vv)))
		case int64:
			attrs = append(attrs, slog.Int64(k, vv))
		case uint:
			attrs = append(attrs, slog.Uint64(k, uint64(vv)))
		case uint8:
			attrs = append(attrs, slog.Uint64(k, uint64(vv)))
		case uint16:
			attrs = append(attrs, slog.Uint64(k, uint64(vv)))
		case uint32:
			attrs = append(attrs, slog.Uint64(k, uint64(vv)))
		case uint64:
			attrs = append(attrs, slog.Uint64(k, vv))
		case float32:
			attrs = append(attrs, slog.Float64(k, float64(vv)))
		case float64:
			attrs = append(attrs, slog.Float64(k, vv))
		case time.Duration:
			attrs = append(attrs, slog.String(k, vv.String()))
		case time.Time:
			attrs = append(attrs, slog.Time(k, vv))
		case error:
			if vv == nil {
				attrs = append(attrs, slog.String(k, "<nil error>"))
			} else {
				attrs = append(attrs, slog.String(k, vv.Error()))
			}
		case fmt.Stringer:
			if vv == nil {
				attrs = append(attrs, slog.String(k, "<nil Stringer>"))
			} else {
				attrs = append(attrs, slog.String(k, vv.String()))
			}
		case []byte:
			// Allow binary payloads; handlers (e.g., JSON) will encode suitably
			attrs = append(attrs, slog.Any(k, vv))
		default:
			// Handle slices and maps minimally without formatting contents
			rt := reflect.TypeOf(vv)
			rv := reflect.ValueOf(vv)

			if rt.Kind() == reflect.Slice {
				attrs = append(attrs, slog.String(k, fmt.Sprintf("<slice %s len=%d>", rt.String(), rv.Len())))
			} else if rt.Kind() == reflect.Map {
				attrs = append(attrs, slog.String(k, fmt.Sprintf("<map %s len=%d>", rt.String(), rv.Len())))
			} else {
				// Like go-kit minimalism: don't try to be clever; just mark unsupported
				attrs = append(attrs, slog.String(k, fmt.Sprintf("<unsupported %T>", vv)))
			}
		}
	}

	if msg == "" {
		msg = levelToDefaultMessage(s.lvl)
	}

	// Emit via handler with explicit PC so AddSource resolves the real caller
	pc := uintptr(0)
	if p, _, _, ok := runtime.Caller(2); ok {
		pc = p
	}

	r := slog.NewRecord(time.Now(), s.lvl, msg, pc)
	r.AddAttrs(attrs...)

	return l.Handler().Handle(ctx, r)
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
