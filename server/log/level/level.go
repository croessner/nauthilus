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
	"log/slog"
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
func (s *slogLevelLogger) Log(keyvals ...any) error {
	var msg string

	attrs := make([]slog.Attr, 0, len(keyvals))
	for i := 0; i+1 < len(keyvals); i += 2 {
		k, ok := keyvals[i].(string)
		if !ok {
			continue
		}

		if k == "msg" {
			if v, ok := keyvals[i+1].(string); ok {
				msg = v

				continue
			}
		}

		attrs = append(attrs, slog.Any(k, keyvals[i+1]))
	}

	if msg == "" {
		msg = levelToDefaultMessage(s.lvl)
	}

	s.l.LogAttrs(s.ctx, s.lvl, msg, attrs...)

	return nil
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
