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

// Package color provides ANSI color helpers and a slog.Handler wrapper
// that preserves slog.TextHandler formatting while coloring entire lines.
package color

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"strings"
)

const (
	ansiReset = "\x1b[0m"

	// Standard intensity foreground colors (work better on light backgrounds)
	fgRed    = "\x1b[31m"
	fgYellow = "\x1b[33m"
	fgGreen  = "\x1b[32m"
	fgCyan   = "\x1b[36m"

	// Bright/high-intensity foreground colors (better on dark backgrounds)
	fgBrightRed    = "\x1b[91m"
	fgBrightYellow = "\x1b[93m"
	fgBrightGreen  = "\x1b[92m"
	fgBrightCyan   = "\x1b[96m"
)

// ThemeColorMap returns a level->ANSI-color map for the given theme.
// Accepted theme values (case-insensitive): "dark", "light".
// Unknown or empty values default to the "light" mapping.
func ThemeColorMap(theme string) map[slog.Level]string {
	switch strings.ToLower(strings.TrimSpace(theme)) {
	case "dark":
		return map[slog.Level]string{
			slog.LevelDebug: fgBrightCyan,
			slog.LevelInfo:  fgBrightGreen,
			slog.LevelWarn:  fgBrightYellow,
			slog.LevelError: fgBrightRed,
		}
	default: // "light" or unspecified
		return map[slog.Level]string{
			slog.LevelDebug: fgCyan,
			slog.LevelInfo:  fgGreen,
			slog.LevelWarn:  fgYellow,
			slog.LevelError: fgRed,
		}
	}
}

// LineWrapper delegates formatting to slog.TextHandler and wraps the
// whole resulting line in an ANSI foreground color based on the level.
// It preserves the exact output layout of slog.TextHandler.
type LineWrapper struct {
	out    io.Writer
	opts   *slog.HandlerOptions
	attrs  []slog.Attr
	groups []string

	// colors maps levels to ANSI foreground color codes.
	colors map[slog.Level]string
}

// NewLineWrapper creates a new LineWrapper. If colors is nil, sensible
// defaults are used for Debug/Info/Warn/Error.
func NewLineWrapper(out io.Writer, opts *slog.HandlerOptions, colors map[slog.Level]string) *LineWrapper {
	if colors == nil {
		colors = ThemeColorMap("") // default to light mapping
	}

	return &LineWrapper{out: out, opts: opts, colors: colors}
}

// Enabled determines if the given logging level is enabled based on the handler's configuration and options.
func (h *LineWrapper) Enabled(ctx context.Context, lvl slog.Level) bool {
	_ = ctx

	if h.opts == nil || h.opts.Level == nil {
		return true
	}

	return lvl >= h.opts.Level.Level()
}

// Handle processes a logging record, formats it using TextHandler, wraps it with ANSI coloring, and writes to output.
func (h *LineWrapper) Handle(ctx context.Context, r slog.Record) error {
	// 1) Render with standard TextHandler into a buffer.
	var buf bytes.Buffer

	inner := slog.NewTextHandler(&buf, h.opts)

	var ih slog.Handler = inner

	for _, g := range h.groups {
		ih = ih.WithGroup(g)
	}

	if len(h.attrs) > 0 {
		ih = ih.WithAttrs(h.attrs)
	}

	if err := ih.Handle(ctx, r); err != nil {
		return err
	}

	// 2) Wrap the entire line in ANSI color and write out.
	b := buf.Bytes()
	prefix := h.pickColor(r.Level)

	// Ensure color reset before final newline to avoid color bleed.
	n := len(b)
	if n > 0 && b[n-1] == '\n' {
		if _, err := io.WriteString(h.out, prefix); err != nil {
			return err
		}

		if _, err := h.out.Write(b[:n-1]); err != nil {
			return err
		}

		if _, err := io.WriteString(h.out, ansiReset); err != nil {
			return err
		}

		_, err := h.out.Write([]byte{'\n'})

		return err
	}

	if _, err := io.WriteString(h.out, prefix); err != nil {
		return err
	}

	if _, err := h.out.Write(b); err != nil {
		return err
	}

	_, err := io.WriteString(h.out, ansiReset)

	return err
}

// WithAttrs returns a new handler with the provided attributes appended to its existing attributes.
func (h *LineWrapper) WithAttrs(attrs []slog.Attr) slog.Handler {
	cp := *h
	if len(attrs) > 0 {
		cp.attrs = append(append([]slog.Attr(nil), h.attrs...), attrs...)
	}

	return &cp
}

// WithGroup returns a new handler with the specified group name appended to its existing group hierarchy.
func (h *LineWrapper) WithGroup(name string) slog.Handler {
	cp := *h
	cp.groups = append(append([]string(nil), h.groups...), name)

	return &cp
}

// pickColor selects an ANSI color string based on the provided logging level. It uses predefined mappings or defaults.
func (h *LineWrapper) pickColor(lvl slog.Level) string {
	if c, ok := h.colors[lvl]; ok {
		return c
	}

	if lvl >= slog.LevelError {
		return fgRed
	}

	if lvl <= slog.LevelDebug {
		return fgCyan
	}

	return fgGreen
}

var _ slog.Handler = (*LineWrapper)(nil)
