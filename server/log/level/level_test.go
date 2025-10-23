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

package level

import (
	"context"
	"log/slog"
	"sync"
	"testing"
)

type rec struct {
	Ctx     context.Context
	Level   slog.Level
	Message string
	Attrs   []slog.Attr
}

type memHandler struct {
	mu      sync.Mutex
	level   slog.Leveler
	records []rec
}

func newMemHandler(min slog.Leveler) *memHandler {
	return &memHandler{level: min, records: make([]rec, 0, 8)}
}

func (h *memHandler) Enabled(_ context.Context, lvl slog.Level) bool {
	if h.level == nil {
		return true
	}
	return lvl >= h.level.Level()
}

func (h *memHandler) Handle(ctx context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	attrs := make([]slog.Attr, 0, r.NumAttrs())
	r.Attrs(func(a slog.Attr) bool {
		attrs = append(attrs, a)
		return true
	})

	h.records = append(h.records, rec{
		Ctx:     ctx,
		Level:   r.Level,
		Message: r.Message,
		Attrs:   attrs,
	})
	return nil
}

func (h *memHandler) WithAttrs(attrs []slog.Attr) slog.Handler { return h }
func (h *memHandler) WithGroup(name string) slog.Handler       { return h }

func TestInfoLogWithMessage(t *testing.T) {
	h := newMemHandler(slog.LevelInfo)
	logger := slog.New(h)

	if err := Info(logger).Log("msg", "hello", "k", "v", "n", 1); err != nil {
		t.Fatalf("Log returned error: %v", err)
	}

	if len(h.records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(h.records))
	}
	r := h.records[0]
	if r.Level != slog.LevelInfo {
		t.Errorf("expected level info, got %v", r.Level)
	}
	if r.Message != "hello" {
		t.Errorf("expected message 'hello', got %q", r.Message)
	}
	// Check attrs include k=v and n=1
	want := map[string]string{"k": "v", "n": "1"}
	got := map[string]string{}
	for _, a := range r.Attrs {
		got[a.Key] = a.Value.String()
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("attr %q mismatch: want %v got %v", k, v, got[k])
		}
	}
}

func TestWarnLogWithoutMessageDefaults(t *testing.T) {
	h := newMemHandler(slog.LevelDebug)
	logger := slog.New(h)

	if err := Warn(logger).Log("k", "v"); err != nil {
		t.Fatalf("Log returned error: %v", err)
	}
	if len(h.records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(h.records))
	}
	r := h.records[0]
	if r.Level != slog.LevelWarn {
		t.Errorf("expected level warn, got %v", r.Level)
	}
	if r.Message != "warn" {
		t.Errorf("expected default message 'warn', got %q", r.Message)
	}
	if len(r.Attrs) != 1 || r.Attrs[0].Key != "k" || r.Attrs[0].Value.String() != "v" {
		t.Errorf("unexpected attrs: %+v", r.Attrs)
	}
}

func TestOddKeyvalsAreIgnoredGracefully(t *testing.T) {
	h := newMemHandler(slog.LevelDebug)
	logger := slog.New(h)

	// odd trailing key should be ignored, non-string key should be ignored
	if err := Debug(logger).Log("msg", "m", "ok", 1, 123, "x", "trailing"); err != nil {
		t.Fatalf("Log returned error: %v", err)
	}
	if len(h.records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(h.records))
	}
	r := h.records[0]
	if r.Message != "m" {
		t.Errorf("expected message 'm', got %q", r.Message)
	}
	got := map[string]string{}
	for _, a := range r.Attrs {
		got[a.Key] = a.Value.String()
	}
	if len(got) != 1 || got["ok"] != "1" {
		t.Errorf("unexpected attrs: %+v", got)
	}
}

func TestWithContextPropagatesToHandler(t *testing.T) {
	h := newMemHandler(slog.LevelDebug)
	logger := slog.New(h)

	ctx := context.WithValue(context.Background(), struct{}{}, "val")
	if err := WithContext(ctx, logger).Log("k", "v"); err != nil {
		t.Fatalf("Log returned error: %v", err)
	}
	if len(h.records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(h.records))
	}
	if h.records[0].Ctx == nil {
		t.Fatalf("expected context to be forwarded to handler")
	}
}
