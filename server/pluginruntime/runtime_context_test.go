// Copyright (C) 2026 Christian Roessner
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

package pluginruntime

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
)

const (
	runtimeContextBase      = "base"
	runtimeContextDeleteKey = "delete"
	runtimeContextFirst     = "first"
	runtimeContextNameKey   = "name"
	runtimeContextNestedKey = "nested"
	runtimeContextOriginal  = "original"
	runtimeContextSecond    = "second"
	runtimeContextSharedKey = "shared"
)

func TestRuntimeContextIsReadOnly(t *testing.T) {
	runtimeContext, err := NewRuntimeContext(map[string]any{
		runtimeContextNestedKey: map[string]any{runtimeContextNameKey: runtimeContextOriginal},
	})
	if err != nil {
		t.Fatalf("NewRuntimeContext() error = %v", err)
	}

	value, ok := runtimeContext.Get(runtimeContextNestedKey)
	if !ok {
		t.Fatal("Get() did not return nested value")
	}

	value.(map[string]any)[runtimeContextNameKey] = "changed"

	next, _ := runtimeContext.Get(runtimeContextNestedKey)
	if got := next.(map[string]any)[runtimeContextNameKey]; got != runtimeContextOriginal {
		t.Fatalf("runtime context was mutable through Get(): %v", got)
	}

	snapshot := runtimeContext.Snapshot()
	snapshot[runtimeContextNestedKey].(map[string]any)[runtimeContextNameKey] = "snapshot-changed"

	next, _ = runtimeContext.Get(runtimeContextNestedKey)
	if got := next.(map[string]any)[runtimeContextNameKey]; got != runtimeContextOriginal {
		t.Fatalf("runtime context was mutable through Snapshot(): %v", got)
	}
}

func TestRuntimeDeltaRejectsUnsupportedValues(t *testing.T) {
	err := ValidateRuntimeDelta(pluginapi.RuntimeDelta{
		Set: map[string]any{"unsupported": time.Now()},
	})

	if !errors.Is(err, ErrUnsupportedRuntimeValue) {
		t.Fatalf("ValidateRuntimeDelta() error = %v, want ErrUnsupportedRuntimeValue", err)
	}
}

func TestRuntimeDeltaMergeOrderIsDeterministic(t *testing.T) {
	merged, err := MergeRuntimeDeltas(
		context.Background(),
		map[string]any{runtimeContextSharedKey: runtimeContextBase, runtimeContextDeleteKey: true},
		&recordingRuntimeLogger{},
		pluginapi.RuntimeDelta{Set: map[string]any{runtimeContextSharedKey: runtimeContextFirst}},
		pluginapi.RuntimeDelta{Delete: []string{runtimeContextDeleteKey}, Set: map[string]any{runtimeContextSharedKey: runtimeContextSecond}},
	)
	if err != nil {
		t.Fatalf("MergeRuntimeDeltas() error = %v", err)
	}

	if got := merged[runtimeContextSharedKey]; got != runtimeContextSecond {
		t.Fatalf("merged shared value = %v, want second", got)
	}

	if _, ok := merged[runtimeContextDeleteKey]; ok {
		t.Fatal("merged runtime still contains deleted key")
	}
}

func TestRuntimeDeltaConflictLoggingIsBoundedAndSecretSafe(t *testing.T) {
	logger := &recordingRuntimeLogger{}

	deltas := make([]pluginapi.RuntimeDelta, 0, RuntimeDeltaConflictLogLimit+4)
	for index := range RuntimeDeltaConflictLogLimit + 4 {
		deltas = append(deltas, pluginapi.RuntimeDelta{
			Set: map[string]any{runtimeContextSharedKey: fmt.Sprintf("secret-value-%d", index)},
		})
	}

	if _, err := MergeRuntimeDeltas(context.Background(), map[string]any{runtimeContextSharedKey: runtimeContextBase}, logger, deltas...); err != nil {
		t.Fatalf("MergeRuntimeDeltas() error = %v", err)
	}

	if len(logger.records) != RuntimeDeltaConflictLogLimit {
		t.Fatalf("conflict log count = %d, want %d", len(logger.records), RuntimeDeltaConflictLogLimit)
	}

	for _, record := range logger.records {
		if strings.Contains(record.message, "secret-value-") {
			t.Fatal("conflict log message exposed a runtime value")
		}

		for _, field := range record.fields {
			if value, ok := field.Value.(string); ok && strings.Contains(value, "secret-value-") {
				t.Fatalf("conflict log field exposed a runtime value: %#v", record.fields)
			}
		}
	}
}

type runtimeLogRecord struct {
	message string
	fields  []pluginapi.LogField
}

type recordingRuntimeLogger struct {
	records []runtimeLogRecord
}

func (l *recordingRuntimeLogger) Debug(_ context.Context, message string, fields ...pluginapi.LogField) {
	l.records = append(l.records, runtimeLogRecord{message: message, fields: fields})
}

func (l *recordingRuntimeLogger) Info(context.Context, string, ...pluginapi.LogField) {}

func (l *recordingRuntimeLogger) Warn(context.Context, string, ...pluginapi.LogField) {}

func (l *recordingRuntimeLogger) Error(context.Context, string, ...pluginapi.LogField) {}
