package log

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/croessner/nauthilus/v4/server/definitions"
)

// TestNoticeFieldFilter verifies final output, including bound and grouped attributes.
func TestNoticeFieldFilter(t *testing.T) {
	for _, test := range []struct {
		name     string
		level    slog.Level
		ignore   []string
		filtered bool
	}{
		{"unset", slog.LevelInfo + definitions.SlogNoticeLevelOffset, nil, false},
		{"notice", slog.LevelInfo + definitions.SlogNoticeLevelOffset, []string{"builtin", "additional", "bound", "nested", "source"}, true},
		{"warn", slog.LevelWarn, []string{"builtin", "additional", "bound", "nested"}, false},
		{"info", slog.LevelInfo, []string{"builtin", "additional", "bound", "nested"}, false},
		{"error", slog.LevelError, []string{"builtin", "additional", "bound", "nested"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer

			opts := &slog.HandlerOptions{ReplaceAttr: noticeLevelReplaceAttr}
			normal := slog.NewJSONHandler(&output, opts)
			filter := newNoticeFieldFilter(test.ignore)
			opts.ReplaceAttr = filter.replaceAttr
			handler := &noticeFieldHandler{normal: normal, notice: slog.NewJSONHandler(&output, opts)}
			logger := slog.New(handler).With("bound", "value").WithGroup("request").With("nested", "value")
			logger.Log(context.Background(), test.level, "message", "builtin", "value", "additional", "value", "session", "id", "keep", true)

			var entry map[string]any
			if err := json.Unmarshal(output.Bytes(), &entry); err != nil {
				t.Fatal(err)
			}

			fields := entry["request"].(map[string]any)
			if fields["session"] != "id" {
				t.Fatal("session missing")
			}

			if entry["msg"] != "message" {
				t.Fatal("message missing")
			}

			if _, ok := entry["time"]; !ok {
				t.Fatal("time missing")
			}

			for _, key := range []string{"builtin", "additional", "nested"} {
				_, exists := fields[key]
				if exists == test.filtered {
					t.Errorf("unexpected presence of %s: %v", key, exists)
				}
			}

			_, exists := entry["bound"]
			if exists == test.filtered {
				t.Errorf("unexpected bound field presence: %v", exists)
			}
		})
	}
}

// TestNoticeFilterReload exercises configured encoders and previously derived loggers.
func TestNoticeFilterReload(t *testing.T) {
	for _, format := range []struct {
		name  string
		json  bool
		color bool
	}{
		{"json", true, false},
		{"text", false, false},
		{"color", false, true},
	} {
		t.Run(format.name, func(t *testing.T) {
			output, err := os.CreateTemp(t.TempDir(), "notice-output")
			if err != nil {
				t.Fatal(err)
			}

			stdout, previousLogger, previousRoot := os.Stdout, Logger, rootLogger
			os.Stdout = output
			Logger, rootLogger = nil, nil

			t.Cleanup(func() {
				os.Stdout, Logger, rootLogger = stdout, previousLogger, previousRoot
				_ = output.Close()
			})

			SetupLogging(definitions.LogLevelDebug, format.json, format.color, true, "test-instance")

			logger := Logger.With("bound", "bound-value")
			emit := func() {
				logger.Log(context.Background(), slog.LevelInfo+definitions.SlogNoticeLevelOffset, "notice-message", "additional", "extra-value", "session", "session-id")
			}
			emit()
			SetupLogging(definitions.LogLevelDebug, format.json, format.color, true, "test-instance", "bound", "additional", "source", "time", "level", "instance", "session", "msg")
			emit()
			SetupLogging(definitions.LogLevelDebug, format.json, format.color, true, "test-instance")
			emit()
			assertNoticeReloadOutput(t, output.Name())
		})
	}
}

// assertNoticeReloadOutput checks removal, protected fields, and reset across encoder formats.
func assertNoticeReloadOutput(t *testing.T, path string) {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d records, want 3", len(lines))
	}

	for index, line := range lines {
		for _, key := range []string{"bound", "additional", "source"} {
			if strings.Contains(line, key) != (index != 1) {
				t.Errorf("record %d: unexpected presence of %s", index, key)
			}
		}

		for _, value := range []string{"time", "NOTICE", "test-instance", "session-id", "notice-message"} {
			if !strings.Contains(line, value) {
				t.Errorf("record %d: missing required value %s", index, value)
			}
		}
	}
}
