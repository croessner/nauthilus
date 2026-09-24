// Copyright (C) 2026 Christian Rößner
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

package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// sentinelTestConfig is a minimal valid configuration whose Redis block receives a sentinels block.
const sentinelTestConfig = `storage:
  redis:
    primary:
      address: localhost:6379
    password_nonce: nonce-secret-1234
    encryption_secret: redis-secret-1234
%s`

// sentinelConfig returns the minimal configuration with sentinels indented below storage.redis.
func sentinelConfig(sentinels string) string {
	indented := make([]string, 0)

	for line := range strings.SplitSeq(strings.TrimRight(sentinels, "\n"), "\n") {
		indented = append(indented, "    "+line)
	}

	return strings.Replace(sentinelTestConfig, "%s", strings.Join(indented, "\n")+"\n", 1)
}

// defaultDumpSentinels renders the sentinels block exactly as `nauthilus -d --dump-format yaml` prints it.
func defaultDumpSentinels(t *testing.T) string {
	t.Helper()

	dump, err := RenderDefaultConfigDumpWithFormat(DumpFormatYAML)
	if err != nil {
		t.Fatalf("RenderDefaultConfigDumpWithFormat() error = %v", err)
	}

	var document map[string]any
	if err = yaml.Unmarshal([]byte(dump), &document); err != nil {
		t.Fatalf("parse default dump: %v", err)
	}

	storage, _ := document["storage"].(map[string]any)
	redis, _ := storage["redis"].(map[string]any)

	sentinels, ok := redis["sentinels"]
	if !ok {
		t.Fatal("default dump has no storage.redis.sentinels block")
	}

	raw, err := yaml.Marshal(map[string]any{"sentinels": sentinels})
	if err != nil {
		t.Fatalf("marshal sentinels: %v", err)
	}

	return string(raw)
}

func TestHandleFileAcceptsEmptySentinelsFromDefaultDump(t *testing.T) {
	sentinels := defaultDumpSentinels(t)

	cfg, err := handleFileFromContent(t, sentinelConfig(sentinels))
	if err != nil {
		t.Fatalf("HandleFile() with the dumped empty sentinels block error = %v\n%s", err, sentinels)
	}

	if !cfg.GetServer().GetRedis().GetSentinel().IsEmpty() {
		t.Fatalf("empty sentinels block = %+v, want no Sentinel configuration", cfg.GetServer().GetRedis().GetSentinel())
	}
}

func TestHandleFileKeepsPartialSentinelsStrict(t *testing.T) {
	for name, sentinels := range map[string]string{
		"addresses without master": "sentinels:\n  master: \"\"\n  addresses:\n    - sentinel.example.test:26379\n",
		"username only":            "sentinels:\n  username: sentinel-user\n",
		"password only":            "sentinels:\n  password: sentinel-secret\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := handleFileFromContent(t, sentinelConfig(sentinels))
			if err == nil || !strings.Contains(err.Error(), "storage.redis.sentinels.") {
				t.Fatalf("HandleFile() error = %v, want a storage.redis.sentinels validation error", err)
			}
		})
	}
}

func TestSentinelsIsEmpty(t *testing.T) {
	if !(&Sentinels{Addresses: []string{}}).IsEmpty() {
		t.Fatal("a block with an empty address list must count as empty")
	}

	if (&Sentinels{Master: "mymaster"}).IsEmpty() {
		t.Fatal("a block with a master name is not empty")
	}
}
