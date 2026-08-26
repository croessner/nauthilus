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
	"errors"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/spf13/viper"
)

func TestBoundActiveFileSourceTracksGenerationProjectionAndRejectsIndependentPublication(t *testing.T) {
	activeFileSource = atomic.Value{}

	activeFileSourceBound.Store(false)
	t.Cleanup(func() {
		activeFileSource = atomic.Value{}

		activeFileSourceBound.Store(false)
		SetTestFile(nil)
	})

	first := &FileSettings{}
	second := &FileSettings{}
	current := File(first)

	if err := BindActiveFileSource(func() File { return current }); err != nil {
		t.Fatalf("BindActiveFileSource() error = %v", err)
	}

	if GetFile() != first {
		t.Fatal("GetFile() did not project the first active generation config")
	}

	current = second
	if GetFile() != second {
		t.Fatal("GetFile() retained the boot config after generation replacement")
	}

	if err := BindActiveFileSource(func() File { return first }); err == nil {
		t.Fatal("second active config source binding succeeded")
	}

	if err := ReloadConfigFile(); !errors.Is(err, ErrIndependentConfigPublication) {
		t.Fatalf("ReloadConfigFile() error = %v, want independent-publication rejection", err)
	}
}

// TestPrepareFileDoesNotPublishCandidateOrMutateAmbientViper proves off-side decoding.
func TestPrepareFileDoesNotPublishCandidateOrMutateAmbientViper(t *testing.T) {
	active := &FileSettings{}
	SetTestFile(active)

	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.Set("ambient.marker", "active")

	ambientBefore := viper.AllSettings()

	configureCandidateFileTest(t, `storage:
  redis:
    primary:
      address: candidate.example.test:6379
    password_nonce: nonce-secret-1234
    encryption_secret: redis-secret-1234
`)

	candidate, err := PrepareFile()
	if err != nil {
		t.Fatalf("PrepareFile() error = %v", err)
	}

	if candidate == nil || candidate == active {
		t.Fatal("PrepareFile() did not return an off-side candidate")
	}

	if GetFile() != active {
		t.Fatal("PrepareFile() replaced the active config file")
	}

	if ambientAfter := viper.AllSettings(); !reflect.DeepEqual(ambientAfter, ambientBefore) {
		t.Fatalf("ambient Viper settings changed: before=%v after=%v", ambientBefore, ambientAfter)
	}
}

// TestPrepareFileFailureRetainsActiveConfig proves failed candidates cannot publish config.
func TestPrepareFileFailureRetainsActiveConfig(t *testing.T) {
	active := &FileSettings{}
	SetTestFile(active)

	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.Set("ambient.marker", "active")

	ambientBefore := viper.AllSettings()

	configureCandidateFileTest(t, "unsupported_candidate_root: true\n")

	if _, err := PrepareFile(); err == nil {
		t.Fatal("PrepareFile() error = nil, want validation failure")
	}

	if GetFile() != active {
		t.Fatal("failed PrepareFile() replaced the active config file")
	}

	if ambientAfter := viper.AllSettings(); !reflect.DeepEqual(ambientAfter, ambientBefore) {
		t.Fatalf("failed candidate changed ambient Viper settings: before=%v after=%v", ambientBefore, ambientAfter)
	}
}

// configureCandidateFileTest installs one temporary candidate file location.
func configureCandidateFileTest(t *testing.T, content string) {
	t.Helper()

	path := writeConfigFile(t, t.TempDir(), "candidate.yml", content)
	previousPath := ConfigFilePath
	previousType := ConfigFileType
	ConfigFilePath = path
	ConfigFileType = string(DumpFormatYAML)

	t.Cleanup(func() {
		ConfigFilePath = previousPath
		ConfigFileType = previousType

		SetTestFile(nil)
	})
}
