// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type synchronizedSnapshotCapture struct {
	start     chan struct{}
	snapshots []*ArtifactSnapshot
	ready     atomic.Int32
	mu        sync.Mutex
}

// newSynchronizedSnapshotCapture creates a capture barrier for concurrent ownership tests.
func newSynchronizedSnapshotCapture() *synchronizedSnapshotCapture {
	return &synchronizedSnapshotCapture{
		start:     make(chan struct{}),
		snapshots: make([]*ArtifactSnapshot, 0, 2),
	}
}

// capture records a candidate and waits until both concurrent captures are ready.
func (c *synchronizedSnapshotCapture) capture(ArtifactSnapshotSpec) (*ArtifactSnapshot, error) {
	snapshot, err := CaptureArtifactSnapshot(ArtifactSnapshotSpec{})
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.snapshots = append(c.snapshots, snapshot)
	c.mu.Unlock()

	if c.ready.Add(1) == 2 {
		close(c.start)
	}

	<-c.start

	return snapshot, nil
}

// captured returns a stable copy of the candidates observed by the barrier.
func (c *synchronizedSnapshotCapture) captured() []*ArtifactSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()

	return append([]*ArtifactSnapshot(nil), c.snapshots...)
}

func TestArtifactSnapshotRetainsCapturedBytesAndRejectsMutationAfterSeal(t *testing.T) {
	directory := t.TempDir()
	artifactPath := filepath.Join(directory, "backend.lua")

	const captured = "return 'captured'\n"

	if err := os.WriteFile(artifactPath, []byte(captured), 0o600); err != nil {
		t.Fatalf("write captured artifact: %v", err)
	}

	snapshot, err := CaptureArtifactSnapshot(ArtifactSnapshotSpec{Paths: []string{artifactPath}})
	if err != nil {
		t.Fatalf("CaptureArtifactSnapshot() error = %v", err)
	}

	if err = os.WriteFile(artifactPath, []byte("return 'mutated'\n"), 0o600); err != nil {
		t.Fatalf("mutate artifact after seal: %v", err)
	}

	content, err := snapshot.ReadFile(artifactPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}

	if string(content) != captured {
		t.Fatalf("ReadFile() = %q, want exact captured bytes %q", content, captured)
	}

	content[0] = 'X'

	second, err := snapshot.ReadFile(artifactPath)
	if err != nil {
		t.Fatalf("ReadFile(second) error = %v", err)
	}

	if string(second) != captured {
		t.Fatalf("ReadFile(second) = %q, want defensive exact copy %q", second, captured)
	}

	if err = snapshot.ValidateLive(); !errors.Is(err, ErrArtifactSnapshotDrift) {
		t.Fatalf("ValidateLive() error = %v, want ErrArtifactSnapshotDrift", err)
	}
}

func TestArtifactSnapshotRejectsDirectoryMembershipDrift(t *testing.T) {
	directory := t.TempDir()
	firstPath := filepath.Join(directory, "first.html")
	pattern := filepath.Join(directory, "*.html")

	if err := os.WriteFile(firstPath, []byte("first\n"), 0o600); err != nil {
		t.Fatalf("write first template: %v", err)
	}

	snapshot, err := CaptureArtifactSnapshot(ArtifactSnapshotSpec{Globs: []string{pattern}})
	if err != nil {
		t.Fatalf("CaptureArtifactSnapshot() error = %v", err)
	}

	files, err := snapshot.FilesMatching(pattern)
	if err != nil {
		t.Fatalf("FilesMatching() error = %v", err)
	}

	if len(files) != 1 || files[0].Path != firstPath || string(files[0].Content) != "first\n" {
		t.Fatalf("FilesMatching() = %#v, want exact first template", files)
	}

	secondPath := filepath.Join(directory, "second.html")
	if err = os.WriteFile(secondPath, []byte("second\n"), 0o600); err != nil {
		t.Fatalf("write template after seal: %v", err)
	}

	if err = snapshot.ValidateLive(); !errors.Is(err, ErrArtifactSnapshotDrift) {
		t.Fatalf("ValidateLive() membership error = %v, want ErrArtifactSnapshotDrift", err)
	}
}

func TestArtifactSnapshotClearsBytesOnlyAfterFinalLifecycleOwner(t *testing.T) {
	artifactPath := filepath.Join(t.TempDir(), "private-key.pem")
	if err := os.WriteFile(artifactPath, []byte("private material\n"), 0o600); err != nil {
		t.Fatalf("write private material: %v", err)
	}

	snapshot, err := CaptureArtifactSnapshot(ArtifactSnapshotSpec{Paths: []string{artifactPath}})
	if err != nil {
		t.Fatalf("CaptureArtifactSnapshot() error = %v", err)
	}

	if err = snapshot.Retain(); err != nil {
		t.Fatalf("Retain() error = %v", err)
	}

	snapshot.Release()

	if snapshot.IsReleased() {
		t.Fatal("Release() cleared bytes while one lifecycle owner remained")
	}

	if _, err = snapshot.ReadFile(artifactPath); err != nil {
		t.Fatalf("ReadFile() with retained owner error = %v", err)
	}

	snapshot.Release()

	if !snapshot.IsReleased() {
		t.Fatal("final Release() did not retire the snapshot")
	}

	if _, err = snapshot.ReadFile(artifactPath); !errors.Is(err, ErrArtifactNotCaptured) {
		t.Fatalf("ReadFile() after final Release error = %v, want ErrArtifactNotCaptured", err)
	}
}

func TestArtifactSnapshotCandidateClaimsTransferAttachmentAndRetainOnReuse(t *testing.T) {
	artifactPath := filepath.Join(t.TempDir(), "token.txt")
	if err := os.WriteFile(artifactPath, []byte("token material\n"), 0o600); err != nil {
		t.Fatalf("write token material: %v", err)
	}

	snapshot, err := CaptureArtifactSnapshot(ArtifactSnapshotSpec{Paths: []string{artifactPath}})
	if err != nil {
		t.Fatalf("CaptureArtifactSnapshot() error = %v", err)
	}

	if err = snapshot.Retain(); err != nil {
		t.Fatalf("Retain(process) error = %v", err)
	}

	if err = snapshot.ClaimCandidateOwner(); err != nil {
		t.Fatalf("ClaimCandidateOwner(first) error = %v", err)
	}

	snapshot.Release()

	if snapshot.IsReleased() {
		t.Fatal("first candidate retirement cleared the retained process owner")
	}

	if err = snapshot.ClaimCandidateOwner(); err != nil {
		t.Fatalf("ClaimCandidateOwner(reuse) error = %v", err)
	}

	snapshot.Release()

	if snapshot.IsReleased() {
		t.Fatal("reused candidate retirement cleared the retained process owner")
	}

	snapshot.Release()

	if !snapshot.IsReleased() {
		t.Fatal("final process release did not clear transferred candidate ownership")
	}
}

func TestArtifactSnapshotRejectsOptionalArtifactAppearingAfterSeal(t *testing.T) {
	artifactPath := filepath.Join(t.TempDir(), "optional-plugin.so")

	snapshot, err := CaptureArtifactSnapshot(ArtifactSnapshotSpec{OptionalPaths: []string{artifactPath}})
	if err != nil {
		t.Fatalf("CaptureArtifactSnapshot() error = %v", err)
	}

	if err = os.WriteFile(artifactPath, []byte("appeared after seal\n"), 0o600); err != nil {
		t.Fatalf("write optional artifact after seal: %v", err)
	}

	if err = snapshot.ValidateLive(); !errors.Is(err, ErrArtifactSnapshotDrift) {
		t.Fatalf("ValidateLive() error = %v, want ErrArtifactSnapshotDrift", err)
	}

	if _, err = snapshot.ReadFile(artifactPath); !errors.Is(err, ErrArtifactNotCaptured) {
		t.Fatalf("ReadFile(appeared optional) error = %v, want ErrArtifactNotCaptured", err)
	}
}

func TestArtifactSnapshotRetainsRecursiveTreeAndRejectsNestedMembershipDrift(t *testing.T) {
	root := filepath.Join(t.TempDir(), "img")

	nested := filepath.Join(root, "icons")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatalf("create nested asset directory: %v", err)
	}

	firstPath := filepath.Join(nested, "first.svg")
	if err := os.WriteFile(firstPath, []byte("first asset\n"), 0o600); err != nil {
		t.Fatalf("write first asset: %v", err)
	}

	snapshot, err := CaptureArtifactSnapshot(ArtifactSnapshotSpec{Trees: []string{root}})
	if err != nil {
		t.Fatalf("CaptureArtifactSnapshot() error = %v", err)
	}

	files, err := snapshot.FilesUnder(root)
	if err != nil {
		t.Fatalf("FilesUnder() error = %v", err)
	}

	if len(files) != 1 || files[0].Path != firstPath || string(files[0].Content) != "first asset\n" {
		t.Fatalf("FilesUnder() = %#v, want exact recursive asset", files)
	}

	secondPath := filepath.Join(nested, "second.svg")
	if err = os.WriteFile(secondPath, []byte("second asset\n"), 0o600); err != nil {
		t.Fatalf("write nested asset after seal: %v", err)
	}

	if err = snapshot.ValidateLive(); !errors.Is(err, ErrArtifactSnapshotDrift) {
		t.Fatalf("ValidateLive() error = %v, want ErrArtifactSnapshotDrift", err)
	}
}

func TestArtifactSnapshotCapturesOnlyMatchingLuaModulesAndRejectsMembershipDrift(t *testing.T) {
	root := t.TempDir()

	nested := filepath.Join(root, "nested")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatalf("create nested module directory: %v", err)
	}

	pattern := filepath.Join(root, "?.lua")
	topLevel := filepath.Join(root, "shared.lua")
	nestedModule := filepath.Join(nested, "module.lua")

	secretPath := filepath.Join(root, "private-key.pem")
	for path, content := range map[string]string{
		topLevel:     "return { value = 'top' }\n",
		nestedModule: "return { value = 'nested' }\n",
		secretPath:   "must not be captured\n",
	} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write test artifact %q: %v", path, err)
		}
	}

	snapshot, err := CaptureArtifactSnapshot(ArtifactSnapshotSpec{LuaPackagePatterns: []string{pattern}})
	if err != nil {
		t.Fatalf("CaptureArtifactSnapshot() error = %v", err)
	}

	files, err := snapshot.FilesForLuaPackagePattern(pattern)
	if err != nil {
		t.Fatalf("FilesForLuaPackagePattern() error = %v", err)
	}

	wantFiles := []string{topLevel, nestedModule}
	sort.Strings(wantFiles)

	if got, want := artifactFilePaths(files), wantFiles; !slices.Equal(got, want) {
		t.Fatalf("FilesForLuaPackagePattern() paths = %#v, want matching Lua modules %#v", got, want)
	}

	if _, err = snapshot.ReadFile(secretPath); !errors.Is(err, ErrArtifactNotCaptured) {
		t.Fatalf("ReadFile(nonmatching secret) error = %v, want ErrArtifactNotCaptured", err)
	}

	if err = os.WriteFile(filepath.Join(root, "unrelated.secret"), []byte("ignored\n"), 0o600); err != nil {
		t.Fatalf("write unrelated file after seal: %v", err)
	}

	if err = snapshot.ValidateLive(); err != nil {
		t.Fatalf("ValidateLive() rejected unrelated nonmatching file: %v", err)
	}

	if err = os.WriteFile(filepath.Join(root, "appeared.lua"), []byte("return {}\n"), 0o600); err != nil {
		t.Fatalf("write matching module after seal: %v", err)
	}

	if err = snapshot.ValidateLive(); !errors.Is(err, ErrArtifactSnapshotDrift) {
		t.Fatalf("ValidateLive() matching membership error = %v, want ErrArtifactSnapshotDrift", err)
	}
}

func TestArtifactSnapshotRejectsSymlinkedLuaModule(t *testing.T) {
	root := t.TempDir()

	target := filepath.Join(t.TempDir(), "target.lua")
	if err := os.WriteFile(target, []byte("return {}\n"), 0o600); err != nil {
		t.Fatalf("write symlink target: %v", err)
	}

	if err := os.Symlink(target, filepath.Join(root, "linked.lua")); err != nil {
		t.Fatalf("create Lua module symlink: %v", err)
	}

	_, err := CaptureArtifactSnapshot(ArtifactSnapshotSpec{LuaPackagePatterns: []string{filepath.Join(root, "?.lua")}})
	if err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("CaptureArtifactSnapshot() error = %v, want path-only symbolic-link rejection", err)
	}
}

func TestArtifactSnapshotAcceptsKubernetesProjectedLuaModule(t *testing.T) {
	root := t.TempDir()
	generation := filepath.Join(root, "..2026_09_01_13_03_10")

	if err := os.Mkdir(generation, 0o700); err != nil {
		t.Fatalf("create projected generation: %v", err)
	}

	target := filepath.Join(generation, "shared.lua")
	if err := os.WriteFile(target, []byte("return {}\n"), 0o600); err != nil {
		t.Fatalf("write projected Lua module: %v", err)
	}

	if err := os.Symlink(filepath.Base(generation), filepath.Join(root, "..data")); err != nil {
		t.Fatalf("create projected data symlink: %v", err)
	}

	modulePath := filepath.Join(root, "shared.lua")
	if err := os.Symlink(filepath.Join("..data", "shared.lua"), modulePath); err != nil {
		t.Fatalf("create projected Lua module symlink: %v", err)
	}

	pattern := filepath.Join(root, "?.lua")

	snapshot, err := CaptureArtifactSnapshot(ArtifactSnapshotSpec{LuaPackagePatterns: []string{pattern}})
	if err != nil {
		t.Fatalf("CaptureArtifactSnapshot() error = %v", err)
	}

	files, err := snapshot.FilesForLuaPackagePattern(pattern)
	if err != nil {
		t.Fatalf("FilesForLuaPackagePattern() error = %v", err)
	}

	if len(files) != 1 || files[0].Path != modulePath || string(files[0].Content) != "return {}\n" {
		t.Fatalf("FilesForLuaPackagePattern() = %#v, want projected Lua module", files)
	}
}

func TestArtifactSnapshotRejectsGenericCaptureBounds(t *testing.T) {
	t.Run("too many files", func(t *testing.T) {
		paths := make([]string, maximumArtifactCount+1)
		for index := range paths {
			paths[index] = fmt.Sprintf("missing-%06d", index)
		}

		_, err := CaptureArtifactSnapshot(ArtifactSnapshotSpec{Paths: paths})
		if err == nil || !strings.Contains(err.Error(), "file count") {
			t.Fatalf("CaptureArtifactSnapshot() error = %v, want file-count bound", err)
		}
	})

	t.Run("oversized file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "oversized.bin")

		file, err := os.Create(path)
		if err != nil {
			t.Fatalf("create oversized artifact: %v", err)
		}

		if err = file.Truncate(maximumArtifactFileSize + 1); err != nil {
			_ = file.Close()

			t.Fatalf("truncate oversized artifact: %v", err)
		}

		if err = file.Close(); err != nil {
			t.Fatalf("close oversized artifact: %v", err)
		}

		_, err = CaptureArtifactSnapshot(ArtifactSnapshotSpec{Paths: []string{path}})
		if err == nil || !strings.Contains(err.Error(), "size limit") {
			t.Fatalf("CaptureArtifactSnapshot() error = %v, want per-file size bound", err)
		}
	})
}

func TestArtifactSnapshotValidateLiveRejectsGrowthThroughBoundedReader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "growing.bin")
	if err := os.WriteFile(path, []byte("captured\n"), 0o600); err != nil {
		t.Fatalf("write captured artifact: %v", err)
	}

	snapshot, err := CaptureArtifactSnapshot(ArtifactSnapshotSpec{Paths: []string{path}})
	if err != nil {
		t.Fatalf("CaptureArtifactSnapshot() error = %v", err)
	}

	if err = os.Truncate(path, maximumArtifactFileSize+1); err != nil {
		t.Fatalf("grow captured artifact: %v", err)
	}

	if err = snapshot.ValidateLive(); !errors.Is(err, ErrArtifactSnapshotDrift) || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("ValidateLive() error = %v, want bounded ErrArtifactSnapshotDrift", err)
	}
}

func TestArtifactSnapshotRejectsSymlinksInGenericTrees(t *testing.T) {
	t.Run("root", func(t *testing.T) {
		target := t.TempDir()

		linkedRoot := filepath.Join(t.TempDir(), "linked-tree")
		if err := os.Symlink(target, linkedRoot); err != nil {
			t.Fatalf("create tree root symlink: %v", err)
		}

		_, err := CaptureArtifactSnapshot(ArtifactSnapshotSpec{Trees: []string{linkedRoot}})
		if err == nil || !strings.Contains(err.Error(), "symbolic link") {
			t.Fatalf("CaptureArtifactSnapshot() error = %v, want tree-root symlink rejection", err)
		}
	})

	t.Run("member", func(t *testing.T) {
		root := t.TempDir()

		target := filepath.Join(t.TempDir(), "target.bin")
		if err := os.WriteFile(target, []byte("target\n"), 0o600); err != nil {
			t.Fatalf("write tree member target: %v", err)
		}

		if err := os.Symlink(target, filepath.Join(root, "linked.bin")); err != nil {
			t.Fatalf("create tree member symlink: %v", err)
		}

		_, err := CaptureArtifactSnapshot(ArtifactSnapshotSpec{Trees: []string{root}})
		if err == nil || !strings.Contains(err.Error(), "symbolic link") {
			t.Fatalf("CaptureArtifactSnapshot() error = %v, want tree-member symlink rejection", err)
		}
	})
}

// artifactFilePaths extracts ordered paths without exposing captured contents in failures.
func artifactFilePaths(files []ArtifactFile) []string {
	paths := make([]string, 0, len(files))
	for _, file := range files {
		paths = append(paths, file.Path)
	}

	return paths
}

func TestArtifactSnapshotClearsPartialCaptureAfterLaterReadFailure(t *testing.T) {
	directory := t.TempDir()
	firstPath := filepath.Join(directory, "a-private-key.pem")
	secondPath := filepath.Join(directory, "b-private-key.pem")

	const secretMaterial = "captured private key material\n"

	if err := os.WriteFile(firstPath, []byte(secretMaterial), 0o600); err != nil {
		t.Fatalf("write first secret: %v", err)
	}

	if err := os.WriteFile(secondPath, []byte("unreadable replacement\n"), 0o600); err != nil {
		t.Fatalf("write second secret: %v", err)
	}

	snapshot, err := captureArtifactSnapshot(
		ArtifactSnapshotSpec{Paths: []string{secondPath, firstPath}},
		func(path string) ([]byte, error) {
			if path == secondPath {
				return nil, fmt.Errorf("injected read failure")
			}

			return os.ReadFile(path)
		},
	)
	if err == nil {
		t.Fatal("captureArtifactSnapshot() error = nil, want injected read failure")
	}

	if snapshot == nil || !snapshot.IsReleased() {
		t.Fatal("partial capture did not retire its snapshot")
	}

	if _, err = snapshot.ReadFile(firstPath); !errors.Is(err, ErrArtifactNotCaptured) {
		t.Fatalf("ReadFile(first secret) error = %v, want cleared ErrArtifactNotCaptured", err)
	}
}

func TestEnsureArtifactSnapshotConcurrentCaptureReleasesCASLoser(t *testing.T) {
	configured := &FileSettings{}
	capture := newSynchronizedSnapshotCapture()

	results := make(chan *ArtifactSnapshot, 2)
	errors := make(chan error, 2)

	for range 2 {
		go func() {
			snapshot, err := ensureArtifactSnapshot(configured, capture.capture)
			results <- snapshot

			errors <- err
		}()
	}

	first := <-results
	second := <-results

	if err := <-errors; err != nil {
		t.Fatalf("ensureArtifactSnapshot(first) error = %v", err)
	}

	if err := <-errors; err != nil {
		t.Fatalf("ensureArtifactSnapshot(second) error = %v", err)
	}

	if first == nil || first != second || first != configured.ArtifactSnapshot() {
		t.Fatal("concurrent ensure did not return the single installed snapshot")
	}

	captured := capture.captured()
	if len(captured) != 2 {
		t.Fatalf("capture count = %d, want 2 concurrent candidates", len(captured))
	}

	released := 0

	for _, snapshot := range captured {
		if snapshot.IsReleased() {
			released++
		}
	}

	if released != 1 {
		t.Fatalf("released captured snapshots = %d, want exactly one CAS loser", released)
	}
}
