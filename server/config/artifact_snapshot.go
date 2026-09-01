// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package config

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
)

const (
	maximumArtifactCount      = 16_384
	maximumArtifactFileSize   = 64 << 20
	maximumArtifactTotalSize  = 512 << 20
	maximumLuaModuleCount     = 1_024
	maximumLuaModuleSize      = 4 << 20
	maximumLuaModuleTotalSize = 32 << 20
	kubernetesDataDirectory   = "..data"
	parentDirectory           = ".."
)

var (
	// ErrArtifactSnapshotDrift reports that a sealed path, byte stream, or directory membership changed.
	ErrArtifactSnapshotDrift = errors.New("sealed configuration artifact changed")
	// ErrArtifactNotCaptured reports that a consumer requested a path outside its configuration snapshot.
	ErrArtifactNotCaptured = errors.New("configuration artifact was not captured")
)

// ArtifactSnapshotSpec declares exact files and directory patterns captured as one immutable unit.
type ArtifactSnapshotSpec struct {
	Paths              []string `mapstructure:"-"`
	OptionalPaths      []string `mapstructure:"-"`
	Globs              []string `mapstructure:"-"`
	Trees              []string `mapstructure:"-"`
	LuaPackagePatterns []string `mapstructure:"-"`
}

// ArtifactFile returns one detached exact-byte file from a sealed pattern.
type ArtifactFile struct {
	Path    string `mapstructure:"-"`
	Content []byte `mapstructure:"-"`
}

// ArtifactFingerprint identifies one captured path without exposing its contents.
type ArtifactFingerprint struct {
	Path   string            `mapstructure:"-"`
	Digest [sha256.Size]byte `mapstructure:"-"`
}

type artifactSnapshotFile struct {
	content []byte            `mapstructure:"-"`
	digest  [sha256.Size]byte `mapstructure:"-"`
}

// ArtifactSnapshot owns immutable exact bytes and directory membership for one config candidate.
type ArtifactSnapshot struct {
	files       map[string]artifactSnapshotFile `mapstructure:"-"`
	globs       map[string][]string             `mapstructure:"-"`
	trees       map[string][]string             `mapstructure:"-"`
	luaPackages map[string][]string             `mapstructure:"-"`
	absent      map[string]struct{}             `mapstructure:"-"`
	references  int                             `mapstructure:"-"`
	mu          sync.RWMutex                    `mapstructure:"-"`
	claimed     bool                            `mapstructure:"-"`
}

// ArtifactSnapshotProvider exposes the immutable file material bound to one config candidate.
type ArtifactSnapshotProvider interface {
	ArtifactSnapshot() *ArtifactSnapshot
}

type artifactSnapshotOwner interface {
	ArtifactSnapshotProvider
	attachArtifactSnapshot(*ArtifactSnapshot) *ArtifactSnapshot
}

type artifactSnapshotCapture func(ArtifactSnapshotSpec) (*ArtifactSnapshot, error)
type artifactFileReader func(string) ([]byte, error)

type artifactMembershipKind uint8

const (
	artifactGlobMembership artifactMembershipKind = iota
	artifactTreeMembership
	artifactLuaPackageMembershipKind
)

type artifactSnapshotResolution struct {
	paths        map[string]struct{} `mapstructure:"-"`
	globs        map[string][]string `mapstructure:"-"`
	trees        map[string][]string `mapstructure:"-"`
	luaPackages  map[string][]string `mapstructure:"-"`
	absent       map[string]struct{} `mapstructure:"-"`
	luaFiles     map[string]int64    `mapstructure:"-"`
	luaTotalSize int64               `mapstructure:"-"`
}

type artifactLuaPackageMembership struct {
	pattern   string   `mapstructure:"-"`
	prefix    string   `mapstructure:"-"`
	suffix    string   `mapstructure:"-"`
	members   []string `mapstructure:"-"`
	totalSize int64    `mapstructure:"-"`
}

// CaptureArtifactSnapshot reads every declared artifact exactly once into a detached immutable snapshot.
func CaptureArtifactSnapshot(spec ArtifactSnapshotSpec) (*ArtifactSnapshot, error) {
	snapshot, err := captureArtifactSnapshot(spec, readArtifactFileBounded)
	if err != nil {
		return nil, err
	}

	return snapshot, nil
}

// captureArtifactSnapshot owns partial-capture cleanup around one injected exact-byte reader.
func captureArtifactSnapshot(
	spec ArtifactSnapshotSpec,
	reader artifactFileReader,
) (*ArtifactSnapshot, error) {
	if reader == nil {
		return nil, fmt.Errorf("capture configuration artifacts: reader is nil")
	}

	paths, globs, trees, luaPackages, absent, err := resolveArtifactSnapshotSpec(spec)
	if err != nil {
		return nil, err
	}

	if err = inspectArtifactCapturePlan(paths); err != nil {
		return nil, err
	}

	snapshot := &ArtifactSnapshot{
		files:       make(map[string]artifactSnapshotFile, len(paths)),
		globs:       globs,
		trees:       trees,
		luaPackages: luaPackages,
		absent:      absent,
		references:  1,
	}

	var totalSize int64

	for _, path := range paths {
		content, readErr := reader(path)
		if readErr != nil {
			snapshot.Release()

			return snapshot, fmt.Errorf("capture configuration artifact %q: %w", path, readErr)
		}

		contentSize := int64(len(content))
		if contentSize > maximumArtifactFileSize || totalSize+contentSize > maximumArtifactTotalSize {
			clear(content)
			snapshot.Release()

			return snapshot, fmt.Errorf("capture configuration artifact %q: size limit exceeded", path)
		}

		totalSize += contentSize

		snapshot.files[path] = artifactSnapshotFile{
			content: bytes.Clone(content),
			digest:  sha256.Sum256(content),
		}
		clear(content)
	}

	return snapshot, nil
}

// resolveArtifactSnapshotSpec freezes sorted unique paths and every configured glob membership.
func resolveArtifactSnapshotSpec(
	spec ArtifactSnapshotSpec,
) ([]string, map[string][]string, map[string][]string, map[string][]string, map[string]struct{}, error) {
	resolution := newArtifactSnapshotResolution(spec)
	resolution.addRequiredPaths(spec.Paths)

	if err := resolution.addOptionalPaths(spec.OptionalPaths); err != nil {
		return nil, nil, nil, nil, nil, err
	}

	if err := resolution.addGlobs(spec.Globs); err != nil {
		return nil, nil, nil, nil, nil, err
	}

	if err := resolution.addTrees(spec.Trees); err != nil {
		return nil, nil, nil, nil, nil, err
	}

	if err := resolution.addLuaPackages(spec.LuaPackagePatterns); err != nil {
		return nil, nil, nil, nil, nil, err
	}

	return resolution.result()
}

// newArtifactSnapshotResolution allocates the mutable capture plan for one candidate.
func newArtifactSnapshotResolution(spec ArtifactSnapshotSpec) *artifactSnapshotResolution {
	return &artifactSnapshotResolution{
		paths:       make(map[string]struct{}, len(spec.Paths)),
		globs:       make(map[string][]string, len(spec.Globs)),
		trees:       make(map[string][]string, len(spec.Trees)),
		luaPackages: make(map[string][]string, len(spec.LuaPackagePatterns)),
		absent:      make(map[string]struct{}, len(spec.OptionalPaths)),
		luaFiles:    make(map[string]int64),
	}
}

// addRequiredPaths records non-empty exact artifact paths.
func (r *artifactSnapshotResolution) addRequiredPaths(paths []string) {
	for _, path := range paths {
		if path != "" {
			r.paths[filepath.Clean(path)] = struct{}{}
		}
	}
}

// addOptionalPaths records present files and seals the absence of missing files.
func (r *artifactSnapshotResolution) addOptionalPaths(paths []string) error {
	for _, path := range paths {
		if path == "" {
			continue
		}

		cleanPath := filepath.Clean(path)
		_, err := os.Stat(cleanPath)

		switch {
		case err == nil:
			r.paths[cleanPath] = struct{}{}
		case os.IsNotExist(err):
			r.absent[cleanPath] = struct{}{}
		default:
			return fmt.Errorf("inspect optional configuration artifact %q: %w", cleanPath, err)
		}
	}

	return nil
}

// addGlobs resolves and records deterministic glob membership.
func (r *artifactSnapshotResolution) addGlobs(patterns []string) error {
	for _, pattern := range patterns {
		if pattern == "" {
			continue
		}

		cleanPattern := filepath.Clean(pattern)

		matches, err := resolveArtifactGlob(cleanPattern)
		if err != nil {
			return err
		}

		r.globs[cleanPattern] = matches
		r.addResolvedPaths(matches)
	}

	return nil
}

// addTrees resolves and records deterministic directory-tree membership.
func (r *artifactSnapshotResolution) addTrees(roots []string) error {
	for _, root := range roots {
		if root == "" {
			continue
		}

		cleanRoot := filepath.Clean(root)

		members, err := resolveArtifactTree(cleanRoot)
		if err != nil {
			return err
		}

		r.trees[cleanRoot] = members
		r.addResolvedPaths(members)
	}

	return nil
}

// addLuaPackages resolves module memberships and enforces aggregate snapshot limits.
func (r *artifactSnapshotResolution) addLuaPackages(patterns []string) error {
	for _, rawPattern := range patterns {
		if strings.TrimSpace(rawPattern) == "" {
			continue
		}

		pattern := filepath.Clean(strings.TrimSpace(rawPattern))

		members, err := resolveArtifactLuaPackagePattern(pattern)
		if err != nil {
			return err
		}

		r.luaPackages[pattern] = members
		for _, path := range members {
			if err = r.addLuaModule(path); err != nil {
				return err
			}
		}
	}

	return nil
}

// addLuaModule adds one unique module while enforcing the cross-pattern limits.
func (r *artifactSnapshotResolution) addLuaModule(path string) error {
	r.paths[path] = struct{}{}
	if _, exists := r.luaFiles[path]; exists {
		return nil
	}

	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect lua module %q: %w", path, err)
	}

	if len(r.luaFiles) >= maximumLuaModuleCount {
		return fmt.Errorf("lua module snapshot exceeds %d files", maximumLuaModuleCount)
	}

	if info.Size() <= 0 || info.Size() > maximumLuaModuleSize || r.luaTotalSize+info.Size() > maximumLuaModuleTotalSize {
		return fmt.Errorf("lua module %q has an invalid snapshot size", path)
	}

	r.luaFiles[path] = info.Size()
	r.luaTotalSize += info.Size()

	return nil
}

// addResolvedPaths adds every member of a resolved glob or tree.
func (r *artifactSnapshotResolution) addResolvedPaths(paths []string) {
	for _, path := range paths {
		r.paths[path] = struct{}{}
	}
}

// result freezes the capture plan into sorted paths and resolved membership maps.
func (r *artifactSnapshotResolution) result() (
	[]string,
	map[string][]string,
	map[string][]string,
	map[string][]string,
	map[string]struct{},
	error,
) {
	paths := make([]string, 0, len(r.paths))
	for path := range r.paths {
		paths = append(paths, path)
	}

	sort.Strings(paths)

	return paths, r.globs, r.trees, r.luaPackages, r.absent, nil
}

// resolveArtifactLuaPackagePattern returns exact prefix/suffix module membership without capturing unrelated files.
func resolveArtifactLuaPackagePattern(pattern string) ([]string, error) {
	root, err := LuaModuleTreeRoot(pattern)
	if err != nil {
		return nil, err
	}

	present, err := inspectLuaModuleRoot(root)
	if err != nil || !present {
		return nil, err
	}

	marker := strings.IndexByte(pattern, '?')
	membership := &artifactLuaPackageMembership{
		pattern: pattern,
		prefix:  pattern[:marker],
		suffix:  pattern[marker+1:],
		members: make([]string, 0),
	}

	err = filepath.WalkDir(root, membership.visit)
	if err != nil {
		return nil, fmt.Errorf("resolve lua module pattern %q: %w", pattern, err)
	}

	sort.Strings(membership.members)

	return membership.members, nil
}

// inspectLuaModuleRoot validates the directory that bounds one package pattern.
func inspectLuaModuleRoot(root string) (bool, error) {
	rootInfo, err := os.Lstat(root)
	if os.IsNotExist(err) {
		return false, nil
	}

	if err != nil {
		return false, fmt.Errorf("inspect lua module root %q: %w", root, err)
	}

	if rootInfo.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("lua module root %q must not be a symbolic link", root)
	}

	if !rootInfo.IsDir() {
		return false, fmt.Errorf("lua module root %q must be a directory", root)
	}

	return true, nil
}

// visit records one matching regular module while enforcing pattern-local limits.
func (m *artifactLuaPackageMembership) visit(path string, entry fs.DirEntry, walkErr error) error {
	if walkErr != nil {
		return walkErr
	}

	if entry.IsDir() {
		if strings.HasPrefix(entry.Name(), "..") {
			return filepath.SkipDir
		}

		return nil
	}

	if !strings.HasPrefix(path, m.prefix) || !strings.HasSuffix(path, m.suffix) {
		return nil
	}

	info, err := inspectArtifactPath(path)
	if err != nil {
		return fmt.Errorf("inspect lua module %q: %w", path, err)
	}

	if err = m.validateModule(path, info); err != nil {
		return err
	}

	m.members = append(m.members, filepath.Clean(path))
	m.totalSize += info.Size()

	return nil
}

// validateModule enforces file-type, per-file, count, and aggregate limits.
func (m *artifactLuaPackageMembership) validateModule(path string, info fs.FileInfo) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("lua module %q must be a regular file", path)
	}

	if info.Size() <= 0 || info.Size() > maximumLuaModuleSize {
		return fmt.Errorf("lua module %q has an invalid snapshot size", path)
	}

	if len(m.members) >= maximumLuaModuleCount {
		return fmt.Errorf("lua module pattern %q exceeds %d files", m.pattern, maximumLuaModuleCount)
	}

	if m.totalSize+info.Size() > maximumLuaModuleTotalSize {
		return fmt.Errorf("lua module pattern %q exceeds the total size limit", m.pattern)
	}

	return nil
}

// inspectArtifactCapturePlan rejects unsafe file types and allocations before opening artifact contents.
func inspectArtifactCapturePlan(paths []string) error {
	if len(paths) > maximumArtifactCount {
		return fmt.Errorf("configuration artifact file count %d exceeds limit %d", len(paths), maximumArtifactCount)
	}

	var totalSize int64

	for _, path := range paths {
		info, err := inspectArtifactPath(path)
		if err != nil {
			return fmt.Errorf("inspect configuration artifact %q: %w", path, err)
		}

		if !info.Mode().IsRegular() {
			return fmt.Errorf("configuration artifact %q must be a regular file", path)
		}

		if info.Size() > maximumArtifactFileSize {
			return fmt.Errorf("configuration artifact %q exceeds the per-file size limit", path)
		}

		totalSize += info.Size()
		if totalSize > maximumArtifactTotalSize {
			return fmt.Errorf("configuration artifact total size exceeds limit %d", maximumArtifactTotalSize)
		}
	}

	return nil
}

// readArtifactFileBounded reads one stable regular file without allocating beyond the artifact limit.
func readArtifactFileBounded(path string) ([]byte, error) {
	before, err := inspectArtifactFile(path)
	if err != nil {
		return nil, err
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	content, readErr := readStableArtifactFile(file, before)
	closeErr := file.Close()

	if readErr != nil {
		return nil, readErr
	}

	if closeErr != nil {
		clear(content)

		return nil, closeErr
	}

	return content, nil
}

// inspectArtifactFile validates a path before it is opened for bounded reading.
func inspectArtifactFile(path string) (fs.FileInfo, error) {
	info, err := inspectArtifactPath(path)
	if err != nil {
		return nil, err
	}

	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("artifact is not a regular file")
	}

	if info.Size() > maximumArtifactFileSize {
		return nil, fmt.Errorf("artifact exceeds the per-file size limit")
	}

	return info, nil
}

// inspectArtifactPath accepts only regular paths or Kubernetes projected-volume links confined to their mount root.
func inspectArtifactPath(path string) (fs.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}

	if info.Mode()&os.ModeSymlink == 0 {
		return info, nil
	}

	return inspectProjectedArtifactPath(path)
}

// inspectProjectedArtifactPath validates one Kubernetes projected-volume file link and its confined target.
func inspectProjectedArtifactPath(path string) (fs.FileInfo, error) {
	target, err := os.Readlink(path)
	if err != nil {
		return nil, err
	}

	expectedTarget := filepath.Join(kubernetesDataDirectory, filepath.Base(path))
	if filepath.IsAbs(target) || filepath.Clean(target) != expectedTarget {
		return nil, fmt.Errorf("artifact path must not be a symbolic link")
	}

	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}

	root, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return nil, err
	}

	root, err = filepath.Abs(root)
	if err != nil {
		return nil, err
	}

	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return nil, err
	}

	relative, err := filepath.Rel(root, resolved)
	if err != nil || relative == parentDirectory || strings.HasPrefix(relative, parentDirectory+string(os.PathSeparator)) {
		return nil, fmt.Errorf("artifact path must not be a symbolic link")
	}

	return os.Stat(path)
}

// readStableArtifactFile reads one opened file and proves that its metadata stayed stable.
func readStableArtifactFile(file *os.File, before fs.FileInfo) ([]byte, error) {
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}

	if !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return nil, fmt.Errorf("artifact changed while opening")
	}

	content, err := io.ReadAll(io.LimitReader(file, maximumArtifactFileSize+1))
	if err != nil {
		clear(content)

		return nil, err
	}

	if int64(len(content)) > maximumArtifactFileSize {
		clear(content)

		return nil, fmt.Errorf("artifact exceeds the per-file size limit")
	}

	return validateStableArtifactContent(file, opened, content)
}

// validateStableArtifactContent checks metadata after reading and owns cleanup on drift.
func validateStableArtifactContent(file *os.File, opened fs.FileInfo, content []byte) ([]byte, error) {
	after, err := file.Stat()
	if err == nil && opened.Size() == after.Size() && opened.ModTime().Equal(after.ModTime()) && int64(len(content)) == after.Size() {
		return content, nil
	}

	clear(content)

	if err != nil {
		return nil, err
	}

	return nil, fmt.Errorf("artifact changed while reading")
}

// resolveArtifactGlob returns one clean deterministic directory membership view.
func resolveArtifactGlob(pattern string) ([]string, error) {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("resolve configuration artifact pattern %q: %w", pattern, err)
	}

	for index := range matches {
		matches[index] = filepath.Clean(matches[index])
	}

	sort.Strings(matches)

	return matches, nil
}

// resolveArtifactTree returns every regular file under one configured asset root.
func resolveArtifactTree(root string) ([]string, error) {
	rootInfo, err := os.Lstat(root)
	if os.IsNotExist(err) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("inspect configuration artifact tree %q: %w", root, err)
	}

	if rootInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("configuration artifact tree %q must not be a symbolic link", root)
	}

	if !rootInfo.IsDir() {
		return nil, fmt.Errorf("configuration artifact tree %q must be a directory", root)
	}

	paths := make([]string, 0)

	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("configuration artifact tree member %q must not be a symbolic link", path)
		}

		if entry.IsDir() {
			return nil
		}

		info, err := entry.Info()
		if err != nil {
			return err
		}

		if !info.Mode().IsRegular() {
			return fmt.Errorf("configuration artifact tree member %q must be a regular file", path)
		}

		if len(paths) >= maximumArtifactCount {
			return fmt.Errorf("configuration artifact tree %q exceeds the file-count limit", root)
		}

		paths = append(paths, filepath.Clean(path))

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("resolve configuration artifact tree %q: %w", root, err)
	}

	sort.Strings(paths)

	return paths, nil
}

// ReadFile returns a defensive copy of one exact captured byte stream.
func (s *ArtifactSnapshot) ReadFile(path string) ([]byte, error) {
	if s == nil {
		return nil, fmt.Errorf("%w: snapshot is nil", ErrArtifactNotCaptured)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	cleanPath := filepath.Clean(path)

	artifact, ok := s.files[cleanPath]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrArtifactNotCaptured, cleanPath)
	}

	return bytes.Clone(artifact.content), nil
}

// Fingerprint returns the sealed digest for one captured path.
func (s *ArtifactSnapshot) Fingerprint(path string) (ArtifactFingerprint, error) {
	if s == nil {
		return ArtifactFingerprint{}, fmt.Errorf("%w: snapshot is nil", ErrArtifactNotCaptured)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	cleanPath := filepath.Clean(path)

	artifact, ok := s.files[cleanPath]
	if !ok {
		return ArtifactFingerprint{}, fmt.Errorf("%w: %q", ErrArtifactNotCaptured, cleanPath)
	}

	return ArtifactFingerprint{Path: cleanPath, Digest: artifact.digest}, nil
}

// Digest returns only the sealed digest for cache identities that must not expose bytes.
func (s *ArtifactSnapshot) Digest(path string) ([sha256.Size]byte, error) {
	fingerprint, err := s.Fingerprint(path)

	return fingerprint.Digest, err
}

// FilesMatching returns the captured membership and detached bytes for one declared glob.
func (s *ArtifactSnapshot) FilesMatching(pattern string) ([]ArtifactFile, error) {
	cleanPattern := filepath.Clean(pattern)

	return s.filesForMembership(artifactGlobMembership, cleanPattern)
}

// FilesUnder returns detached exact bytes for every captured file under one declared tree.
func (s *ArtifactSnapshot) FilesUnder(root string) ([]ArtifactFile, error) {
	cleanRoot := filepath.Clean(root)

	return s.filesForMembership(artifactTreeMembership, cleanRoot)
}

// FilesForLuaPackagePattern returns detached exact bytes for the matching module membership only.
func (s *ArtifactSnapshot) FilesForLuaPackagePattern(pattern string) ([]ArtifactFile, error) {
	cleanPattern := filepath.Clean(strings.TrimSpace(pattern))

	return s.filesForMembership(artifactLuaPackageMembershipKind, cleanPattern)
}

// filesForMembership returns defensive copies for one captured membership key.
func (s *ArtifactSnapshot) filesForMembership(
	kind artifactMembershipKind,
	key string,
) ([]ArtifactFile, error) {
	if s == nil {
		return nil, fmt.Errorf("%w: snapshot is nil", ErrArtifactNotCaptured)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	memberships, label := s.membership(kind)

	paths, ok := memberships[key]

	if !ok {
		return nil, fmt.Errorf("%w: %s %q", ErrArtifactNotCaptured, label, key)
	}

	result := make([]ArtifactFile, 0, len(paths))
	for _, path := range paths {
		artifact := s.files[path]
		result = append(result, ArtifactFile{Path: path, Content: bytes.Clone(artifact.content)})
	}

	return result, nil
}

// membership selects one captured membership map and its diagnostic label.
func (s *ArtifactSnapshot) membership(kind artifactMembershipKind) (map[string][]string, string) {
	switch kind {
	case artifactTreeMembership:
		return s.trees, "tree"
	case artifactLuaPackageMembershipKind:
		return s.luaPackages, "lua package pattern"
	default:
		return s.globs, "pattern"
	}
}

// ValidateLive rejects any byte or declared directory-membership drift after capture.
func (s *ArtifactSnapshot) ValidateLive() error {
	if s == nil {
		return fmt.Errorf("%w: snapshot is nil", ErrArtifactSnapshotDrift)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.references == 0 {
		return fmt.Errorf("%w: snapshot has been released", ErrArtifactSnapshotDrift)
	}

	if err := validateArtifactMemberships(s.globs, "pattern", resolveArtifactGlob); err != nil {
		return err
	}

	if err := validateArtifactMemberships(s.trees, "tree", resolveArtifactTree); err != nil {
		return err
	}

	if err := validateArtifactMemberships(s.luaPackages, "lua package pattern", resolveArtifactLuaPackagePattern); err != nil {
		return err
	}

	if err := validateAbsentArtifacts(s.absent); err != nil {
		return err
	}

	return validateCapturedArtifactFiles(s.files)
}

// validateArtifactMemberships rejects drift in one class of captured directory membership.
func validateArtifactMemberships(
	memberships map[string][]string,
	kind string,
	resolve func(string) ([]string, error),
) error {
	for key, captured := range memberships {
		current, err := resolve(key)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrArtifactSnapshotDrift, err)
		}

		if !slices.Equal(captured, current) {
			return fmt.Errorf("%w: %s %q membership changed", ErrArtifactSnapshotDrift, kind, key)
		}
	}

	return nil
}

// validateAbsentArtifacts rejects optional files that appeared or became unreadable.
func validateAbsentArtifacts(absent map[string]struct{}) error {
	for path := range absent {
		if _, err := os.Stat(path); err == nil || !os.IsNotExist(err) {
			return fmt.Errorf("%w: absent optional path %q appeared or became unreadable", ErrArtifactSnapshotDrift, path)
		}
	}

	return nil
}

// validateCapturedArtifactFiles rejects byte drift for every sealed file.
func validateCapturedArtifactFiles(files map[string]artifactSnapshotFile) error {
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}

	sort.Strings(paths)

	for _, path := range paths {
		content, err := readArtifactFileBounded(path)
		if err != nil {
			return fmt.Errorf("%w: read %q: %v", ErrArtifactSnapshotDrift, path, err)
		}

		digest := sha256.Sum256(content)
		clear(content)

		if digest != files[path].digest {
			return fmt.Errorf("%w: bytes at %q changed", ErrArtifactSnapshotDrift, path)
		}
	}

	return nil
}

// Retain adds one explicit generation or process-lifecycle owner.
func (s *ArtifactSnapshot) Retain() error {
	if s == nil {
		return fmt.Errorf("retain configuration artifact snapshot: snapshot is nil")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.references == 0 {
		return fmt.Errorf("retain configuration artifact snapshot: snapshot has been released")
	}

	s.references++

	return nil
}

// ClaimCandidateOwner transfers the attached reference once and retains on later candidate reuse.
func (s *ArtifactSnapshot) ClaimCandidateOwner() error {
	if s == nil {
		return fmt.Errorf("claim configuration artifact snapshot: snapshot is nil")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.references == 0 {
		return fmt.Errorf("claim configuration artifact snapshot: snapshot has been released")
	}

	if s.claimed {
		s.references++

		return nil
	}

	s.claimed = true

	return nil
}

// Release removes one owner and clears every captured byte at final retirement.
func (s *ArtifactSnapshot) Release() {
	if s == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.references == 0 {
		return
	}

	s.references--
	if s.references != 0 {
		return
	}

	for path, artifact := range s.files {
		clear(artifact.content)
		delete(s.files, path)
	}

	clear(s.globs)
	s.globs = nil
	clear(s.trees)
	s.trees = nil
	clear(s.luaPackages)
	s.luaPackages = nil
	clear(s.absent)
	s.absent = nil
}

// IsReleased reports whether final lifecycle retirement cleared the snapshot.
func (s *ArtifactSnapshot) IsReleased() bool {
	if s == nil {
		return true
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.references == 0
}

// EnsureArtifactSnapshot captures and attaches every production artifact declared by one config candidate.
func EnsureArtifactSnapshot(configured File) (*ArtifactSnapshot, error) {
	return ensureArtifactSnapshot(configured, CaptureArtifactSnapshot)
}

// ensureArtifactSnapshot owns capture races so every losing snapshot is retired immediately.
func ensureArtifactSnapshot(
	configured File,
	capture artifactSnapshotCapture,
) (*ArtifactSnapshot, error) {
	if configured == nil {
		return nil, fmt.Errorf("capture configuration artifacts: config is nil")
	}

	if capture == nil {
		return nil, fmt.Errorf("capture configuration artifacts: capture function is nil")
	}

	owner, ok := configured.(artifactSnapshotOwner)
	if !ok {
		return nil, fmt.Errorf("capture configuration artifacts: config type %T cannot own a snapshot", configured)
	}

	if existing := owner.ArtifactSnapshot(); existing != nil {
		return existing, nil
	}

	snapshot, err := capture(ProductionArtifactSnapshotSpec(configured))
	if err != nil {
		return nil, err
	}

	return owner.attachArtifactSnapshot(snapshot), nil
}

// ArtifactSnapshotFor returns the already sealed snapshot without opening any live path.
func ArtifactSnapshotFor(configured File) (*ArtifactSnapshot, error) {
	provider, ok := configured.(ArtifactSnapshotProvider)
	if !ok || provider.ArtifactSnapshot() == nil {
		return nil, fmt.Errorf("%w: config type %T has no sealed snapshot", ErrArtifactNotCaptured, configured)
	}

	return provider.ArtifactSnapshot(), nil
}
