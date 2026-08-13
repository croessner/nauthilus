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

package pluginloader

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
)

type stagedArtifact struct {
	path   string
	digest ArtifactDigest
}

type verifiedArtifactStager struct {
	artifacts map[string]stagedArtifact
	directory string
}

// newVerifiedArtifactStager creates one private staging owner for a loader run.
func newVerifiedArtifactStager() (*verifiedArtifactStager, error) {
	directory, err := os.MkdirTemp("", "nauthilus-plugin-artifacts-")
	if err != nil {
		return nil, fmt.Errorf("create private plugin artifact staging directory: %w", err)
	}

	if err = os.Chmod(directory, 0o700); err != nil {
		_ = os.RemoveAll(directory)

		return nil, fmt.Errorf("protect private plugin artifact staging directory: %w", err)
	}

	return &verifiedArtifactStager{
		artifacts: make(map[string]stagedArtifact),
		directory: directory,
	}, nil
}

// stage copies and rehashes one verified artifact before any opener can observe its mutable source path.
func (s *verifiedArtifactStager) stage(verified VerifiedModule) (stagedArtifact, error) {
	if s == nil || s.directory == "" {
		return stagedArtifact{}, fmt.Errorf("%w: artifact stager is unavailable", ErrArtifactUnavailable)
	}

	if existing, ok := s.artifacts[verified.ArtifactPath]; ok {
		if verified.ArtifactDigest != (ArtifactDigest{}) && existing.digest != verified.ArtifactDigest {
			return stagedArtifact{}, fmt.Errorf("%w: artifact identity changed between module references", ErrArtifactUnavailable)
		}

		return existing, nil
	}

	if err := checkVerifiedArtifact(verified.ArtifactPath); err != nil {
		return stagedArtifact{}, err
	}

	artifact, err := s.copyArtifact(verified.ArtifactPath)
	if err != nil {
		return stagedArtifact{}, err
	}

	if verified.ArtifactDigest != (ArtifactDigest{}) && artifact.digest != verified.ArtifactDigest {
		return stagedArtifact{}, fmt.Errorf("%w: artifact changed after verification", ErrArtifactUnavailable)
	}

	s.artifacts[verified.ArtifactPath] = artifact

	return artifact, nil
}

// copyArtifact writes one source stream into an exclusive private file while hashing the exact staged bytes.
func (s *verifiedArtifactStager) copyArtifact(sourcePath string) (artifact stagedArtifact, err error) {
	source, err := os.Open(sourcePath)
	if err != nil {
		return stagedArtifact{}, fmt.Errorf("%w: open source artifact: %v", ErrArtifactUnavailable, err)
	}

	defer func() {
		err = errors.Join(err, source.Close())
	}()

	destination, err := os.CreateTemp(s.directory, "verified-*.so")
	if err != nil {
		return stagedArtifact{}, fmt.Errorf("%w: create staged artifact: %v", ErrArtifactUnavailable, err)
	}

	stagedPath := destination.Name()
	keep := false

	defer func() {
		closeErr := destination.Close()

		if !keep {
			_ = os.Remove(stagedPath)
		}

		err = errors.Join(err, closeErr)
	}()

	hasher := sha256.New()
	if _, err = io.Copy(io.MultiWriter(destination, hasher), source); err != nil {
		return stagedArtifact{}, fmt.Errorf("%w: copy staged artifact: %v", ErrArtifactUnavailable, err)
	}

	if err = destination.Sync(); err != nil {
		return stagedArtifact{}, fmt.Errorf("%w: sync staged artifact: %v", ErrArtifactUnavailable, err)
	}

	if err = destination.Chmod(0o400); err != nil {
		return stagedArtifact{}, fmt.Errorf("%w: protect staged artifact: %v", ErrArtifactUnavailable, err)
	}

	var digest ArtifactDigest
	copy(digest[:], hasher.Sum(nil))

	keep = true

	return stagedArtifact{path: stagedPath, digest: digest}, nil
}

// close removes only the private directory created by this staging owner.
func (s *verifiedArtifactStager) close() error {
	if s == nil || s.directory == "" {
		return nil
	}

	return os.RemoveAll(s.directory)
}
