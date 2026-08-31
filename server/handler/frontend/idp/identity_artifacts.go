// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package idp

import (
	"fmt"

	"github.com/croessner/nauthilus/v4/server/config"
)

// identityArtifactContent resolves inline material or immutable candidate-captured file bytes.
func identityArtifactContent(
	artifacts *config.ArtifactSnapshot,
	raw any,
	path string,
	label string,
) (string, error) {
	content, err := config.GetContent(raw, "")
	if err != nil || content != "" || path == "" {
		return content, err
	}

	if artifacts == nil {
		return "", fmt.Errorf("read %s: %w", label, config.ErrArtifactNotCaptured)
	}

	contentBytes, err := artifacts.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", label, err)
	}

	content = string(contentBytes)
	clear(contentBytes)

	return content, nil
}

// identityArtifactSnapshot returns the already sealed config source without opening live paths.
func identityArtifactSnapshot(configured config.File) *config.ArtifactSnapshot {
	artifacts, _ := config.ArtifactSnapshotFor(configured)

	return artifacts
}
