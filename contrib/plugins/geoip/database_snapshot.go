// Copyright (C) 2026 Christian Roessner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"fmt"
	"io"
	"os"
	"time"
)

type databaseSnapshot struct{ timestamp time.Time }

// SnapshotTime reports source freshness captured with the immutable database bytes.
func (d databaseSnapshot) SnapshotTime() time.Time { return d.timestamp }

// readGeoDatabaseSnapshot captures bytes and metadata from the same open file and rejects concurrent replacement in place.
func readGeoDatabaseSnapshot(path string) ([]byte, time.Time, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer func() { _ = file.Close() }()

	before, err := file.Stat()
	if err != nil {
		return nil, time.Time{}, err
	}

	raw, err := io.ReadAll(file)
	if err != nil {
		return nil, time.Time{}, err
	}

	after, err := file.Stat()
	if err != nil {
		return nil, time.Time{}, err
	}

	if before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || int64(len(raw)) != after.Size() {
		return nil, time.Time{}, fmt.Errorf("database changed during snapshot capture")
	}

	return raw, before.ModTime().UTC(), nil
}

// oldestEvidenceTime conservatively retains the age of every source contributing to one result.
func oldestEvidenceTime(left, right time.Time) time.Time {
	if left.Before(right) {
		return left
	}

	return right
}
