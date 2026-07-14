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

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/oschwald/maxminddb-golang"
)

func TestLoadMaxMindDatabaseReadsFileIntoMemory(t *testing.T) {
	want := []byte("complete mmdb fixture")
	path := filepath.Join(t.TempDir(), "geoip.mmdb")

	if err := os.WriteFile(path, want, 0o600); err != nil {
		t.Fatalf("write MMDB fixture: %v", err)
	}

	factory := &recordingMaxMindReaderFactory{}

	database, err := loadMaxMindDatabaseWithFactory(context.Background(), path, factory)
	if err != nil {
		t.Fatalf("loadMaxMindDatabaseWithFactory() error = %v", err)
	}

	if !bytes.Equal(factory.raw, want) {
		t.Fatalf("factory bytes = %q, want %q", factory.raw, want)
	}

	if database.reader == nil {
		t.Fatal("database reader is nil")
	}
}

type recordingMaxMindReaderFactory struct {
	raw []byte
}

// FromBytes records the eager file contents and returns a test reader.
func (f *recordingMaxMindReaderFactory) FromBytes(raw []byte) (*maxminddb.Reader, error) {
	f.raw = append([]byte(nil), raw...)

	return &maxminddb.Reader{}, nil
}
