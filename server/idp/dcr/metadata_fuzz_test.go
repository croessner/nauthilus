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

package dcr

import (
	"strings"
	"testing"
)

func FuzzDecodeMetadataNeverPanics(f *testing.F) {
	for _, seed := range []string{
		`{"redirect_uris":["http://127.0.0.1/callback"]}`,
		`{"client_name":"one","client_name":"two"}`,
		`{"unknown":{"nested":[null,true,1]}}`,
		`[]`,
		`{`,
	} {
		f.Add(seed)
	}

	f.Fuzz(func(_ *testing.T, body string) {
		request, protocolErr := DecodeMetadata(strings.NewReader(body))
		if protocolErr == nil {
			_, _ = BuildEffectiveMetadata(request, nativeTestPolicy())
		}
	})
}

func FuzzMatchRedirectURINeverBroadensHost(f *testing.F) {
	for _, seed := range []string{
		"http://127.0.0.1:49152/callback",
		"http://[::1]:49152/callback",
		"http://localhost/callback",
		"com.example:/callback",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, candidate string) {
		matched := MatchRedirectURI([]string{"http://127.0.0.1/callback"}, candidate)
		if matched && !strings.HasPrefix(candidate, "http://127.0.0.1") {
			t.Fatalf("MatchRedirectURI accepted non-literal IPv4 loopback candidate %q", candidate)
		}
	})
}
