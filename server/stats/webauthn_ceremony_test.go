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

package stats

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestWebAuthnCeremonyReferenceMetricsAreRegisteredAndBounded(t *testing.T) {
	metrics := GetMetrics()
	cookieBytes := metrics.GetWebAuthnCeremonyReferenceCookieBytes()
	operations := metrics.GetWebAuthnCeremonyReferenceOperationsTotal()

	if count := testutil.CollectAndCount(cookieBytes, "webauthn_ceremony_reference_cookie_bytes"); count != 1 {
		t.Fatalf("cookie-size metric families = %d, want 1", count)
	}

	operationMetric := operations.WithLabelValues("store", "success")
	description := operationMetric.Desc().String()

	_, labelsAndRest, ok := strings.Cut(description, "variableLabels: {")
	if !ok {
		t.Fatalf("operation metric labels are not the bounded contract: %s", description)
	}

	labels, _, ok := strings.Cut(labelsAndRest, "}")
	if !ok || labels != "op,outcome" {
		t.Fatalf("operation metric labels = %q, want %q", labels, "op,outcome")
	}

	for _, forbiddenLabel := range []string{"username", "client_id", "flow_id", "reference", "redis_key", "error"} {
		if strings.Contains(labels, forbiddenLabel) {
			t.Fatalf("operation metric exposes forbidden label %q: %s", forbiddenLabel, description)
		}
	}
}
