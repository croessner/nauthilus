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

package authmetrics

import "testing"

// TestNormalizeLabelsBoundsAuthenticationMetricCardinality fixes the label contract.
func TestNormalizeLabelsBoundsAuthenticationMetricCardinality(t *testing.T) {
	testCases := []struct {
		name          string
		transport     string
		outcome       string
		protocol      string
		wantTransport string
		wantOutcome   string
		wantProtocol  string
	}{
		{name: "http success", transport: "HTTP", outcome: "ok", protocol: " IMAP ", wantTransport: TransportHTTP, wantOutcome: OutcomeOK, wantProtocol: "imap"},
		{name: "grpc denial", transport: "grpc", outcome: "fail", protocol: "SMTP", wantTransport: TransportGRPC, wantOutcome: OutcomeFail, wantProtocol: "smtp"},
		{name: "temporary failure", transport: "grpc", outcome: "tempfail", protocol: "LMTP", wantTransport: TransportGRPC, wantOutcome: OutcomeTempFail, wantProtocol: "lmtp"},
		{name: "unknown protocol", transport: "http", outcome: "error", wantTransport: TransportHTTP, wantOutcome: OutcomeError, wantProtocol: ProtocolUnknown},
		{name: "attacker controlled labels", transport: "custom", outcome: "custom", protocol: "user-12345", wantTransport: TransportOther, wantOutcome: OutcomeError, wantProtocol: ProtocolOther},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			transport, outcome, protocol := normalizeLabels(testCase.transport, testCase.outcome, testCase.protocol)
			if transport != testCase.wantTransport || outcome != testCase.wantOutcome || protocol != testCase.wantProtocol {
				t.Fatalf(
					"labels = %q/%q/%q, want %q/%q/%q",
					transport,
					outcome,
					protocol,
					testCase.wantTransport,
					testCase.wantOutcome,
					testCase.wantProtocol,
				)
			}
		})
	}
}
