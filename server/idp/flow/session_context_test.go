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

package flow

import (
	"testing"

	"github.com/croessner/nauthilus/server/definitions"
)

type contextTestManager struct {
	data map[string]any
}

func (m *contextTestManager) Set(key string, value any) {
	m.data[key] = value
}

func (m *contextTestManager) Delete(key string) {
	delete(m.data, key)
}

func TestRestoreFlowCookieContext(t *testing.T) {
	mgr := &contextTestManager{data: map[string]any{}}

	RestoreFlowCookieContext(mgr, definitions.ProtoOIDC, definitions.OIDCFlowAuthorizationCode)

	if mgr.data[definitions.SessionKeyIdPFlowType] != definitions.ProtoOIDC {
		t.Fatalf("expected %s to be restored", definitions.SessionKeyIdPFlowType)
	}

	if mgr.data[definitions.SessionKeyOIDCGrantType] != definitions.OIDCFlowAuthorizationCode {
		t.Fatalf("expected %s to be restored", definitions.SessionKeyOIDCGrantType)
	}
}

func TestSetRequireMFAPending(t *testing.T) {
	mgr := &contextTestManager{data: map[string]any{}}

	SetRequireMFAPending(mgr, "totp,webauthn")

	if mgr.data[definitions.SessionKeyRequireMFAFlow] != true {
		t.Fatalf("expected %s to be true", definitions.SessionKeyRequireMFAFlow)
	}

	if mgr.data[definitions.SessionKeyRequireMFAPending] != "totp,webauthn" {
		t.Fatalf("unexpected pending methods value")
	}

	SetRequireMFAPending(mgr, "")

	if _, ok := mgr.data[definitions.SessionKeyRequireMFAFlow]; ok {
		t.Fatalf("expected %s to be cleared", definitions.SessionKeyRequireMFAFlow)
	}

	if _, ok := mgr.data[definitions.SessionKeyRequireMFAPending]; ok {
		t.Fatalf("expected %s to be cleared", definitions.SessionKeyRequireMFAPending)
	}
}
