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

package pluginapi

import (
	"reflect"
	"testing"
)

const (
	responseMutationProtectionHeader = "X-Nauthilus-Protection"
	responseMutationStepupValue      = "stepup"
)

func TestResponseMutationResultSurfaces(t *testing.T) {
	mutation := ResponseMutation{
		Headers: ResponseHeaderMutation{
			Set: map[string][]string{
				responseMutationProtectionHeader: {responseMutationStepupValue},
			},
			Delete: []string{"X-Nauthilus-Stale"},
		},
		StatusHeader: true,
	}

	subject := SubjectResult{Response: mutation}
	if subject.Response.Headers.Set[responseMutationProtectionHeader][0] != responseMutationStepupValue {
		t.Fatalf("subject response mutation = %#v, want protection header", subject.Response)
	}

	obligation := ObligationResult{Response: mutation}
	if !obligation.Response.StatusHeader {
		t.Fatalf("obligation response mutation = %#v, want status header interaction", obligation.Response)
	}

	if _, ok := reflect.TypeFor[PostActionEnqueueResult]().FieldByName("Response"); ok {
		t.Fatal("post-action enqueue results must not expose late response mutation")
	}
}

func TestPostActionEnqueueResultRuntimeDeltaContract(t *testing.T) {
	resultType := reflect.TypeFor[PostActionEnqueueResult]()

	field, ok := resultType.FieldByName("RuntimeDelta")
	if !ok {
		t.Fatal("post-action enqueue results must expose a runtime delta")
	}

	if field.Type != reflect.TypeFor[RuntimeDelta]() {
		t.Fatalf("RuntimeDelta field type = %s, want %s", field.Type, reflect.TypeFor[RuntimeDelta]())
	}

	result := PostActionEnqueueResult{
		RuntimeDelta: RuntimeDelta{
			Set: map[string]any{"post_action_runtime": "shared"},
		},
		Enqueued: true,
	}
	if got := result.RuntimeDelta.Set["post_action_runtime"]; got != "shared" {
		t.Fatalf("post-action runtime delta value = %#v, want shared", got)
	}

	if _, ok := resultType.FieldByName("Response"); ok {
		t.Fatal("post-action enqueue results must still not expose response mutation")
	}
}
