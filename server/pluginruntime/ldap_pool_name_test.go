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

package pluginruntime

import (
	"context"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v3/pluginapi/v1"
	"github.com/croessner/nauthilus/v3/server/backend/bktype"
	"github.com/croessner/nauthilus/v3/server/backend/priorityqueue"
	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
)

func TestPluginLDAPQueueRequestsResolveDefaultPoolAlias(t *testing.T) {
	tests := []struct {
		name     string
		poolName string
		want     string
	}{
		{name: "empty default alias", poolName: "", want: definitions.DefaultBackendName},
		{name: "public default alias", poolName: config.RemoteBackendDefaultName, want: definitions.DefaultBackendName},
		{name: "internal default name", poolName: definitions.DefaultBackendName, want: definitions.DefaultBackendName},
		{name: "named pool", poolName: "accounts", want: "accounts"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			searchRequest, err := newLDAPSearchQueueRequest(context.Background(), pluginapi.LDAPSearchRequest{
				PoolName: test.poolName,
				Scope:    pluginapi.LDAPScopeSub,
			})
			if err != nil {
				t.Fatalf("newLDAPSearchQueueRequest() error = %v", err)
			}

			if searchRequest.PoolName != test.want {
				t.Fatalf("search pool name = %q, want %q", searchRequest.PoolName, test.want)
			}

			modifyRequest, err := newLDAPModifyQueueRequest(context.Background(), pluginapi.LDAPModifyRequest{
				PoolName:  test.poolName,
				Operation: pluginapi.LDAPModifyReplace,
			})
			if err != nil {
				t.Fatalf("newLDAPModifyQueueRequest() error = %v", err)
			}

			if modifyRequest.PoolName != test.want {
				t.Fatalf("modify pool name = %q, want %q", modifyRequest.PoolName, test.want)
			}
		})
	}
}

func TestPluginLDAPDefaultAliasReachesDefaultWorker(t *testing.T) {
	queue := priorityqueue.NewLDAPRequestQueue(nil)
	queue.AddPoolName(definitions.DefaultBackendName)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	workerResult := make(chan string, 1)

	go func() {
		request := queue.PopWithContext(ctx, definitions.DefaultBackendName)
		if request == nil {
			workerResult <- ""

			return
		}

		workerResult <- request.PoolName

		request.LDAPReplyChan <- &bktype.LDAPReply{
			Result: bktype.AttributeMapping{"uid": {"alice"}},
		}
	}()

	result, err := NewLDAPQueueExecutor(queue).Search(ctx, pluginapi.LDAPSearchRequest{
		PoolName: config.RemoteBackendDefaultName,
		BaseDN:   "dc=example,dc=test",
		Filter:   "(uid=alice)",
		Scope:    pluginapi.LDAPScopeSub,
	})
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}

	if got := <-workerResult; got != definitions.DefaultBackendName {
		t.Fatalf("worker received pool name = %q, want %q", got, definitions.DefaultBackendName)
	}

	if got := result.Attributes["uid"][0]; got != "alice" {
		t.Fatalf("Search() uid = %q, want alice", got)
	}
}

func TestPluginLDAPQueueExecutorUsesMediumPriority(t *testing.T) {
	queue := &replyingLDAPQueue{}
	executor := NewLDAPQueueExecutor(queue)

	_, err := executor.Search(context.Background(), pluginapi.LDAPSearchRequest{
		PoolName: config.RemoteBackendDefaultName,
		Scope:    pluginapi.LDAPScopeSub,
	})
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}

	if queue.priority != priorityqueue.PriorityMedium {
		t.Fatalf("queue priority = %d, want %d", queue.priority, priorityqueue.PriorityMedium)
	}
}

type replyingLDAPQueue struct {
	priority int
}

// Push records the request priority and completes the synthetic LDAP request.
func (q *replyingLDAPQueue) Push(request *bktype.LDAPRequest, priority int) {
	q.priority = priority

	request.LDAPReplyChan <- &bktype.LDAPReply{}
}
