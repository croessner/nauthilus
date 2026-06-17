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

	pluginapi "github.com/croessner/nauthilus/pluginapi/v1"
	"github.com/croessner/nauthilus/server/rediscli"

	"github.com/go-redis/redismock/v9"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

const (
	facadeLDAPDN       = "uid=demo,dc=example,dc=test"
	facadeLDAPMail     = "demo@example.test"
	facadeLDAPPoolName = "default"
	facadeMetricResult = "result"
	facadeMetricOK     = "ok"
)

func TestRedisFacadeUsesInjectedHandles(t *testing.T) {
	db, mock := redismock.NewClientMock()
	redisClient := rediscli.NewTestClient(db)
	facade := NewRedisFacade(redisClient)

	mock.ExpectGet("key").SetVal("value")

	if got := facade.Read().Get(context.Background(), "key").Val(); got != "value" {
		t.Fatalf("Read().Get() = %q, want value", got)
	}

	if facade.Write() == nil {
		t.Fatal("Write() returned nil")
	}

	if facade.ReadPipeline() == nil || facade.WritePipeline() == nil {
		t.Fatal("Redis facade returned nil pipeline")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("Redis expectations were not met: %v", err)
	}
}

func TestLDAPFacadeMapsSearchAndModifyRequests(t *testing.T) {
	fake := &recordingLDAPExecutor{
		searchResult: pluginapi.LDAPSearchResult{
			Attributes: map[string][]string{backendTestMailAttr: {facadeLDAPMail}},
			Entries: []pluginapi.LDAPEntry{
				{DN: facadeLDAPDN, Attributes: map[string][]string{"cn": {"Demo"}}},
			},
		},
	}
	facade := NewLDAPFacade(fake)

	searchRequest := pluginapi.LDAPSearchRequest{
		PoolName:   facadeLDAPPoolName,
		BaseDN:     "dc=example,dc=test",
		Filter:     "(uid=demo)",
		Scope:      pluginapi.LDAPScopeSub,
		Attributes: []string{backendTestMailAttr},
	}

	searchResult, err := facade.Search(context.Background(), searchRequest)
	if err != nil {
		t.Fatalf("Search() error = %v", err)
	}

	if got := searchResult.Attributes[backendTestMailAttr][0]; got != facadeLDAPMail {
		t.Fatalf("Search() mail = %q, want %s", got, facadeLDAPMail)
	}

	modifyRequest := pluginapi.LDAPModifyRequest{
		PoolName:   facadeLDAPPoolName,
		DN:         facadeLDAPDN,
		Operation:  pluginapi.LDAPModifyReplace,
		Attributes: map[string][]string{"description": {"updated"}},
	}
	if err := facade.Modify(context.Background(), modifyRequest); err != nil {
		t.Fatalf("Modify() error = %v", err)
	}

	if len(fake.searchRequests) != 1 || fake.searchRequests[0].Filter != searchRequest.Filter {
		t.Fatalf("mapped search requests = %#v", fake.searchRequests)
	}

	if len(fake.modifyRequests) != 1 || fake.modifyRequests[0].Operation != modifyRequest.Operation {
		t.Fatalf("mapped modify requests = %#v", fake.modifyRequests)
	}
}

func TestMetricsFacadeRejectsUndeclaredLabels(t *testing.T) {
	metrics := NewMetricsFacade("geoip")

	counter, err := metrics.Counter(pluginapi.MetricDefinition{
		Name:   "lookups",
		Help:   "lookup count",
		Labels: []string{facadeMetricResult},
	})
	if err != nil {
		t.Fatalf("Counter() error = %v", err)
	}

	counter.Add(context.Background(), 1, pluginapi.LabelValue{Name: "unknown", Value: "bad"})

	if got := metrics.ObservationCount("lookups"); got != 0 {
		t.Fatalf("ObservationCount() = %d, want 0 for rejected labels", got)
	}

	counter.Add(context.Background(), 1, pluginapi.LabelValue{Name: facadeMetricResult, Value: facadeMetricOK})

	if got := metrics.ObservationCount("lookups"); got != 1 {
		t.Fatalf("ObservationCount() = %d, want 1 after declared label", got)
	}
}

func TestMetricsFacadeExportsPluginCounterToPrometheus(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics := NewMetricsFacadeWithRegisterer("geoip", registry)

	counter, err := metrics.Counter(pluginapi.MetricDefinition{
		Name:   "lookup_total",
		Help:   "plugin lookup count",
		Labels: []string{facadeMetricResult},
	})
	if err != nil {
		t.Fatalf("Counter() error = %v", err)
	}

	counter.Add(context.Background(), 2, pluginapi.LabelValue{Name: facadeMetricResult, Value: facadeMetricOK})

	families, err := registry.Gather()
	if err != nil {
		t.Fatalf("Gather() error = %v", err)
	}

	for _, family := range families {
		if family.GetName() != "nauthilus_plugin_geoip_lookup_total" {
			continue
		}

		for _, metric := range family.GetMetric() {
			if metric.GetCounter().GetValue() != 2 {
				t.Fatalf("counter value = %f, want 2", metric.GetCounter().GetValue())
			}

			if !prometheusMetricHasLabel(metric, "plugin_scope", "geoip") {
				t.Fatalf("counter labels = %#v, want plugin_scope=geoip", metric.GetLabel())
			}

			if !prometheusMetricHasLabel(metric, facadeMetricResult, facadeMetricOK) {
				t.Fatalf("counter labels = %#v, want result=ok", metric.GetLabel())
			}

			return
		}
	}

	t.Fatal("exported plugin counter was not gathered")
}

// prometheusMetricHasLabel reports whether a gathered metric has the expected label pair.
func prometheusMetricHasLabel(metric *dto.Metric, name string, value string) bool {
	for _, label := range metric.GetLabel() {
		if label.GetName() == name && label.GetValue() == value {
			return true
		}
	}

	return false
}

type recordingLDAPExecutor struct {
	searchResult   pluginapi.LDAPSearchResult
	searchRequests []pluginapi.LDAPSearchRequest
	modifyRequests []pluginapi.LDAPModifyRequest
}

func (e *recordingLDAPExecutor) Search(_ context.Context, request pluginapi.LDAPSearchRequest) (pluginapi.LDAPSearchResult, error) {
	e.searchRequests = append(e.searchRequests, request)

	return e.searchResult, nil
}

func (e *recordingLDAPExecutor) Modify(_ context.Context, request pluginapi.LDAPModifyRequest) error {
	e.modifyRequests = append(e.modifyRequests, request)

	return nil
}
