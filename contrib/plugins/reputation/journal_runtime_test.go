package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/twmb/franz-go/pkg/kgo"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
	"github.com/croessner/nauthilus/v4/server/pluginruntime"
)

// journalTestCertificate generates isolated startup credentials without reading deployment secrets.
func journalTestCertificate(t *testing.T) (string, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	requireNoError(t, err)

	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	requireNoError(t, err)
	encodedKey, err := x509.MarshalPKCS8PrivateKey(key)
	requireNoError(t, err)
	directory := t.TempDir()
	certificate := filepath.Join(directory, "certificate.pem")
	privateKey := filepath.Join(directory, "key.pem")

	requireNoError(t, os.WriteFile(certificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
	requireNoError(t, os.WriteFile(privateKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedKey}), 0600))

	return certificate, privateKey
}

// TestJournalRuntimeStopsWithLiveHost reproduces host-supervised workers detaching caller cancellation.
func TestJournalRuntimeStopsWithLiveHost(t *testing.T) {
	certificate, key := journalTestCertificate(t)
	raw := testConfigMap(t)
	journal := testJournalConfig()
	journal["ca_file"], journal["certificate_file"], journal["key_file"] = certificate, certificate, key
	raw["journal"] = journal
	cfg, err := decodeConfig(pluginregistry.NewConfigView(raw))
	requireNoError(t, err)
	state := &stateOwner{config: cfg, planner: &manifestPlanner{tagger: manifestTestTagger(t, false)}}
	registry := prometheus.NewRegistry()
	host := pluginruntime.NewHost(pluginruntime.WithMetricsFactory(func(scope string) pluginapi.Metrics {
		return pluginruntime.NewMetricsFacadeWithRegisterer(scope, registry)
	}))

	t.Cleanup(func() {
		host.CancelWorkers()
		host.WaitWorkers()
	})

	runtime, err := newJournalRuntime(state, host)
	requireNoError(t, err)
	runtime.start(host)

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()

	requireNoError(t, runtime.stop(ctx))
}

// unavailableJournalRuntime isolates delivery failure without opening external sockets.
func unavailableJournalRuntime(t *testing.T) *journalRuntime {
	t.Helper()

	client, err := kgo.NewClient(kgo.SeedBrokers("broker.invalid:9093"), kgo.Dialer(func(context.Context, string, string) (net.Conn, error) {
		return nil, errStateUnavailable
	}))
	requireNoError(t, err)
	t.Cleanup(client.Close)
	metrics, err := newJournalTelemetry(pluginruntime.NewMetricsFacadeWithRegisterer(pluginName, prometheus.NewRegistry()))
	requireNoError(t, err)

	return &journalRuntime{client: client, config: &journalConfig{Role: journalProducer, Topic: "test"}, timeout: time.Second,
		metrics: metrics, codec: journalCodec{tagger: manifestTestTagger(t, false), scope: "reputation-manifest", topic: "test"}}
}

// TestJournalRequiresBrokerAcknowledgement rejects a deadline even after a local receipt could be written.
func TestJournalRequiresBrokerAcknowledgement(t *testing.T) {
	for _, canceledBefore := range []bool{false, true} {
		t.Run(strconv.FormatBool(canceledBefore), func(t *testing.T) {
			runtime := unavailableJournalRuntime(t)

			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()
			if canceledBefore {
				cancel()
			}
			err := runtime.enqueue(ctx, "allocation", manifestPayload{}, float64(time.Now().Add(time.Hour).Unix()))
			if err == nil {
				t.Fatal("unconfirmed Kafka delivery was accepted")
			}
		})
	}
}
