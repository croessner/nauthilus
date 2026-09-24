//go:build reputation_worker

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/viper"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/app/bootfx"
	serverconfig "github.com/croessner/nauthilus/v4/server/config"
	"github.com/croessner/nauthilus/v4/server/log"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
	"github.com/croessner/nauthilus/v4/server/pluginruntime"
	"github.com/croessner/nauthilus/v4/server/rediscli"
)

var workerVersion = "development"

// main starts only reputation consumption and operational HTTP endpoints, never authentication or identity routes.
func main() {
	path := flag.String("config", "", "path to the validated Nauthilus worker configuration")
	version := flag.Bool("version", false, "print worker version")

	flag.Parse()

	if *version {
		fmt.Println(workerVersion)
		return
	}

	if *path == "" {
		fmt.Fprintln(os.Stderr, "reputation worker requires -config")
		os.Exit(1)
	}

	serverconfig.ConfigFilePath = *path
	serverconfig.ConfigFileType = "yaml"

	viper.SetConfigFile(*path)
	viper.SetConfigType("yaml")

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	if err := runReputationWorker(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "reputation worker stopped with an initialization or runtime error")
		os.Exit(1)
	}
}

// runReputationWorker reuses sealed configuration and the centralized Redis runtime without creating an authentication server.
func runReputationWorker(ctx context.Context) error {
	file, err := bootfx.PrepareConfiguration()
	if err != nil {
		return errConfiguration
	}

	cfg, err := workerReputationConfig(file)
	if err != nil {
		return err
	}

	client, err := rediscli.NewClientWithDeps(file, log.GetLogger())
	if err != nil {
		return errStateUnavailable
	}

	defer client.Close()

	tagger, err := pluginruntime.OpaqueIdentifierTaggerFromConfig(file)
	if err != nil || tagger == nil {
		return errStateUnavailable
	}

	registry := prometheus.NewRegistry()
	host := pluginruntime.NewHost(pluginruntime.WithServiceContext(ctx), pluginruntime.WithRedisPrefix(file.GetServer().GetRedis().GetPrefix()),
		pluginruntime.WithRedisClient(client), pluginruntime.WithOpaqueIdentifierTagger(tagger),
		pluginruntime.WithMetricsFactory(func(scope string) pluginapi.Metrics {
			return pluginruntime.NewMetricsFacadeWithRegisterer(scope, registry)
		}))

	return serveReputationWorker(ctx, file, cfg, host, tagger, registry)
}

// workerReputationConfig admits exactly one configured consumer module and no producer responsibility.
func workerReputationConfig(file serverconfig.File) (*configuration, error) {
	if file.GetPlugins() == nil {
		return nil, errConfiguration
	}

	var selected *configuration

	for _, module := range file.GetPlugins().Modules {
		if module.Name != pluginName {
			continue
		}

		if selected != nil {
			return nil, errConfiguration
		}

		cfg, err := decodeConfig(pluginregistry.NewConfigView(module.Config))
		if err != nil || cfg.raw.Journal == nil || cfg.raw.Journal.Role != journalConsumer {
			return nil, errConfiguration
		}

		selected = cfg
	}

	if selected == nil {
		return nil, errConfiguration
	}

	return selected, nil
}

// serveReputationWorker coordinates Redis activation, Kafka consumption and bounded shutdown of operational endpoints.
func serveReputationWorker(ctx context.Context, file serverconfig.File, cfg *configuration, host *pluginruntime.Host,
	tagger pluginapi.OpaqueIdentifierTagger, registry *prometheus.Registry) error {
	state, err := newStateOwner(cfg, tagger, host.Redis())
	if err != nil {
		return err
	}

	state.telemetry, err = newReputationTelemetry(cfg, host.Metrics(pluginName))
	if err != nil {
		return err
	}

	if err := state.startWithRetry(ctx, host.Logger(pluginName)); err != nil {
		return err
	}

	journal, err := newJournalRuntime(state, host)
	if err != nil {
		return err
	}

	server, listener, err := newWorkerHTTPServer(file, state, registry)
	if err != nil {
		journal.client.Close()
		return err
	}

	journal.start(host)

	errors := make(chan error, 1)

	host.Go(ctx, "reputation-worker-http", func(context.Context) error {
		errors <- server.ServeTLS(listener, "", "")
		return nil
	})

	var failure error

	select {
	case <-ctx.Done():
	case <-errors:
		failure = errStateUnavailable
	}

	state.ready.Store(false)

	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	httpError := server.Shutdown(shutdown)
	journalError := journal.stop(shutdown)

	host.CancelWorkers()
	workerError := host.WaitWorkersContext(shutdown)

	if httpError != nil || journalError != nil || workerError != nil {
		return errStateUnavailable
	}

	return failure
}
