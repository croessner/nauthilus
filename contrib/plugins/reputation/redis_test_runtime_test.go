//go:build reputation_integration

package main

import (
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/pluginruntime"
	"github.com/croessner/nauthilus/v4/server/rediscli"
	"github.com/croessner/nauthilus/v4/server/secret"
	"github.com/redis/go-redis/v9"
)

type integrationRedisHost struct{ client redis.UniversalClient }

var _ rediscli.Client = integrationRedisHost{}

// GetWriteHandle supplies the exclusively test-owned primary or Cluster connection.
func (h integrationRedisHost) GetWriteHandle() redis.UniversalClient { return h.client }

// GetReadHandle deliberately supplies no replica lane so accidental read routing fails the test.
func (integrationRedisHost) GetReadHandle() redis.UniversalClient { return nil }

// GetReadHandles has no replicas to initialize in this primary-only integration fixture.
func (integrationRedisHost) GetReadHandles() []redis.UniversalClient { return nil }

// GetWritePipeline preserves the host's primary pipeline contract.
func (h integrationRedisHost) GetWritePipeline() redis.Pipeliner { return h.client.Pipeline() }

// GetReadPipeline deliberately omits a replica pipeline from enforcing-path tests.
func (integrationRedisHost) GetReadPipeline() redis.Pipeliner { return nil }

// Close leaves connection lifecycle with the owning test cleanup.
func (integrationRedisHost) Close() {}

// GetSecurityManager returns a disposable fixture with no production key.
func (integrationRedisHost) GetSecurityManager() *rediscli.SecurityManager {
	return rediscli.NewSecurityManager(secret.Value{})
}

// localRedisFacade avoids ambient singletons and makes primary-only access testable.
func localRedisFacade(client redis.UniversalClient) pluginapi.Redis {
	return pluginruntime.NewRedisFacade(integrationRedisHost{client: client}, pluginruntime.RedisFacadePrefix("test-reputation:"))
}

// privateRedisDirectory creates a short owned path that fits Unix socket limits on macOS.
func privateRedisDirectory(t *testing.T) string {
	t.Helper()

	directory, err := os.MkdirTemp("/tmp", "reputation-redis-")
	requireNoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(directory) })

	return directory
}

// startPrivateRedis starts one bounded test-owned server and always reaps the child before removing its files.
func startPrivateRedis(t *testing.T, directory string, arguments ...string) {
	t.Helper()

	binary, err := exec.LookPath("valkey-server")
	if err != nil {
		binary, err = exec.LookPath("redis-server")
	}

	if err != nil {
		t.Fatal("local Redis/Valkey executable is required for the integration lane")
	}

	var log bytes.Buffer

	arguments = append([]string{"--save", "", "--appendonly", "no", "--bind", "127.0.0.1"}, arguments...)
	command := exec.Command(binary, arguments...)
	command.Dir = directory
	command.Stdout = &log
	command.Stderr = &log
	requireNoError(t, command.Start())
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
}

// waitPrivateRedis bounds startup waiting without accepting an operator-supplied endpoint.
func waitPrivateRedis(t *testing.T, client redis.UniversalClient) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for client.Ping(ctx).Err() != nil {
		select {
		case <-ctx.Done():
			t.Fatal("private Redis did not become ready")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// reserveLocalPort obtains a private ephemeral listener until the owned Redis process is ready to bind.
func reserveLocalPort(t *testing.T) (net.Listener, int) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	requireNoError(t, err)

	return listener, listener.Addr().(*net.TCPAddr).Port
}

// localReputationCluster creates three private loopback masters and assigns every hash slot explicitly.
func localReputationCluster(t *testing.T) (*redis.ClusterClient, pluginapi.Redis) {
	t.Helper()

	nodes := make([]*redis.Client, 0, 3)
	addresses := make([]string, 0, 3)
	ports, buses := make([]int, 0, 3), make([]int, 0, 3)

	for range 3 {
		directory := privateRedisDirectory(t)
		listener, port := reserveLocalPort(t)
		busListener, bus := reserveLocalPort(t)
		requireNoError(t, listener.Close())
		requireNoError(t, busListener.Close())
		startPrivateRedis(t, directory, "--port", strconv.Itoa(port), "--cluster-enabled", "yes", "--cluster-port", strconv.Itoa(bus),
			"--cluster-config-file", filepath.Join(directory, "nodes.conf"), "--cluster-node-timeout", "1000", "--cluster-announce-ip", "127.0.0.1",
			"--cluster-announce-port", strconv.Itoa(port), "--cluster-announce-bus-port", strconv.Itoa(bus))
		address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
		client := redis.NewClient(&redis.Options{Addr: address, MaxRetries: -1})

		t.Cleanup(func() { _ = client.Close() })
		waitPrivateRedis(t, client)
		nodes = append(nodes, client)
		addresses = append(addresses, address)
		ports = append(ports, port)
		buses = append(buses, bus)
	}

	configurePrivateCluster(t, nodes, ports, buses)

	client := redis.NewClusterClient(&redis.ClusterOptions{Addrs: addresses, MaxRetries: -1})

	t.Cleanup(func() { _ = client.Close() })

	return client, localRedisFacade(client)
}

// configurePrivateCluster joins only the owned nodes and waits for complete slot coverage.
func configurePrivateCluster(t *testing.T, nodes []*redis.Client, ports, buses []int) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for index, node := range nodes {
		requireNoError(t, node.Do(ctx, "CLUSTER", "SET-CONFIG-EPOCH", index+1).Err())
		requireNoError(t, node.ClusterAddSlotsRange(ctx, index*16384/len(nodes), (index+1)*16384/len(nodes)-1).Err())

		if index > 0 {
			requireNoError(t, nodes[0].Do(ctx, "CLUSTER", "MEET", "127.0.0.1", ports[index], buses[index]).Err())
		}
	}

	for _, node := range nodes {
		for {
			info, err := node.ClusterInfo(ctx).Result()
			if err == nil && strings.Contains(info, "cluster_state:ok") {
				break
			}

			select {
			case <-ctx.Done():
				t.Fatal("private Cluster did not become healthy")
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
}
