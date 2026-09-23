//go:build reputation_integration

package main

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/pluginregistry"
	"github.com/redis/go-redis/v9"
)

const monitorSentinel = "reputation-command-budget-sentinel"

// Budgets bound the Redis work one steady-state authentication may spend on its hottest subject keys.
const (
	maximumStateCommandsPerAuthentication = 10
	maximumSeenCommandsPerAuthentication  = 8
	maximumScriptCallsPerAuthentication   = 6
)

// redisCommandMonitor reads the raw MONITOR stream of one private test server, including commands issued by scripts.
type redisCommandMonitor struct {
	conn   net.Conn
	reader *bufio.Reader
}

// commandBudget aggregates one measured window by top-level scripts and per-key inner commands.
type commandBudget struct {
	perKey  map[string]int
	scripts int
	total   int
}

// startRedisCommandMonitor opens a dedicated MONITOR connection on the private Unix socket.
func startRedisCommandMonitor(t *testing.T, client *redis.Client) *redisCommandMonitor {
	t.Helper()

	conn, err := net.Dial("unix", client.Options().Addr)
	requireNoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	_, err = conn.Write([]byte("MONITOR\r\n"))
	requireNoError(t, err)

	monitor := &redisCommandMonitor{conn: conn, reader: bufio.NewReader(conn)}
	if line := monitor.readLine(t); line != "+OK" {
		t.Fatalf("MONITOR was not accepted: %q", line)
	}

	return monitor
}

// readLine returns one bounded protocol line within a short deadline.
func (m *redisCommandMonitor) readLine(t *testing.T) string {
	t.Helper()

	requireNoError(t, m.conn.SetReadDeadline(time.Now().Add(5*time.Second)))

	line, err := m.reader.ReadString('\n')
	requireNoError(t, err)

	return strings.TrimRight(line, "\r\n")
}

// collect drains the stream up to an explicit sentinel so the window contains every measured command.
func (m *redisCommandMonitor) collect(t *testing.T, client *redis.Client) commandBudget {
	t.Helper()
	requireNoError(t, client.Echo(context.Background(), monitorSentinel).Err())

	budget := commandBudget{perKey: map[string]int{}}

	for {
		line := m.readLine(t)
		arguments := monitorArguments(line)

		if len(arguments) == 0 {
			continue
		}

		if strings.EqualFold(arguments[0], "ECHO") && len(arguments) > 1 && arguments[1] == monitorSentinel {
			return budget
		}

		budget.record(line, arguments)
	}
}

// record separates top-level script calls from the commands those scripts execute.
func (b *commandBudget) record(line string, arguments []string) {
	command := strings.ToUpper(arguments[0])
	if !strings.Contains(line, " lua]") {
		if command == "EVALSHA" || command == "EVAL" {
			b.scripts++
		}

		return
	}

	b.total++

	if len(arguments) > 1 {
		b.perKey[arguments[1]]++
	}
}

// hottest returns the largest per-key command count among keys containing marker.
func (b commandBudget) hottest(marker string) int {
	result := 0

	for key, count := range b.perKey {
		if strings.Contains(key, marker) && count > result {
			result = count
		}
	}

	return result
}

// monitorArguments extracts the quoted command arguments of one MONITOR line.
func monitorArguments(line string) []string {
	var (
		arguments []string
		current   strings.Builder
		quoted    bool
		escaped   bool
	)

	for _, character := range line {
		switch {
		case escaped:
			escaped = false

			current.WriteRune(character)
		case quoted && character == '\\':
			escaped = true
		case character == '"':
			if quoted {
				arguments = append(arguments, current.String())
				current.Reset()
			}

			quoted = !quoted
		case quoted:
			current.WriteRune(character)
		}
	}

	return arguments
}

// authenticationBudgetOwner starts a primary-only state owner with the shipped authentication catalog.
func authenticationBudgetOwner(t *testing.T, facade pluginapi.Redis) *stateOwner {
	t.Helper()

	cfg, err := decodeConfig(pluginregistry.NewConfigView(learningConfigMap(t)))
	requireNoError(t, err)

	owner, err := newStateOwner(cfg, manifestTestTagger(t, false), facade)
	requireNoError(t, err)
	requireNoError(t, owner.start(t.Context()))

	return owner
}

// authenticateOnce performs the decision-time assessment and the background learning of one successful login.
func authenticateOnce(t *testing.T, owner *stateOwner, event string) {
	t.Helper()

	const clientIP = "192.0.2.7"

	subject := subjectInput{role: "auth_client", kind: kindIP, value: clientIP}
	if owner.assess(t.Context(), subject, profileOperational).State == assessmentUnavailable {
		t.Fatal("assessment unavailable")
	}

	identity, err := pluginapi.NewExecutionIdentityView(pluginName, componentLearnOutcome, extensionObligation, operationExecute, authenticationTarget)
	requireNoError(t, err)
	request, err := pluginapi.NewObligationRequest(pluginapi.ObligationRequest{Snapshot: pluginapi.RequestSnapshot{ClientIP: clientIP}}, identity)
	requireNoError(t, err)
	request.BackendOutcome, err = pluginapi.NewBackendOutcomeView(event, "verified-account", pluginapi.BackendOutcomeAuthenticated, time.Now())
	requireNoError(t, err)

	if result := owner.learnAuthentication(t.Context(), learningJobFromRequest(t, owner.config, request)); result != storageApplied {
		t.Fatalf("authentication learning result %q", result)
	}
}

// TestReputationRedisAuthenticationCommandBudget pins the Redis work one steady-state authentication spends on its hottest subject keys.
func TestReputationRedisAuthenticationCommandBudget(t *testing.T) {
	client, facade := localReputationRedis(t)
	owner := authenticationBudgetOwner(t, facade)

	authenticateOnce(t, owner, "budget-warm-up")

	monitor := startRedisCommandMonitor(t, client)
	authenticateOnce(t, owner, "budget-measured")
	budget := monitor.collect(t, client)

	state, seen := budget.hottest(":state:"), budget.hottest(":seen:")
	t.Logf("per authentication: scripts=%d script-commands=%d hottest-state-key=%d hottest-seen-key=%d", budget.scripts, budget.total, state, seen)

	if state > maximumStateCommandsPerAuthentication || seen > maximumSeenCommandsPerAuthentication || budget.scripts > maximumScriptCallsPerAuthentication {
		t.Fatal("authentication exceeded its hot-key Redis command budget")
	}
}
