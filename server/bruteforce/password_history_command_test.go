package bruteforce

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/definitions"
	"github.com/croessner/nauthilus/v3/server/log"
	"github.com/croessner/nauthilus/v3/server/rediscli"
	"github.com/croessner/nauthilus/v3/server/secret"
	"github.com/croessner/nauthilus/v3/server/util"
	"github.com/redis/go-redis/v9"
)

const (
	passwordHistoryCommandAccount = "account"
	passwordHistoryCommandGUID    = "command-guid"
	passwordHistoryCommandNonce   = "0123456789abcdef"
	passwordHistoryCommandPrefix  = "nt_"
)

func TestLoadAllPasswordHistoriesCommandShape(t *testing.T) {
	for _, tc := range passwordHistoryCommandScenarios {
		t.Run(tc.name, func(t *testing.T) {
			runPasswordHistoryCommandCase(t, tc)
		})
	}
}

type passwordHistoryCommandCase struct {
	name                string
	clientIP            string
	scopedIP            string
	accountName         string
	password            string
	ipv6CIDR            uint
	memberSeen          bool
	wantCommands        []passwordHistoryRedisCommand
	wantReadHandleCalls int
	wantAccountSeen     uint
	wantTotalSeen       uint
	wantLoginAttempts   uint
}

var passwordHistoryCommandScenarios = []passwordHistoryCommandCase{
	{
		name:        "known account with password skips legacy total reads for IPv4",
		clientIP:    "1.2.3.4",
		scopedIP:    "1.2.3.4",
		accountName: passwordHistoryCommandAccount,
		password:    "wrong-password",
		memberSeen:  true,
		wantCommands: passwordHistoryExpectedCommands(
			passwordHistoryCommandAccount,
			"1.2.3.4",
			true,
			true,
		),
		wantReadHandleCalls: 1,
		wantAccountSeen:     7,
		wantTotalSeen:       13,
		wantLoginAttempts:   1,
	},
	{
		name:        "known account without password skips membership read",
		clientIP:    "1.2.3.4",
		scopedIP:    "1.2.3.4",
		accountName: passwordHistoryCommandAccount,
		wantCommands: passwordHistoryExpectedCommands(
			passwordHistoryCommandAccount,
			"1.2.3.4",
			true,
			false,
		),
		wantReadHandleCalls: 1,
		wantAccountSeen:     7,
		wantTotalSeen:       13,
	},
	{
		name:     "unknown account skips account scoped reads and legacy total reads",
		clientIP: "1.2.3.4",
		scopedIP: "1.2.3.4",
		password: "wrong-password",
		wantCommands: passwordHistoryExpectedCommands(
			"",
			"1.2.3.4",
			false,
			false,
		),
		wantReadHandleCalls: 1,
		wantTotalSeen:       13,
	},
	{
		name:        "known account with password uses IPv6 CIDR scope",
		clientIP:    "2001:db8:abcd:1234::5",
		scopedIP:    "2001:db8:abcd:1234::/64",
		accountName: passwordHistoryCommandAccount,
		password:    "wrong-password",
		ipv6CIDR:    64,
		memberSeen:  true,
		wantCommands: passwordHistoryExpectedCommands(
			passwordHistoryCommandAccount,
			"2001:db8:abcd:1234::/64",
			true,
			true,
		),
		wantReadHandleCalls: 1,
		wantAccountSeen:     7,
		wantTotalSeen:       13,
		wantLoginAttempts:   1,
	},
}

// runPasswordHistoryCommandCase executes one command-shape scenario.
func runPasswordHistoryCommandCase(t *testing.T, tc passwordHistoryCommandCase) {
	t.Helper()

	cfg := passwordHistoryCommandConfig(tc.ipv6CIDR)
	handle := newPasswordHistoryCommandReadHandle(tc.scopedIP, tc.memberSeen)
	redisClient := &passwordHistoryTestRedisClient{readHandle: handle}

	bm := NewBucketManagerWithDeps(context.Background(), passwordHistoryCommandGUID, tc.clientIP, BucketManagerDeps{
		Cfg:    cfg,
		Logger: log.GetLogger(),
		Redis:  redisClient,
	})

	if tc.accountName != "" {
		bm = bm.WithAccountName(tc.accountName)
	}

	if tc.password != "" {
		bm = bm.WithPassword(secret.New(tc.password))
	}

	bm.LoadAllPasswordHistories()

	assertPasswordHistoryCommands(t, handle.commands, tc.wantCommands)
	assertPasswordHistoryReadState(t, bm, redisClient, tc.wantReadHandleCalls, tc.wantAccountSeen, tc.wantTotalSeen, tc.wantLoginAttempts)
}

func TestPasswordHistoryKeyEquivalence(t *testing.T) {
	tests := []struct {
		name           string
		clientIP       string
		scopedIP       string
		accountName    string
		ipv6CIDR       uint
		wantAccountKey bool
	}{
		{
			name:           "known IPv4 account",
			clientIP:       "1.2.3.4",
			scopedIP:       "1.2.3.4",
			accountName:    passwordHistoryCommandAccount,
			wantAccountKey: true,
		},
		{
			name:     "unknown IPv4 account",
			clientIP: "1.2.3.4",
			scopedIP: "1.2.3.4",
		},
		{
			name:           "known IPv6 CIDR account",
			clientIP:       "2001:db8:abcd:1234::5",
			scopedIP:       "2001:db8:abcd:1234::/64",
			accountName:    passwordHistoryCommandAccount,
			ipv6CIDR:       64,
			wantAccountKey: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := passwordHistoryCommandConfig(tc.ipv6CIDR)
			bm := NewBucketManagerWithDeps(context.Background(), passwordHistoryCommandGUID, tc.clientIP, BucketManagerDeps{
				Cfg:    cfg,
				Logger: log.GetLogger(),
				Redis:  &passwordHistoryTestRedisClient{readHandle: newPasswordHistoryCommandReadHandle(tc.scopedIP, false)},
			})

			if tc.accountName != "" {
				bm = bm.WithAccountName(tc.accountName)
			}

			impl, ok := bm.(*bucketManagerImpl)
			if !ok {
				t.Fatalf("unexpected bucket manager implementation: %T", bm)
			}

			assertPasswordHistoryKey(t, impl.getPasswordHistoryRedisSetKey(true), passwordHistorySetKey(tc.accountName, tc.scopedIP), tc.wantAccountKey)
			assertPasswordHistoryKey(t, impl.getPasswordHistoryTotalRedisKey(true), passwordHistoryTotalKey(tc.accountName, tc.scopedIP), tc.wantAccountKey)
			assertPasswordHistoryKey(t, impl.getPasswordHistoryRedisSetKey(false), passwordHistorySetKey("", tc.scopedIP), true)
			assertPasswordHistoryKey(t, impl.getPasswordHistoryTotalRedisKey(false), passwordHistoryTotalKey("", tc.scopedIP), true)
		})
	}
}

func TestPasswordHistoryLoadPlanComputesPasswordHashOnlyWhenNeeded(t *testing.T) {
	cfg := passwordHistoryCommandConfig(0)
	handle := newPasswordHistoryCommandReadHandle("1.2.3.4", true)
	redisClient := &passwordHistoryTestRedisClient{readHandle: handle}

	bm := NewBucketManagerWithDeps(context.Background(), passwordHistoryCommandGUID, "1.2.3.4", BucketManagerDeps{
		Cfg:    cfg,
		Logger: log.GetLogger(),
		Redis:  redisClient,
	}).
		WithAccountName(passwordHistoryCommandAccount)

	impl, ok := bm.(*bucketManagerImpl)
	if !ok {
		t.Fatalf("unexpected bucket manager implementation: %T", bm)
	}

	plan := impl.preparePasswordHistoryLoad(redisClient.GetReadHandle(), false)
	plan.loadPasswordHistoryCount(true)
	plan.loadCurrentPasswordHistoryMembership()
	plan.loadPasswordHistoryCount(false)

	if plan.hashComputed {
		t.Fatal("password hash was computed without a current password")
	}

	handle.commands = nil
	impl.password = secret.New("wrong-password")
	plan = impl.preparePasswordHistoryLoad(redisClient.GetReadHandle(), false)
	plan.loadCurrentPasswordHistoryMembership()

	if !plan.hashComputed {
		t.Fatal("password hash was not computed for membership read with a current password")
	}

	if plan.passwordHashes.Full() == "" || plan.passwordHashes.Legacy() == "" {
		t.Fatal("password hash is empty after membership read with a current password")
	}

	assertPasswordHistoryCommands(t, handle.commands, []passwordHistoryRedisCommand{
		{name: "SISMEMBER", key: passwordHistorySetKey(passwordHistoryCommandAccount, "1.2.3.4")},
	})
}

func BenchmarkLoadAllPasswordHistories(b *testing.B) {
	for _, bmCase := range passwordHistoryBenchmarkCases() {
		b.Run(bmCase.name, func(b *testing.B) {
			runPasswordHistoryBenchmark(b, bmCase)
		})
	}
}

type passwordHistoryBenchmarkCase struct {
	name        string
	clientIP    string
	scopedIP    string
	accountName string
	password    string
	ipv6CIDR    uint
}

// passwordHistoryBenchmarkCases returns benchmark scenarios for password-history loads.
func passwordHistoryBenchmarkCases() []passwordHistoryBenchmarkCase {
	return []passwordHistoryBenchmarkCase{
		{
			name:        "IPv4WithPassword",
			clientIP:    "1.2.3.4",
			scopedIP:    "1.2.3.4",
			accountName: passwordHistoryCommandAccount,
			password:    "wrong-password",
		},
		{
			name:        "IPv4WithoutPassword",
			clientIP:    "1.2.3.4",
			scopedIP:    "1.2.3.4",
			accountName: passwordHistoryCommandAccount,
		},
		{
			name:     "IPv4UnknownAccount",
			clientIP: "1.2.3.4",
			scopedIP: "1.2.3.4",
			password: "wrong-password",
		},
		{
			name:        "IPv6CIDRWithPassword",
			clientIP:    "2001:db8:abcd:1234::5",
			scopedIP:    "2001:db8:abcd:1234::/64",
			accountName: passwordHistoryCommandAccount,
			password:    "wrong-password",
			ipv6CIDR:    64,
		},
	}
}

// runPasswordHistoryBenchmark executes one benchmark scenario without timing setup.
func runPasswordHistoryBenchmark(b *testing.B, bmCase passwordHistoryBenchmarkCase) {
	b.Helper()

	cfg := passwordHistoryCommandConfig(bmCase.ipv6CIDR)
	handle := newPasswordHistoryCommandReadHandle(bmCase.scopedIP, false)
	handle.recordCommands = false
	redisClient := &passwordHistoryTestRedisClient{readHandle: handle}
	manager := NewBucketManagerWithDeps(context.Background(), passwordHistoryCommandGUID, bmCase.clientIP, BucketManagerDeps{
		Cfg:    cfg,
		Logger: log.GetLogger(),
		Redis:  redisClient,
	})

	if bmCase.accountName != "" {
		manager = manager.WithAccountName(bmCase.accountName)
	}

	if bmCase.password != "" {
		manager = manager.WithPassword(secret.New(bmCase.password))
	}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		manager.LoadAllPasswordHistories()
	}
}

// assertPasswordHistoryKey verifies that generated keys keep the historical byte representation.
func assertPasswordHistoryKey(t *testing.T, got string, want string, wantPresent bool) {
	t.Helper()

	if !wantPresent {
		if got != "" {
			t.Fatalf("key = %q, want empty key", got)
		}

		return
	}

	if got != want {
		t.Fatalf("key = %q, want %q", got, want)
	}
}

// passwordHistoryTestRedisClient provides a hermetic Redis client seam for password-history tests.
type passwordHistoryTestRedisClient struct {
	readHandle redis.UniversalClient

	readHandleCalls int
}

// GetWriteHandle returns the shared fake handle for unused write paths.
func (c *passwordHistoryTestRedisClient) GetWriteHandle() redis.UniversalClient {
	return c.readHandle
}

// GetReadHandle returns the fake read handle and records handle lookup frequency.
func (c *passwordHistoryTestRedisClient) GetReadHandle() redis.UniversalClient {
	c.readHandleCalls++

	return c.readHandle
}

// GetWritePipeline returns nil because password-history command tests do not use pipelines.
func (c *passwordHistoryTestRedisClient) GetWritePipeline() redis.Pipeliner {
	return nil
}

// GetReadPipeline returns nil because password-history command tests do not use pipelines.
func (c *passwordHistoryTestRedisClient) GetReadPipeline() redis.Pipeliner {
	return nil
}

// GetReadHandles returns the single fake read handle for interface completeness.
func (c *passwordHistoryTestRedisClient) GetReadHandles() []redis.UniversalClient {
	return []redis.UniversalClient{c.readHandle}
}

// Close is a no-op because the fake client owns no external resources.
func (c *passwordHistoryTestRedisClient) Close() {}

// GetSecurityManager returns nil because password-history reads do not use encryption helpers.
func (c *passwordHistoryTestRedisClient) GetSecurityManager() *rediscli.SecurityManager {
	return nil
}

type passwordHistoryRedisCommand struct {
	name   string
	key    string
	member string
}

type passwordHistoryCommandReadHandle struct {
	redis.UniversalClient

	sCardValues    map[string]int64
	memberValues   map[string]bool
	exactMembers   map[string]map[string]bool
	commands       []passwordHistoryRedisCommand
	recordCommands bool
}

// newPasswordHistoryCommandReadHandle creates a deterministic fake Redis read handle.
func newPasswordHistoryCommandReadHandle(scopedIP string, memberSeen bool) *passwordHistoryCommandReadHandle {
	accountSetKey := passwordHistorySetKey(passwordHistoryCommandAccount, scopedIP)
	ipSetKey := passwordHistorySetKey("", scopedIP)

	return &passwordHistoryCommandReadHandle{
		sCardValues: map[string]int64{
			accountSetKey: 7,
			ipSetKey:      13,
		},
		memberValues: map[string]bool{
			accountSetKey: memberSeen,
		},
		recordCommands: true,
	}
}

// SCard records an SCARD read and returns deterministic password-history counts.
func (h *passwordHistoryCommandReadHandle) SCard(_ context.Context, key string) *redis.IntCmd {
	h.record("SCARD", key, "")

	return redis.NewIntResult(h.sCardValues[key], nil)
}

// Get records a GET read and returns a Redis nil miss for ignored total counters.
func (h *passwordHistoryCommandReadHandle) Get(_ context.Context, key string) *redis.StringCmd {
	h.record("GET", key, "")

	return redis.NewStringResult("", redis.Nil)
}

// SIsMember records an SISMEMBER read and returns deterministic membership.
func (h *passwordHistoryCommandReadHandle) SIsMember(_ context.Context, key string, member any) *redis.BoolCmd {
	memberValue := fmt.Sprint(member)
	h.record("SISMEMBER", key, memberValue)

	if h.exactMembers != nil {
		return redis.NewBoolResult(h.exactMembers[key][memberValue], nil)
	}

	return redis.NewBoolResult(h.memberValues[key], nil)
}

// record stores the observed Redis command when command recording is enabled.
func (h *passwordHistoryCommandReadHandle) record(name string, key string, member string) {
	if !h.recordCommands {
		return
	}

	h.commands = append(h.commands, passwordHistoryRedisCommand{
		name:   name,
		key:    key,
		member: member,
	})
}

// passwordHistoryCommandConfig returns the minimal config needed by command-shape tests.
func passwordHistoryCommandConfig(ipv6CIDR uint) config.File {
	runtimeModule := config.RuntimeModule{}
	if err := runtimeModule.Set(definitions.ControlBruteForce); err != nil {
		panic(err)
	}

	cfg := &config.FileSettings{
		Server: &config.ServerSection{
			RuntimeModules: []*config.RuntimeModule{&runtimeModule},
			Redis: config.Redis{
				Prefix:        passwordHistoryCommandPrefix,
				PasswordNonce: secret.New(passwordHistoryCommandNonce),
			},
		},
		BruteForce: &config.BruteForceSection{
			IPScoping: config.IPScoping{
				RepeatingWrongPasswordIPv6CIDR: ipv6CIDR,
			},
			Buckets: []config.BruteForceRule{
				{
					Name:           "command-shape",
					Period:         time.Minute,
					CIDR:           32,
					IPv4:           true,
					IPv6:           true,
					FailedRequests: 5,
				},
			},
		},
	}

	config.SetTestEnvironmentConfig(config.NewTestEnvironmentConfig())
	config.SetTestFile(cfg)
	util.SetDefaultConfigFile(cfg)
	util.SetDefaultEnvironment(config.NewTestEnvironmentConfig())
	log.SetupLogging(definitions.LogLevelNone, false, false, false, "test")

	return cfg
}

// passwordHistoryExpectedCommands returns the supported command order for password-history reads.
func passwordHistoryExpectedCommands(accountName string, scopedIP string, includeAccount bool, includeMembership bool) []passwordHistoryRedisCommand {
	commands := make([]passwordHistoryRedisCommand, 0, 3)

	if includeAccount {
		commands = append(commands, passwordHistoryRedisCommand{name: "SCARD", key: passwordHistorySetKey(accountName, scopedIP)})
	}

	if includeMembership {
		commands = append(commands, passwordHistoryRedisCommand{name: "SISMEMBER", key: passwordHistorySetKey(accountName, scopedIP)})
	}

	commands = append(commands, passwordHistoryRedisCommand{name: "SCARD", key: passwordHistorySetKey("", scopedIP)})

	return commands
}

// passwordHistorySetKey returns the expected password-history set key for command-shape assertions.
func passwordHistorySetKey(accountName string, scopedIP string) string {
	return passwordHistoryCommandKey(definitions.RedisPwHashKey, accountName, scopedIP)
}

// passwordHistoryTotalKey returns the expected password-history total key for command-shape assertions.
func passwordHistoryTotalKey(accountName string, scopedIP string) string {
	return passwordHistoryCommandKey(definitions.RedisPwHistTotalKey, accountName, scopedIP)
}

// passwordHistoryCommandKey formats the current password-history Redis key contract.
func passwordHistoryCommandKey(baseKey string, accountName string, scopedIP string) string {
	if accountName == "" {
		return fmt.Sprintf("%s%s:{%s}:%s", passwordHistoryCommandPrefix, baseKey, scopedIP, scopedIP)
	}

	return fmt.Sprintf("%s%s:{%s:%s}:%s:%s", passwordHistoryCommandPrefix, baseKey, accountName, scopedIP, accountName, scopedIP)
}

// assertPasswordHistoryCommands compares command name, key, and membership payload presence.
func assertPasswordHistoryCommands(t *testing.T, got []passwordHistoryRedisCommand, want []passwordHistoryRedisCommand) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("recorded %d Redis commands, want %d: %#v", len(got), len(want), got)
	}

	for i := range want {
		if got[i].name != want[i].name || got[i].key != want[i].key {
			t.Fatalf("command %d = %#v, want %#v", i, got[i], want[i])
		}

		if got[i].name == "SISMEMBER" && got[i].member == "" {
			t.Fatalf("command %d has empty membership payload: %#v", i, got[i])
		}
	}
}

// assertPasswordHistoryReadState verifies read counts and public bucket-manager state.
func assertPasswordHistoryReadState(
	t *testing.T,
	bm BucketManager,
	redisClient *passwordHistoryTestRedisClient,
	wantReadHandleCalls int,
	wantAccountSeen uint,
	wantTotalSeen uint,
	wantLoginAttempts uint,
) {
	t.Helper()

	if redisClient.readHandleCalls != wantReadHandleCalls {
		t.Fatalf("GetReadHandle calls = %d, want %d", redisClient.readHandleCalls, wantReadHandleCalls)
	}

	if bm.GetPasswordsAccountSeen() != wantAccountSeen {
		t.Fatalf("passwordsAccountSeen = %d, want %d", bm.GetPasswordsAccountSeen(), wantAccountSeen)
	}

	if bm.GetPasswordsTotalSeen() != wantTotalSeen {
		t.Fatalf("passwordsTotalSeen = %d, want %d", bm.GetPasswordsTotalSeen(), wantTotalSeen)
	}

	if bm.GetLoginAttempts() != wantLoginAttempts {
		t.Fatalf("loginAttempts = %d, want %d", bm.GetLoginAttempts(), wantLoginAttempts)
	}
}
