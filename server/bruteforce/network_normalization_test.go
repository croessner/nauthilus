package bruteforce

import (
	"context"
	"testing"
	"time"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/secret"
)

// TestMappedIPv4RuleCoverage preserves IPv4 rules across equivalent input representations.
func TestMappedIPv4RuleCoverage(t *testing.T) {
	cfg := &config.FileSettings{Server: &config.ServerSection{Redis: config.Redis{Prefix: "test:"}}}
	rules := []config.BruteForceRule{{Name: "ipv4", CIDR: 24, IPv4: true, Period: time.Minute, FailedRequests: 5}}

	for _, ip := range []string{"192.0.2.9", "::ffff:192.0.2.9", "::ffff:c000:209"} {
		t.Run(ip, func(t *testing.T) {
			bm := NewBucketManagerWithDeps(context.Background(), "test", ip, BucketManagerDeps{Cfg: cfg})
			bm.PrepareNetcalc(rules)

			_, network, err := bm.GetBruteForceBanRedisKey(&rules[0])
			if err != nil || network != "192.0.2.0/24" {
				t.Fatalf("network=%q err=%v; want identical IPv4 rule coverage", network, err)
			}
		})
	}
}

// TestRWPSubsecondWindowKeepsHistory avoids an immediate EXPIRE when the configured window is positive.
func TestRWPSubsecondWindowKeepsHistory(t *testing.T) {
	cfg := passwordHistoryCommandConfig(0)
	cfg.GetBruteForce().RWPWindow = time.Millisecond
	bm := NewBucketManagerWithDeps(t.Context(), "test", "192.0.2.1", BucketManagerDeps{Cfg: cfg}).WithAccountName("account").WithPassword(secret.New("wrong"))

	args := bm.(*bucketManagerImpl).buildRWPScriptArgs()
	if args == nil || args.argTTL != "1" {
		t.Fatalf("positive subsecond window must retain history for at least one second: %+v", args)
	}
}
