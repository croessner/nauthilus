package core

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/croessner/nauthilus/v4/server/util"
	"github.com/redis/go-redis/v9"
)

// ErrMFAAttemptLimit indicates that the account's shared code-verification budget is exhausted.
var ErrMFAAttemptLimit = errors.New("MFA verification attempt limit exceeded")

// mfaAttemptReservation retains the script source for go-redis NOSCRIPT recovery.
var mfaAttemptReservation = redis.NewScript(mfaAttemptScript)

const (
	mfaAttemptLimit  = 10
	mfaAttemptWindow = 5 * time.Minute
	// mfaAttemptScript reserves capacity before verification without extending a blocked window.
	mfaAttemptScript = `
local count = tonumber(redis.call('GET', KEYS[1]) or '0')
if count >= tonumber(ARGV[1]) then return 0 end
count = redis.call('INCR', KEYS[1])
if count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[2]) end
return 1
`
)

// ConsumeMFAAttempt reserves one account-wide TOTP/recovery verification before accessing a verifier.
// The trusted stable identity excludes IP, method and challenge so none can reset the budget.
// Successful attempts also consume capacity; resetting on success would race concurrent guesses.
func ConsumeMFAAttempt(ctx context.Context, deps AuthDeps, identity string) error {
	if deps.Cfg == nil || deps.Redis == nil || identity == "" {
		return errors.New("MFA attempt storage or identity unavailable")
	}

	key := fmt.Sprintf("%smfa:attempt:{%x}", deps.Cfg.GetServer().GetRedis().GetPrefix(), sha256.Sum256([]byte(identity)))

	dCtx, cancel := util.GetCtxWithDeadlineRedisWrite(ctx, deps.Cfg)
	defer cancel()

	result, err := mfaAttemptReservation.Run(dCtx, deps.Redis.GetWriteHandle(),
		[]string{key}, mfaAttemptLimit, int64(mfaAttemptWindow.Seconds())).Result()
	if err != nil {
		return fmt.Errorf("MFA attempt storage: %w", err)
	}

	allowed, ok := result.(int64)
	if !ok {
		return errors.New("invalid MFA attempt storage result")
	}

	if allowed != 1 {
		return ErrMFAAttemptLimit
	}

	return nil
}
