package core

import (
	"github.com/croessner/nauthilus/server/backend"
	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/util"
)

// cachePassDB implements the redis password database backend.
func cachePassDB(auth *Authentication) (passDBResult *PassDBResult, err error) {
	var (
		accountName string
		ppc         *backend.PositivePasswordCache
	)

	// defer UnexpectedCrashHandler(cachePassDB)

	passDBResult = &PassDBResult{}

	cacheNames := backend.GetCacheNames(auth.Protocol.Get(), global.CacheAll)

	for _, cacheName := range cacheNames.GetStringSlice() {
		accountName, err = auth.getUserAccountFromRedis()
		if err != nil {
			return
		}

		if accountName != "" {
			redisPosUserKey := config.EnvConfig.RedisPrefix + "ucp:" + cacheName + ":" + accountName

			err = backend.LoadCacheFromRedis(redisPosUserKey, &ppc)
			if err != nil {
				return
			}
		}

		if ppc != nil {
			if auth.NoAuth || ppc.Password == util.GetHash(util.PreparePassword(auth.Password)) {
				passDBResult.UserFound = true
				passDBResult.AccountField = ppc.AccountField
				passDBResult.TOTPSecretField = ppc.TOTPSecretField
				passDBResult.UniqueUserIDField = ppc.UniqueUserIDField
				passDBResult.DisplayNameField = ppc.DisplayNameField
				passDBResult.Authenticated = true
				passDBResult.Backend = ppc.Backend
				passDBResult.Attributes = ppc.Attributes
			}
		}
	}

	if !passDBResult.Authenticated {
		if key := auth.getBruteForcePasswordHistoryRedisHashKey(true); key != "" {
			auth.loadBruteForcePasswordHistoryFromRedis(key)
		}

		// Prevent password lookups for already known wrong passwords.
		if auth.PasswordHistory != nil {
			passwordHash := util.GetHash(util.PreparePassword(auth.Password))
			if _, foundPassword := (*auth.PasswordHistory)[passwordHash]; foundPassword {
				passDBResult.UserFound = true
			}
		}
	}

	return
}
