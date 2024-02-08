package localcache

import (
	"time"

	"github.com/patrickmn/go-cache"
)

// LocalCache is a cache object with a default expiration duration of 5 minutes
// and a cleanup interval of 10 minutes.
var LocalCache = cache.New(5*time.Minute, 10*time.Minute)
