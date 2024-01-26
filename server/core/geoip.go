package core

import (
	"fmt"
	"net"

	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/logging"
	"github.com/go-kit/log/level"
	"github.com/oschwald/maxminddb-golang"
)

var (
	GeoIPReader *GeoIP //nolint:gochecknoglobals // System wide GeoIP handler
)

type GeoIP struct {
	Reader *maxminddb.Reader
}

// GeoIPCity is a MaxMind city DB structure and used if the feature "geoip" is enabled.
type GeoIPCity struct {
	City struct {
		GeoNameID uint              `maxminddb:"geoname_id"`
		Names     map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Country struct {
		GeoNameID         uint              `maxminddb:"geoname_id"`
		IsInEuropeanUnion bool              `maxminddb:"is_in_european_union"`
		IsoCode           string            `maxminddb:"iso_code"`
		Names             map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	Location struct {
		AccuracyRadius uint16  `maxminddb:"accuracy_radius"`
		Latitude       float64 `maxminddb:"latitude"`
		Longitude      float64 `maxminddb:"longitude"`
		MetroCode      uint    `maxminddb:"metro_code"`
		TimeZone       string  `maxminddb:"time_zone"`
	} `maxminddb:"location"`
}

// GetGeoIPCity does an IP address lookup and returns the GeoIPCity object.
//
//goland:noinspection GoUnhandledErrorResult
func (g *GeoIPCity) GetGeoIPCity(ipAddress net.IP, guid string) *GeoIPCity {
	var err error

	if GeoIPReader == nil || ipAddress == nil {
		return g
	}

	err = GeoIPReader.Reader.Lookup(ipAddress, g)
	if err != nil {
		level.Error(logging.DefaultErrLogger).Log(global.LogKeyGUID, guid, global.LogKeyError, err)
	} else {
		level.Debug(logging.DefaultLogger).Log(global.LogKeyGUID, guid, "ip", ipAddress, "geoip", fmt.Sprintf("%+v", *g))
	}

	return g
}
