package core

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/decl"
	"github.com/croessner/nauthilus/server/util"
	"github.com/dspinhirne/netaddr-go"
	"github.com/gin-gonic/gin"
)

// IsListed triggers a result of true, if an IP address was found on a RBL list. It also returns a human readable name.
func (a *Authentication) IsListed(ctx *gin.Context, rbl *config.RBL) (rblListStatus bool, rblName string, err error) {
	var (
		results       []net.IP
		reverseIPAddr string
	)

	guid := ctx.Value(decl.GUIDKey).(string)
	ipAddress := net.ParseIP(a.ClientIP)
	if ipAddress.IsLoopback() {
		return false, "", nil
	}

	if strings.Contains(ipAddress.String(), ".") {
		if !rbl.IPv4 {
			return false, "", nil
		}

		tmp := strings.Split(a.ClientIP, ".")
		tmp = []string{tmp[3], tmp[2], tmp[1], tmp[0]}
		reverseIPAddr = strings.Join(tmp, ".")
	} else {
		if !rbl.IPv6 {
			return false, "", nil
		}

		tmp, err := netaddr.ParseIPv6(a.ClientIP) //nolint:govet // Ignore
		if err != nil {
			return false, "", err
		}

		// Long version uncompressed
		ipv6Str := tmp.Long()

		// Remove ':' signs
		ipv6Slice := strings.Split(ipv6Str, ":")
		ipv6Str = strings.Join(ipv6Slice, "")

		// Reverse address
		ipv6Slice = strings.Split(ipv6Str, "")
		for n := 0; n < (len(ipv6Slice) / 2); n++ { //nolint:gomnd // Ignore
			ipv6Slice[n], ipv6Slice[len(ipv6Slice)-n-1] = ipv6Slice[len(ipv6Slice)-n-1], ipv6Slice[n]
		}

		reverseIPAddr = strings.Join(ipv6Slice, ".")
	}

	query := fmt.Sprintf("%s.%s", reverseIPAddr, rbl.RBL)

	rblCtx, cancel := context.WithDeadline(ctx, time.Now().Add(time.Duration(config.EnvConfig.DNSTimeout)*time.Second))
	defer cancel()

	resolver := util.NewDNSResolver()

	results, err = resolver.LookupIP(rblCtx, "ip4", query)
	if err != nil {
		return false, "", err
	}

	for _, result := range results {
		if result.String() == rbl.ReturnCode {
			util.DebugModule(
				decl.DbgRBL,
				decl.LogKeyGUID, guid,
				"query", query, "result", result.String(), "rbl", rbl.Name,
			)

			return true, rbl.Name, nil
		}
	}

	return false, "", nil
}
