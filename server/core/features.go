package core

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/decl"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/logging"
	"github.com/croessner/nauthilus/server/lualib/feature"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
	"github.com/go-kit/log/level"
)

// FeatureGeoIP logs some geographical information.
func (a *Authentication) FeatureGeoIP() {
	if !(a.ClientIP == decl.Localhost4 || a.ClientIP == decl.Localhost6 || a.ClientIP == "") {
		a.GeoIPCity.GetGeoIPCity(net.ParseIP(a.ClientIP), *a.GUID)
	} else {
		level.Info(logging.DefaultLogger).Log(decl.LogKeyGUID, a.GUID, decl.FeatureGeoIP, "localhost")
		a.GeoIPCity.Country.Names = make(map[string]string)
		a.GeoIPCity.City.Names = make(map[string]string)
	}

	level.Info(logging.DefaultLogger).Log(a.logLineGeoIP()...)
}

// FeatureLua runs Lua scripts and returns a trigger result.
func (a *Authentication) FeatureLua(ctx *gin.Context) (triggered bool, abortFeatures bool, err error) {
	if !(a.ClientIP == decl.Localhost4 || a.ClientIP == decl.Localhost6 || a.ClientIP == "") {
		l := feature.Request{
			Debug:               config.EnvConfig.Verbosity.Level() == decl.LogLevelDebug,
			Session:             *a.GUID,
			ClientIP:            a.ClientIP,
			ClientPort:          a.XClientPort,
			Username:            a.UsernameOrig,
			Password:            a.Password,
			Protocol:            a.Protocol.String(),
			ClientID:            a.XClientID,
			LocalIP:             a.XLocalIP,
			LocalPort:           a.XPort,
			UserAgent:           *a.UserAgent,
			XSSL:                a.XSSL,
			XSSLSessionID:       a.XSSLSessionID,
			XSSLClientVerify:    a.XSSLClientVerify,
			XSSLClientDN:        a.XSSLClientDN,
			XSSLClientCN:        a.XSSLClientCN,
			XSSLIssuer:          a.XSSLIssuer,
			XSSLClientNotBefore: a.XSSLClientNotBefore,
			XSSLClientNotAfter:  a.XSSLClientNotAfter,
			XSSLSubjectDN:       a.XSSLSubjectDN,
			XSSLIssuerDN:        a.XSSLIssuerDN,
			XSSLClientSubjectDN: a.XSSLClientSubjectDN,
			XSSLClientIssuerDN:  a.XSSLClientIssuerDN,
			XSSLProtocol:        a.XSSLProtocol,
			XSSLCipher:          a.XSSLCipher,
			Context:             a.Context,
		}

		triggered, abortFeatures, err = l.CallFeatureLua(ctx)

		for index := range *l.Logs {
			a.AdditionalLogs = append(a.AdditionalLogs, (*l.Logs)[index])
		}

		return
	} else {
		level.Info(logging.DefaultLogger).Log(decl.LogKeyGUID, a.GUID, decl.FeatureLua, "localhost")
	}

	return
}

// FeatureTLSEncryption checks, if the remote client connection was secured.
func (a *Authentication) FeatureTLSEncryption() (triggered bool) {
	if !(a.ClientIP == decl.Localhost4 || a.ClientIP == decl.Localhost6 || a.ClientIP == "") {
		if a.XSSL == decl.NotAvailable {
			matchIP := a.IsInNetwork(config.LoadableConfig.ClearTextList)
			if !matchIP {
				level.Info(logging.DefaultLogger).Log(
					decl.LogKeyGUID, a.GUID,
					decl.FeatureTLSEncryption, "Client has no transport security",
					decl.LogKeyClientIP, a.ClientIP,
				)

				triggered = true

				return
			}

			level.Info(logging.DefaultLogger).Log(
				decl.LogKeyGUID, a.GUID,
				decl.FeatureTLSEncryption, "Client is whitelisted",
				decl.LogKeyClientIP, a.ClientIP)
		}
	} else {
		level.Info(logging.DefaultLogger).Log(decl.LogKeyGUID, a.GUID, decl.FeatureTLSEncryption, "localhost")
	}

	return
}

// FeatureRelayDomains triggers if a user sent an email address as a login name and the domain component does not
// match the list of known domains.
func (a *Authentication) FeatureRelayDomains() (triggered bool) {
	if config.LoadableConfig.RelayDomains == nil {
		return
	}

	if !(a.ClientIP == decl.Localhost4 || a.ClientIP == decl.Localhost6 || a.ClientIP == "") {
		if len(config.LoadableConfig.RelayDomains.StaticDomains) > 0 {
			if strings.Contains(a.Username, "@") {
				split := strings.Split(a.Username, "@")
				//nolint:gomnd // Username may be an email address, which has two parts
				if len(split) != 2 {
					return
				}

				for _, domain := range config.LoadableConfig.RelayDomains.StaticDomains {
					if strings.EqualFold(domain, split[1]) {
						return
					}
				}

				level.Info(logging.DefaultLogger).Log(decl.LogKeyGUID, a.GUID, decl.FeatureRelayDomains, fmt.Sprintf("%s not our domain", split[1]))

				triggered = true
			}
		}
	} else {
		level.Info(logging.DefaultLogger).Log(decl.LogKeyGUID, a.GUID, decl.FeatureRelayDomains, "localhost")
	}

	return
}

// FeatureRBLs checks the remote client IP address against a list of realtime block lists.
//
//nolint:gocognit // Ignore
func (a *Authentication) FeatureRBLs(ctx *gin.Context) (triggered bool, err error) {
	var (
		rblScore      int
		totalRBLScore int
	)

	if config.LoadableConfig.RBLs == nil {
		return
	}

	if !(a.ClientIP == decl.Localhost4 || a.ClientIP == decl.Localhost6 || a.ClientIP == "") {
		matchIP := a.IsInNetwork(config.LoadableConfig.RBLs.IPWhiteList)
		if !matchIP {
			var (
				waitGroup      sync.WaitGroup
				dnsResolverErr atomic.Bool
			)

			numberOfRBLs := len(config.LoadableConfig.RBLs.Lists)
			rblChan := make(chan int)

			dnsResolverErr.Store(false)

			for _, rbl := range config.LoadableConfig.RBLs.Lists {
				waitGroup.Add(1)

				go func(rbl config.RBL, rblChan chan int) {
					isListed, rblName, errRBL := a.IsListed(ctx, &rbl)

					waitGroup.Done()

					if errRBL != nil {
						if strings.HasSuffix(errRBL.Error(), "no such host") {
							util.DebugModule(
								decl.DbgRBL, decl.LogKeyGUID, a.GUID, decl.LogKeyMsg, errRBL)
						} else {
							if !rbl.AllowFailure {
								dnsResolverErr.Store(true)
							}

							level.Error(logging.DefaultErrLogger).Log(decl.LogKeyGUID, a.GUID, decl.LogKeyError, errRBL)
						}

						rblChan <- 0

						return
					}

					if isListed {
						level.Info(logging.DefaultLogger).Log(
							decl.LogKeyGUID, a.GUID,
							decl.FeatureRBL, "RBL matched",
							decl.LogKeyClientIP, a.ClientIP,
							"rbl_name", rblName,
							"weight", rbl.Weight,
						)

						rblChan <- rbl.Weight

						return
					}

					// Given list not responsible for IP address family
					rblChan <- 0
				}(rbl, rblChan)
			}

			waitGroup.Wait()

			// Some required RBL list failed due to a timeout
			if dnsResolverErr.Load() {
				err = errors.ErrDNSResolver

				return
			}

			for rblScore = range rblChan {
				totalRBLScore += rblScore

				numberOfRBLs--

				if numberOfRBLs == 0 {
					break
				}
			}
		} else {
			level.Info(logging.DefaultLogger).Log(
				decl.LogKeyGUID, a.GUID, decl.FeatureRBL, "Client is whitelisted", decl.LogKeyClientIP, a.ClientIP,
			)
		}
	} else {
		level.Info(logging.DefaultLogger).Log(decl.LogKeyGUID, a.GUID, decl.FeatureRBL, "localhost")
	}

	if totalRBLScore >= config.LoadableConfig.RBLs.Threshold {
		triggered = true
	}

	return
}
