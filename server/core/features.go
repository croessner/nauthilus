package core

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/croessner/nauthilus/server/config"
	"github.com/croessner/nauthilus/server/errors"
	"github.com/croessner/nauthilus/server/global"
	"github.com/croessner/nauthilus/server/logging"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/feature"
	"github.com/croessner/nauthilus/server/stats"
	"github.com/croessner/nauthilus/server/util"
	"github.com/gin-gonic/gin"
	"github.com/go-kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
)

// featureLua runs Lua scripts and returns a trigger result.
func (a *Authentication) featureLua(ctx *gin.Context) (triggered bool, abortFeatures bool, err error) {
	timer := prometheus.NewTimer(stats.FunctionDuration.WithLabelValues("Feature", global.FeatureLua))

	defer timer.ObserveDuration()

	if !(a.ClientIP == global.Localhost4 || a.ClientIP == global.Localhost6 || a.ClientIP == "") {
		featureRequest := feature.Request{
			Context: a.Context,
			CommonRequest: &lualib.CommonRequest{
				Debug:               config.LoadableConfig.Server.Log.Level.Level() == global.LogLevelDebug,
				Repeating:           false, // unavailable
				UserFound:           false, // unavailable
				Authenticated:       false, // unavailable
				NoAuth:              a.NoAuth,
				BruteForceCounter:   0, // unavailable
				Service:             a.Service,
				Session:             *a.GUID,
				ClientIP:            a.ClientIP,
				ClientPort:          a.XClientPort,
				ClientNet:           "", // unavailable
				ClientHost:          a.ClientHost,
				ClientID:            a.XClientID,
				UserAgent:           *a.UserAgent,
				LocalIP:             a.XLocalIP,
				LocalPort:           a.XPort,
				Username:            a.UsernameOrig,
				Account:             "", // unavailable
				UniqueUserID:        "", // unavailable
				DisplayName:         "", // unavailable
				Password:            a.Password,
				Protocol:            a.Protocol.String(),
				BruteForceName:      "", // unavailable
				FeatureName:         "", // unavailable
				StatusMessage:       &a.StatusMessage,
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
			},
		}

		triggered, abortFeatures, err = featureRequest.CallFeatureLua(ctx)

		for index := range *featureRequest.Logs {
			a.AdditionalLogs = append(a.AdditionalLogs, (*featureRequest.Logs)[index])
		}

		if statusMessage := featureRequest.StatusMessage; *statusMessage != a.StatusMessage {
			a.StatusMessage = *statusMessage
		}

		return
	} else {
		level.Info(logging.DefaultLogger).Log(global.LogKeyGUID, a.GUID, global.FeatureLua, "localhost")
	}

	return
}

// featureTLSEncryption checks, if the remote client connection was secured.
func (a *Authentication) featureTLSEncryption() (triggered bool) {
	timer := prometheus.NewTimer(stats.FunctionDuration.WithLabelValues("Feature", global.FeatureTLSEncryption))

	defer timer.ObserveDuration()

	if !(a.ClientIP == global.Localhost4 || a.ClientIP == global.Localhost6 || a.ClientIP == "") {
		if a.XSSL == global.NotAvailable {
			matchIP := a.isInNetwork(config.LoadableConfig.ClearTextList)
			if !matchIP {
				level.Info(logging.DefaultLogger).Log(
					global.LogKeyGUID, a.GUID,
					global.FeatureTLSEncryption, "Client has no transport security",
					global.LogKeyClientIP, a.ClientIP,
				)

				triggered = true

				return
			}

			level.Info(logging.DefaultLogger).Log(
				global.LogKeyGUID, a.GUID,
				global.FeatureTLSEncryption, "Client is whitelisted",
				global.LogKeyClientIP, a.ClientIP)
		}
	} else {
		level.Info(logging.DefaultLogger).Log(global.LogKeyGUID, a.GUID, global.FeatureTLSEncryption, "localhost")
	}

	return
}

// featureRelayDomains triggers if a user sent an email address as a login name and the domain component does not
// match the list of known domains.
func (a *Authentication) featureRelayDomains() (triggered bool) {
	timer := prometheus.NewTimer(stats.FunctionDuration.WithLabelValues("Feature", global.FeatureRelayDomains))

	defer timer.ObserveDuration()

	if config.LoadableConfig.RelayDomains == nil {
		return
	}

	if !(a.ClientIP == global.Localhost4 || a.ClientIP == global.Localhost6 || a.ClientIP == "") {
		if len(config.LoadableConfig.RelayDomains.StaticDomains) > 0 {
			username := handleMasterUserMode(a)

			if strings.Contains(username, "@") {
				split := strings.Split(username, "@")
				//nolint:gomnd // Username may be an email address, which has two parts
				if len(split) != 2 {
					return
				}

				for _, domain := range config.LoadableConfig.RelayDomains.StaticDomains {
					if strings.EqualFold(domain, split[1]) {
						return
					}
				}

				level.Info(logging.DefaultLogger).Log(global.LogKeyGUID, a.GUID, global.FeatureRelayDomains, fmt.Sprintf("%s not our domain", split[1]))

				triggered = true
			}
		}
	} else {
		level.Info(logging.DefaultLogger).Log(global.LogKeyGUID, a.GUID, global.FeatureRelayDomains, "localhost")
	}

	return
}

// featureRBLs checks the remote client IP address against a list of realtime block lists.
//
//nolint:gocognit // Ignore
func (a *Authentication) featureRBLs(ctx *gin.Context) (triggered bool, err error) {
	var (
		rblScore      int
		totalRBLScore int
	)

	timer := prometheus.NewTimer(stats.FunctionDuration.WithLabelValues("Feature", global.FeatureRBL))

	defer timer.ObserveDuration()

	if config.LoadableConfig.RBLs == nil {
		return
	}

	if !(a.ClientIP == global.Localhost4 || a.ClientIP == global.Localhost6 || a.ClientIP == "") {
		matchIP := a.isInNetwork(config.LoadableConfig.RBLs.IPWhiteList)
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
					isListed, rblName, errRBL := a.isListed(ctx, &rbl)

					waitGroup.Done()

					if errRBL != nil {
						if strings.HasSuffix(errRBL.Error(), "no such host") {
							util.DebugModule(
								global.DbgRBL, global.LogKeyGUID, a.GUID, global.LogKeyMsg, errRBL)
						} else {
							if !rbl.AllowFailure {
								dnsResolverErr.Store(true)
							}

							level.Error(logging.DefaultErrLogger).Log(global.LogKeyGUID, a.GUID, global.LogKeyError, errRBL)
						}

						rblChan <- 0

						return
					}

					if isListed {
						level.Info(logging.DefaultLogger).Log(
							global.LogKeyGUID, a.GUID,
							global.FeatureRBL, "RBL matched",
							global.LogKeyClientIP, a.ClientIP,
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
				global.LogKeyGUID, a.GUID, global.FeatureRBL, "Client is whitelisted", global.LogKeyClientIP, a.ClientIP,
			)
		}
	} else {
		level.Info(logging.DefaultLogger).Log(global.LogKeyGUID, a.GUID, global.FeatureRBL, "localhost")
	}

	if totalRBLScore >= config.LoadableConfig.RBLs.Threshold {
		triggered = true
	}

	return
}
