// Copyright (C) 2026 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package idp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/crewjam/saml"
)

const defaultSLOReplayTTL = time.Hour

func (h *SAMLHandler) validateInboundLogoutRequestProtocol(ctx context.Context, logoutRequest *saml.LogoutRequest) error {
	if logoutRequest == nil {
		return fmt.Errorf("logout request payload is missing")
	}

	requestID := strings.TrimSpace(logoutRequest.ID)
	if requestID == "" {
		return fmt.Errorf("logout request id is missing")
	}

	issuer := ""
	if logoutRequest.Issuer != nil {
		issuer = strings.TrimSpace(logoutRequest.Issuer.Value)
	}

	if issuer == "" {
		return fmt.Errorf("logout request issuer is missing")
	}

	if err := h.validateLogoutRequestDestination(logoutRequest.Destination); err != nil {
		return err
	}

	now := saml.TimeNow().UTC()

	if logoutRequest.IssueInstant.IsZero() {
		return fmt.Errorf("logout request IssueInstant is missing")
	}

	issueInstant := logoutRequest.IssueInstant.UTC()

	if issueInstant.After(now.Add(saml.MaxClockSkew)) {
		return fmt.Errorf("logout request IssueInstant is in the future")
	}

	if issueInstant.Add(saml.MaxIssueDelay).Before(now) {
		return fmt.Errorf("logout request IssueInstant is too old")
	}

	if logoutRequest.NotOnOrAfter != nil {
		notOnOrAfter := logoutRequest.NotOnOrAfter.UTC()
		if notOnOrAfter.Add(saml.MaxClockSkew).Before(now) {
			return fmt.Errorf("logout request NotOnOrAfter is expired")
		}
	}

	nameID := ""
	if logoutRequest.NameID != nil {
		nameID = strings.TrimSpace(logoutRequest.NameID.Value)
	}

	if nameID == "" {
		return fmt.Errorf("logout request NameID is missing")
	}

	sessionIndex := ""
	if logoutRequest.SessionIndex != nil {
		sessionIndex = strings.TrimSpace(logoutRequest.SessionIndex.Value)
	}

	if err := h.validateLogoutRequestParticipantSession(ctx, nameID, issuer, sessionIndex); err != nil {
		return err
	}

	if err := h.checkAndRememberLogoutRequestID(ctx, issuer, requestID); err != nil {
		return err
	}

	return nil
}

func (h *SAMLHandler) validateInboundLogoutResponseProtocol(logoutResponse *saml.LogoutResponse) error {
	if logoutResponse == nil {
		return fmt.Errorf("logout response payload is missing")
	}

	responseID := strings.TrimSpace(logoutResponse.ID)
	if responseID == "" {
		return fmt.Errorf("logout response id is missing")
	}

	inResponseTo := strings.TrimSpace(logoutResponse.InResponseTo)
	if inResponseTo == "" {
		return fmt.Errorf("logout response InResponseTo is missing")
	}

	issuer := ""
	if logoutResponse.Issuer != nil {
		issuer = strings.TrimSpace(logoutResponse.Issuer.Value)
	}

	if issuer == "" {
		return fmt.Errorf("logout response issuer is missing")
	}

	if err := h.validateLogoutRequestDestination(logoutResponse.Destination); err != nil {
		return err
	}

	now := saml.TimeNow().UTC()

	if logoutResponse.IssueInstant.IsZero() {
		return fmt.Errorf("logout response IssueInstant is missing")
	}

	issueInstant := logoutResponse.IssueInstant.UTC()

	if issueInstant.After(now.Add(saml.MaxClockSkew)) {
		return fmt.Errorf("logout response IssueInstant is in the future")
	}

	if issueInstant.Add(saml.MaxIssueDelay).Before(now) {
		return fmt.Errorf("logout response IssueInstant is too old")
	}

	if strings.TrimSpace(logoutResponse.Status.StatusCode.Value) == "" {
		return fmt.Errorf("logout response StatusCode is missing")
	}

	return nil
}

func (h *SAMLHandler) validateLogoutRequestDestination(destination string) error {
	destination = strings.TrimSpace(destination)
	if destination == "" {
		return fmt.Errorf("logout request destination is missing")
	}

	expected, err := h.expectedLogoutRequestDestination()
	if err != nil {
		return err
	}

	if !sameSLODestination(expected, destination) {
		return fmt.Errorf("logout request destination %q does not match expected endpoint %q", destination, expected)
	}

	return nil
}

func (h *SAMLHandler) expectedLogoutRequestDestination() (string, error) {
	if h == nil || h.deps == nil || h.deps.Cfg == nil {
		return "", fmt.Errorf("SAML handler configuration is not available")
	}

	samlCfg := h.deps.Cfg.GetIdP().SAML2

	entityID := strings.TrimSpace(samlCfg.EntityID)
	if entityID != "" {
		entityURL, err := url.Parse(entityID)
		if err == nil && entityURL.Scheme != "" && entityURL.Host != "" {
			entityURL.Path = "/saml/slo"
			entityURL.RawQuery = ""
			entityURL.Fragment = ""

			return entityURL.String(), nil
		}
	}

	issuer := strings.TrimSpace(h.deps.Cfg.GetIdP().OIDC.Issuer)
	if issuer == "" {
		return "", fmt.Errorf("idp issuer is not configured")
	}

	issuerURL, err := url.Parse(issuer)
	if err != nil || issuerURL.Scheme == "" || issuerURL.Host == "" {
		return "", fmt.Errorf("idp issuer %q is not a valid absolute URL", issuer)
	}

	basePath := strings.TrimSuffix(issuerURL.Path, "/")
	issuerURL.Path = basePath + "/saml/slo"
	issuerURL.RawQuery = ""
	issuerURL.Fragment = ""

	return issuerURL.String(), nil
}

func sameSLODestination(expected, actual string) bool {
	expectedURL, err := normalizeSLODestination(expected)
	if err != nil {
		return false
	}

	actualURL, err := normalizeSLODestination(actual)
	if err != nil {
		return false
	}

	return strings.EqualFold(expectedURL.Scheme, actualURL.Scheme) &&
		strings.EqualFold(expectedURL.Host, actualURL.Host) &&
		normalizedSLOPath(expectedURL.Path) == normalizedSLOPath(actualURL.Path) &&
		expectedURL.RawQuery == actualURL.RawQuery
}

func normalizeSLODestination(rawURL string) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return nil, err
	}

	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("destination must be an absolute URL")
	}

	parsed.Fragment = ""

	return parsed, nil
}

func normalizedSLOPath(path string) string {
	cleaned := strings.TrimRight(path, "/")
	if cleaned == "" {
		return "/"
	}

	return cleaned
}

func (h *SAMLHandler) validateLogoutRequestParticipantSession(ctx context.Context, nameID, issuer, sessionIndex string) error {
	registry := h.sloSessionRegistry()
	if registry == nil {
		return fmt.Errorf("slo session registry is not available")
	}

	sessions, err := registry.LookupParticipants(ctx, nameID)
	if err != nil {
		return fmt.Errorf("cannot lookup SLO participant sessions: %w", err)
	}

	if len(sessions) == 0 {
		return fmt.Errorf("no active SLO participant session for NameID %q", nameID)
	}

	for _, session := range sessions {
		if session.SPEntityID != issuer {
			continue
		}

		if session.NameID != "" && session.NameID != nameID {
			continue
		}

		if sessionIndex != "" && session.SessionIndex != sessionIndex {
			continue
		}

		return nil
	}

	if sessionIndex != "" {
		return fmt.Errorf(
			"no active SLO participant session for issuer %q and session index %q",
			issuer,
			sessionIndex,
		)
	}

	return fmt.Errorf("no active SLO participant session for issuer %q", issuer)
}

func (h *SAMLHandler) checkAndRememberLogoutRequestID(ctx context.Context, issuer, requestID string) error {
	if h == nil || h.deps == nil || h.deps.Redis == nil {
		return fmt.Errorf("slo replay protection is not available")
	}

	handle := h.deps.Redis.GetWriteHandle()
	if handle == nil {
		return fmt.Errorf("slo replay protection is not available")
	}

	stored, err := handle.SetNX(ctx, h.sloReplayRequestKey(issuer, requestID), "1", h.sloReplayTTL()).Result()
	if err != nil {
		return fmt.Errorf("cannot store logout request replay state: %w", err)
	}

	if !stored {
		return fmt.Errorf("logout request replay detected for id %q", requestID)
	}

	return nil
}

func (h *SAMLHandler) sloReplayTTL() time.Duration {
	if h == nil || h.deps == nil || h.deps.Cfg == nil {
		return defaultSLOReplayTTL
	}

	ttl := h.deps.Cfg.GetIdP().SAML2.GetDefaultExpireTime()
	if ttl <= 0 {
		return defaultSLOReplayTTL
	}

	return ttl
}

func (h *SAMLHandler) sloReplayRequestKey(issuer, requestID string) string {
	redisPrefix := ""
	if h != nil && h.deps != nil && h.deps.Cfg != nil {
		redisPrefix = h.deps.Cfg.GetServer().GetRedis().GetPrefix()
	}

	replayScope := strings.TrimSpace(issuer) + "\x1f" + strings.TrimSpace(requestID)
	sum := sha256.Sum256([]byte(replayScope))

	return redisPrefix + "idp:saml:slo:replay:" + hex.EncodeToString(sum[:])
}
