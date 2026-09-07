package main

import (
	"context"
	"net/netip"
	"slices"
)

// compileOverrideNetworks freezes bounded operator-owned CIDRs independently of learned network aggregation.
func (c *configuration) compileOverrideNetworks() error {
	if len(c.raw.IPOverrideNetworks) > 128 {
		return errConfiguration
	}

	c.overrideNetworks = nil
	seen := map[string]bool{}

	for _, text := range c.raw.IPOverrideNetworks {
		canonical, err := c.canonicalSubject(kindNetwork, text)
		if err != nil || canonical != text || seen[text] {
			return errConfiguration
		}

		seen[text] = true

		prefix, err := netip.ParsePrefix(text)
		if err != nil {
			return errConfiguration
		}

		c.overrideNetworks = append(c.overrideNetworks, prefix)
	}

	slices.SortFunc(c.overrideNetworks, func(a, b netip.Prefix) int {
		if a.Bits() != b.Bits() {
			return b.Bits() - a.Bits()
		}

		return a.Addr().Compare(b.Addr())
	})

	return nil
}

// networkOverride resolves only matching explicit CIDRs, using the most specific active override and no guessed subject.
func (c *configuration) networkOverride(ctx context.Context, address string, read func(context.Context, subjectInput) (string, error)) (string, error) {
	ip, err := netip.ParseAddr(address)
	if err != nil || ip.Zone() != "" {
		return "", errAssessment
	}

	for _, prefix := range c.overrideNetworks {
		if !prefix.Contains(ip) {
			continue
		}

		band, err := read(ctx, subjectInput{kind: kindNetwork, value: prefix.String()})
		if err != nil || !overrideBand(band) {
			return "", errStateUnavailable
		}

		if band != overrideNone {
			return band, nil
		}
	}

	return overrideNone, nil
}

// applyNetworkOverride retains exact-IP override authority and otherwise overlays the selected operator network band only.
func (s *stateOwner) applyNetworkOverride(ctx context.Context, address string, profiles map[string]assessmentTuple) map[string]assessmentTuple {
	if len(s.config.overrideNetworks) == 0 || profiles[profileOperational].Override != overrideNone {
		return profiles
	}

	band, err := s.config.networkOverride(ctx, address, s.readNetworkOverride)
	if err != nil {
		return emptyProfiles(assessmentUnavailable)
	}

	return overlayOverrideBand(profiles, band)
}

// overlayOverrideBand shares the selected network authority between Policy and operator views.
func overlayOverrideBand(profiles map[string]assessmentTuple, band string) map[string]assessmentTuple {
	if band == overrideNone {
		return profiles
	}

	for profile, tuple := range profiles {
		tuple.Override = band
		tuple.Band = band
		profiles[profile] = tuple
	}

	return profiles
}

// readNetworkOverride reuses complete primary and rotation validation while ignoring learned mass of a different subject.
func (s *stateOwner) readNetworkOverride(ctx context.Context, subject subjectInput) (string, error) {
	tuple := s.assessProfiles(ctx, subject)[profileOperational]
	if tuple.State == assessmentUnavailable {
		return "", errStateUnavailable
	}

	return tuple.Override, nil
}
