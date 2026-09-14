package pluginregistry

import (
	"testing"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
	"github.com/croessner/nauthilus/v4/server/config"
)

type boundedRegistrationTarget struct {
	fakePostActionTarget
	limits pluginapi.CallbackAdmissionLimits
}

// AdmissionLimits exposes mutable fixture state to verify detached registration ownership.
func (p *boundedRegistrationTarget) AdmissionLimits() (int, int) {
	return p.limits.RequestsPerSecond, p.limits.MaxConcurrency
}

// TestPostActionAdmissionRegistrationRejectsInvalidLimits protects optional bounds without weakening unbounded legacy components.
func TestPostActionAdmissionRegistrationRejectsInvalidLimits(t *testing.T) {
	for _, limits := range []pluginapi.CallbackAdmissionLimits{
		{}, {RequestsPerSecond: 1}, {MaxConcurrency: 1}, {RequestsPerSecond: -1, MaxConcurrency: 1},
		{RequestsPerSecond: 10001, MaxConcurrency: 1}, {RequestsPerSecond: 1, MaxConcurrency: 1025},
	} {
		registrar := NewRegistry().NewRegistrar(config.PluginModule{Name: "example"})

		target := &boundedRegistrationTarget{fakePostActionTarget: fakePostActionTarget{name: "limited"}, limits: limits}
		if err := registrar.RegisterPostActionTarget(target); err == nil {
			t.Fatal("invalid explicit admission limits accepted")
		}
	}
}

// TestPostActionAdmissionRegistrationFreezesLimits ensures plugin changes cannot expand a registered host budget.
func TestPostActionAdmissionRegistrationFreezesLimits(t *testing.T) {
	limits := pluginapi.CallbackAdmissionLimits{RequestsPerSecond: 1, MaxConcurrency: 1}
	registrar := NewRegistry().NewRegistrar(config.PluginModule{Name: "example"})

	target := &boundedRegistrationTarget{fakePostActionTarget: fakePostActionTarget{name: "limited"}, limits: limits}
	if err := registrar.RegisterPostActionTarget(target); err != nil {
		t.Fatal(err)
	}

	target.limits = pluginapi.CallbackAdmissionLimits{RequestsPerSecond: 10000, MaxConcurrency: 1024}

	components := registrar.Components()
	if components[0].CallbackAdmissionLimits != limits {
		t.Fatal("registration borrowed mutable plugin limits")
	}

	components[0].CallbackAdmissionLimits = target.limits
	if registrar.Components()[0].CallbackAdmissionLimits != limits {
		t.Fatal("registration leaked mutable limit metadata")
	}
}

// TestObligationAdmissionRegistrationUsesSharedBounds prevents synchronous callbacks from bypassing source limits.
func TestObligationAdmissionRegistrationUsesSharedBounds(t *testing.T) {
	for _, limits := range []pluginapi.CallbackAdmissionLimits{{}, {RequestsPerSecond: 1, MaxConcurrency: 1}} {
		registrar := NewRegistry().NewRegistrar(config.PluginModule{Name: "example"})
		target := &boundedObligationRegistrationTarget{fakeObligationTarget: fakeObligationTarget{name: "limited"}, limits: limits}

		err := registrar.RegisterObligationTarget(target)
		if limits.MaxConcurrency == 0 {
			if err == nil {
				t.Fatal("invalid synchronous bounds accepted")
			}

			continue
		}

		if err != nil {
			t.Fatal(err)
		}

		target.limits.MaxConcurrency = 100
		if registrar.Components()[0].CallbackAdmissionLimits != limits {
			t.Fatal("synchronous bounds were not frozen")
		}
	}
}

type boundedObligationRegistrationTarget struct {
	fakeObligationTarget
	limits pluginapi.CallbackAdmissionLimits
}

// AdmissionLimits returns mutable fixture bounds to test registration ownership.
func (p *boundedObligationRegistrationTarget) AdmissionLimits() (int, int) {
	return p.limits.RequestsPerSecond, p.limits.MaxConcurrency
}
