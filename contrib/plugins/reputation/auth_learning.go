package main

import (
	"context"
	"errors"
	"slices"
	"sort"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

const componentLearnOutcome = "learn_outcome"
const extensionPostAction = "post_action"

var authenticationTarget = pluginapi.DecisionTargetSelector{Namespace: "authn", Action: "authenticate"}
var errBackendUnobserved = errors.New("independent backend outcome not observed")

type authLearningConfig struct {
	SuccessSignal        string `mapstructure:"success_signal"`
	BadCredentialsSignal string `mapstructure:"bad_credentials_signal"`
}

type authenticationLearner struct{ plugin *Plugin }

// Name declares the sole Policy-selected backend learning callback.
func (authenticationLearner) Name() string { return componentLearnOutcome }

// validateAuthLearning confines authentication evidence to exact host callbacks and conservative subjects.
func (c *configuration) validateAuthLearning() error {
	learning := c.raw.AuthLearning
	if learning == nil {
		return nil
	}

	if learning.SuccessSignal == learning.BadCredentialsSignal {
		return errConfiguration
	}

	for name, direction := range map[string]string{learning.SuccessSignal: directionTrust, learning.BadCredentialsSignal: directionRisk} {
		if err := validateLearningSignal(c.signals[name], direction); err != nil {
			return err
		}
	}

	found := false

	for key, source := range c.internalSources {
		if key.component != componentLearnOutcome {
			continue
		}

		if err := c.validateLearningBinding(key, source); err != nil {
			return err
		}

		found = true
	}

	if !found {
		return errConfiguration
	}

	return nil
}

// validateLearningSource verifies every configured root and derivation before startup rather than silently dropping evidence.
func (c *configuration) validateLearningSource(source *sourcePolicy) error {
	for _, name := range []string{c.raw.AuthLearning.SuccessSignal, c.raw.AuthLearning.BadCredentialsSignal} {
		signal := c.signals[name]
		roots := 0

		for role, kinds := range signal.config.SubjectRoles {
			count, err := validateLearningRole(source, role, kinds)
			if err != nil {
				return err
			}

			roots += count
		}

		if roots == 0 || roots > source.config.MaximumSubjects {
			return errConfiguration
		}
	}

	return nil
}

// registerAuthentication exposes only configured learning and retains its exact source identities for startup checks.
func (p *Plugin) registerAuthentication(registrar pluginapi.Registrar, cfg *configuration) error {
	if cfg.raw.AuthLearning == nil {
		return nil
	}

	if err := registrar.RegisterPostActionTarget(authenticationLearner{plugin: p}); err != nil {
		return err
	}

	for key := range cfg.internalSources {
		if key.component == componentLearnOutcome {
			p.registered[key] = struct{}{}
		}
	}

	return nil
}

// authenticationObservation projects immutable backend evidence without reading final flags, credentials or caller facts.
func (c *configuration) authenticationObservation(request pluginapi.PostActionRequest) (*sourcePolicy, observationInput, error) {
	source := c.sourceForExecution(request.ExecutionIdentity())
	if source == nil || c.raw.AuthLearning == nil || request.ExecutionIdentity().Component() != componentLearnOutcome {
		return nil, observationInput{}, errConfiguration
	}

	outcome := request.BackendOutcome
	if !outcome.Observed() || request.Snapshot.HealthCheck {
		return nil, observationInput{}, errBackendUnobserved
	}

	signal := c.raw.AuthLearning.SuccessSignal
	if outcome.Status() == pluginapi.BackendOutcomeBadCredentials {
		signal = c.raw.AuthLearning.BadCredentialsSignal
	}

	input := observationInput{eventID: outcome.EventID(), observedAt: outcome.ObservedAt(), signal: signal}
	for role, kinds := range c.signals[signal].config.SubjectRoles {
		for kind := range kinds {
			subject := subjectInput{role: role, kind: kind}
			switch kind {
			case kindIP:
				subject.value = request.Snapshot.ClientIP
			case kindAccount:
				subject.value = outcome.Account()
			default:
				continue
			}

			input.subjects = append(input.subjects, subject)
		}
	}

	sort.Slice(input.subjects, func(i, j int) bool {
		if input.subjects[i].role == input.subjects[j].role {
			return input.subjects[i].kind < input.subjects[j].kind
		}

		return input.subjects[i].role < input.subjects[j].role
	})

	return source, input, nil
}

// Enqueue persists only selected independent evidence; failure cannot rewrite the already selected authentication result.
func (p authenticationLearner) Enqueue(ctx context.Context, request pluginapi.PostActionRequest) (pluginapi.PostActionEnqueueResult, error) {
	metric := learningRejected
	defer func() { p.plugin.recordLearning(ctx, learningAuthentication, metric) }()

	if p.plugin == nil {
		metric = learningUnavailable
		return pluginapi.PostActionEnqueueResult{Temporary: true}, errStateUnavailable
	}

	p.plugin.mu.RLock()
	state := p.plugin.state
	p.plugin.mu.RUnlock()

	if state == nil || !state.ready.Load() {
		metric = learningUnavailable
		return pluginapi.PostActionEnqueueResult{Temporary: true}, errStateUnavailable
	}

	source, input, err := state.config.authenticationObservation(request)
	if errors.Is(err, errBackendUnobserved) {
		metric = learningSkipped
		return pluginapi.PostActionEnqueueResult{}, nil
	}

	if err != nil {
		return pluginapi.PostActionEnqueueResult{}, err
	}

	admitted, reason, err := state.admitForPolicy(ctx, source, input, nil)
	if err != nil {
		metric = learningUnavailable
		return pluginapi.PostActionEnqueueResult{Temporary: true}, err
	}

	if reason != reasonValid {
		return pluginapi.PostActionEnqueueResult{}, errConfiguration
	}

	result, err := state.ingest(ctx, admitted)

	metric = learningIngestionResult(result, err)
	if err != nil {
		return pluginapi.PostActionEnqueueResult{Temporary: true}, err
	}

	return pluginapi.PostActionEnqueueResult{Enqueued: true}, nil
}

// validateLearningSignal excludes final decisions and account or ASN poisoning from credential evidence.
func validateLearningSignal(signal *signalPolicy, direction string) error {
	if signal == nil || signal.config.Direction != direction || signal.config.EvidenceOrigin != originBackend || signal.config.Magnitude != magnitudeForbidden {
		return errConfiguration
	}

	for _, kinds := range signal.config.SubjectRoles {
		for kind := range kinds {
			if kind != kindIP && kind != kindNetwork && (kind != kindAccount || direction != directionTrust) {
				return errConfiguration
			}
		}
	}

	return nil
}

// validateLearningBinding matches the closed callback family and its complete source grant.
func (c *configuration) validateLearningBinding(key executionKey, source *sourcePolicy) error {
	learning := c.raw.AuthLearning
	if key.extension != extensionPostAction || key.operation != "enqueue" || key.target != authenticationTarget || source.config.ASNProvider != "" ||
		!slices.Contains(source.config.AllowedSignals, learning.SuccessSignal) || !slices.Contains(source.config.AllowedSignals, learning.BadCredentialsSignal) {
		return errConfiguration
	}

	return c.validateLearningSource(source)
}

// validateLearningRole requires each derived network to have an admitted IP root and an explicit weight.
func validateLearningRole(source *sourcePolicy, role string, kinds map[string]float64) (int, error) {
	roots := 0

	for kind := range kinds {
		if kind == kindNetwork {
			if _, exists := kinds[kindIP]; !exists || !slices.Contains(source.config.DerivedSubjects[role], kindNetwork) {
				return 0, errConfiguration
			}

			continue
		}

		if !slices.Contains(source.config.AllowedSubjects[role], kind) {
			return 0, errConfiguration
		}

		roots++
	}

	for _, derived := range source.config.DerivedSubjects[role] {
		if _, exists := kinds[derived]; !exists || derived != kindNetwork {
			return 0, errConfiguration
		}
	}

	return roots, nil
}
