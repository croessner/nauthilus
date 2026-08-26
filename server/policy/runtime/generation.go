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

package runtime

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/core/localization"
	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
)

const generationResourceCleanupTimeout = 30 * time.Second

// MessageResolver is the runtime-owned name for immutable response localization authority.
type MessageResolver = localization.MessageResolver

var (
	// ErrGenerationUnavailable identifies capture before initial publication.
	ErrGenerationUnavailable = errors.New("policy runtime generation is unavailable")

	// ErrInvalidGeneration identifies an incomplete off-side generation candidate.
	ErrInvalidGeneration = errors.New("invalid policy runtime generation")

	// ErrGenerationChanged identifies commit against a different active generation.
	ErrGenerationChanged = errors.New("active policy runtime generation changed")

	// ErrCandidateConsumed identifies a candidate already committed or discarded.
	ErrCandidateConsumed = errors.New("policy runtime generation candidate was already consumed")

	// ErrGenerationStoreClosed identifies publication after process shutdown began.
	ErrGenerationStoreClosed = errors.New("policy runtime generation store is closed")

	// ErrGenerationRetirement identifies a resource-close failure retained by the store.
	ErrGenerationRetirement = errors.New("policy runtime generation retirement failed")
)

type generationCommitError struct {
	cause      error
	generation uint64
}

type generationDrainError struct {
	cause error
}

// Error reports that publication completed but predecessor retirement failed.
func (e *generationCommitError) Error() string {
	if e == nil {
		return "<nil>"
	}

	return fmt.Sprintf("runtime generation %d committed with retirement failure: %v", e.generation, e.cause)
}

// Unwrap exposes the retained retirement failure and its stable class.
func (e *generationCommitError) Unwrap() error {
	if e == nil {
		return nil
	}

	return e.cause
}

// GenerationCommitted marks errors raised after the atomic publication point.
func (*generationCommitError) GenerationCommitted() bool {
	return true
}

// newGenerationCommitError preserves committed state without hiding retirement failure.
func newGenerationCommitError(generation uint64, cause error) error {
	return &generationCommitError{
		cause:      fmt.Errorf("%w: %w", ErrGenerationRetirement, cause),
		generation: generation,
	}
}

// Error describes an interrupted generation-drain wait.
func (e *generationDrainError) Error() string {
	if e == nil || e.cause == nil {
		return ErrGenerationRetirement.Error()
	}

	return e.cause.Error()
}

// Unwrap exposes the caller-wait failure and any retirement errors observed so far.
func (e *generationDrainError) Unwrap() error {
	if e == nil {
		return nil
	}

	return e.cause
}

// GenerationDrainIncomplete distinguishes caller wait interruption from completed retirement errors.
func (*generationDrainError) GenerationDrainIncomplete() bool {
	return true
}

// newGenerationDrainError retains the interrupted wait and close errors already observed.
func newGenerationDrainError(cause error) error {
	return &generationDrainError{cause: cause}
}

// CallerAuthenticator creates trusted caller context from opaque credential evidence.
type CallerAuthenticator interface {
	Authenticate(context.Context, decision.AuthenticationInput) (decision.CallerContext, error)
}

// AdmissionAuthority authorizes one authenticated caller and exact request.
type AdmissionAuthority interface {
	Admit(context.Context, decision.CallerContext, decision.DecisionRequest) (AdmissionPermit, error)
}

// AdmissionPermit owns admitted facts and request-scoped limit capacity.
type AdmissionPermit interface {
	Facts() decision.FactSet
	Release()
}

// Application is the generation-bound application authority captured by callers.
type Application interface {
	GenerationID() uint64
}

// CandidateResource is one prepared resource owned until commit or candidate disposal.
type CandidateResource interface {
	Dispose(context.Context) error
}

// PolicyModel is one immutable normalized policy candidate owned by a generation.
type PolicyModel interface {
	ClonePolicyModel() PolicyModel
	ValidatePolicyModel() error
	GenerationID() uint64
}

// DecisionLimits contains immutable per-generation evaluation bounds.
type DecisionLimits struct {
	EvaluationTimeout     time.Duration
	PostActionBudget      time.Duration
	MaxDiagnosticsEntries int
}

// DecisionReportSettings contains immutable internal report bounds and switches.
type DecisionReportSettings struct {
	Enabled    bool
	MaxEntries int
}

// GenerationSettings contains every policy-critical limit and report setting.
type GenerationSettings struct {
	Limits  DecisionLimits
	Reports DecisionReportSettings
}

// PolicyAPIAvailability is the immutable generation-owned transport activation view.
type PolicyAPIAvailability struct {
	MaxRequestBytes int
	Configured      bool
	Enabled         bool
	HTTP            bool
	GRPC            bool
}

// GenerationConfig is the runtime-owned name for one complete captured config snapshot.
type GenerationConfig = config.File

// DecisionServiceMaterial is the immutable config, API, and internal-presentation projection.
type DecisionServiceMaterial struct {
	messageResolver       MessageResolver
	config                GenerationConfig
	internalPresentations map[string]decision.AuthenticationInput
	apiAvailability       PolicyAPIAvailability
}

// NewDecisionServiceMaterial projects mandatory Decision Service state from one candidate.
func NewDecisionServiceMaterial(
	configured GenerationConfig,
	presentations map[string]decision.AuthenticationInput,
	resolver MessageResolver,
) (DecisionServiceMaterial, error) {
	if nilInterface(configured) || nilInterface(resolver) {
		return DecisionServiceMaterial{}, fmt.Errorf(
			"%w: generation config and localization resolver are required",
			ErrInvalidGeneration,
		)
	}

	clonedPresentations := cloneAuthenticationInputs(presentations)
	if len(clonedPresentations) != len(presentations) {
		return DecisionServiceMaterial{}, fmt.Errorf("%w: internal presentation is invalid", ErrInvalidGeneration)
	}

	policyConfig := configured.GetPolicy()
	material := DecisionServiceMaterial{
		messageResolver:       resolver,
		config:                configured,
		internalPresentations: clonedPresentations,
		apiAvailability: PolicyAPIAvailability{
			MaxRequestBytes: policyConfig.API.Limits.MaxRequestBytes,
			Configured:      true,
			Enabled:         policyConfig.API.Enabled,
			HTTP:            policyConfig.API.HTTP.Enabled,
			GRPC:            policyConfig.API.GRPC.Enabled,
		},
	}

	if err := material.Validate(); err != nil {
		return DecisionServiceMaterial{}, err
	}

	return material, nil
}

// Validate rejects missing API authority and malformed code-owned presentations.
func (m DecisionServiceMaterial) Validate() error {
	if nilInterface(m.config) || nilInterface(m.messageResolver) ||
		!m.apiAvailability.Configured || m.apiAvailability.MaxRequestBytes <= 0 {
		return fmt.Errorf("%w: Decision Service config and API metadata are required", ErrInvalidGeneration)
	}

	for id, presentation := range m.internalPresentations {
		if !validProfileID(id) || !validAuthenticationInput(presentation) {
			return fmt.Errorf("%w: invalid internal presentation %q", ErrInvalidGeneration, id)
		}
	}

	return nil
}

// MessageResolver returns the immutable generation-owned localization authority.
func (m DecisionServiceMaterial) MessageResolver() MessageResolver {
	return m.messageResolver
}

// Config returns the exact immutable generation config snapshot.
func (m DecisionServiceMaterial) Config() GenerationConfig {
	return m.config
}

// APIAvailability returns the exact external route activation and request bound.
func (m DecisionServiceMaterial) APIAvailability() PolicyAPIAvailability {
	return m.apiAvailability
}

// InternalPresentations returns detached code-owned authentication inputs.
func (m DecisionServiceMaterial) InternalPresentations() map[string]decision.AuthenticationInput {
	return cloneAuthenticationInputs(m.internalPresentations)
}

// Validate rejects settings that cannot safely bound request-time work.
func (s GenerationSettings) Validate() error {
	if s.Limits.EvaluationTimeout <= 0 || s.Limits.PostActionBudget <= 0 ||
		s.Limits.MaxDiagnosticsEntries <= 0 || s.Reports.MaxEntries <= 0 {
		return fmt.Errorf("%w: runtime limits and report bounds must be positive", ErrInvalidGeneration)
	}

	return nil
}

// CredentialProfiles is immutable caller-authentication profile metadata.
type CredentialProfiles struct {
	ids []string
}

// NewCredentialProfiles validates and owns caller-authentication profile identities.
func NewCredentialProfiles(ids []string) (CredentialProfiles, error) {
	owned, err := normalizedProfileIDs(ids)
	if err != nil {
		return CredentialProfiles{}, fmt.Errorf("credential profiles: %w", err)
	}

	return CredentialProfiles{ids: owned}, nil
}

// IDs returns detached deterministic credential profile identities.
func (p CredentialProfiles) IDs() []string {
	return append([]string(nil), p.ids...)
}

// AdmissionProfiles is immutable caller-admission profile metadata.
type AdmissionProfiles struct {
	ids []string
}

// NewAdmissionProfiles validates and owns caller-admission profile identities.
func NewAdmissionProfiles(ids []string) (AdmissionProfiles, error) {
	owned, err := normalizedProfileIDs(ids)
	if err != nil {
		return AdmissionProfiles{}, fmt.Errorf("admission profiles: %w", err)
	}

	return AdmissionProfiles{ids: owned}, nil
}

// IDs returns detached deterministic admission profile identities.
func (p AdmissionProfiles) IDs() []string {
	return append([]string(nil), p.ids...)
}

// ValidateCredentials requires every credential profile to have one admission profile and vice versa.
func (p AdmissionProfiles) ValidateCredentials(credentials CredentialProfiles) error {
	if !slices.Equal(p.ids, credentials.ids) {
		return fmt.Errorf("%w: credential and admission profile identities differ", ErrInvalidGeneration)
	}

	return nil
}

// Generation is the sole immutable policy-critical server-state publication unit.
type Generation struct {
	config             config.File
	policy             PolicyModel
	catalog            *TargetCatalog
	authenticator      CallerAuthenticator
	admission          AdmissionAuthority
	bindings           *BindingSet
	application        Application
	resourceOwnership  *candidateResourceOwnership
	lifetime           *generationLifetime
	definitions        []registry.DefinitionContribution
	credentialProfiles CredentialProfiles
	admissionProfiles  AdmissionProfiles
	settings           GenerationSettings
	id                 uint64
}

// ID returns the monotonically increasing generation identity.
func (g *Generation) ID() uint64 {
	if g == nil {
		return 0
	}

	return g.id
}

// Config returns the full decoded configuration owned by this generation.
func (g *Generation) Config() config.File {
	if g == nil {
		return nil
	}

	return g.config
}

// Policy returns a detached immutable normalized policy model.
func (g *Generation) Policy() PolicyModel {
	if g == nil {
		return nil
	}

	return g.policy.ClonePolicyModel()
}

// TargetCatalog returns a deeply detached exact target catalog.
func (g *Generation) TargetCatalog() *TargetCatalog {
	if g == nil {
		return nil
	}

	return g.catalog.Clone()
}

// Definitions returns detached namespace-owned definition contributions.
func (g *Generation) Definitions() []registry.DefinitionContribution {
	if g == nil {
		return nil
	}

	return cloneDefinitionContributions(g.definitions)
}

// CallerAuthenticator returns the captured caller-authentication authority.
func (g *Generation) CallerAuthenticator() CallerAuthenticator {
	if g == nil {
		return nil
	}

	return g.authenticator
}

// AdmissionAuthority returns the captured request-admission authority.
func (g *Generation) AdmissionAuthority() AdmissionAuthority {
	if g == nil {
		return nil
	}

	return g.admission
}

// CredentialProfiles returns detached caller credential metadata.
func (g *Generation) CredentialProfiles() CredentialProfiles {
	if g == nil {
		return CredentialProfiles{}
	}

	return CredentialProfiles{ids: g.credentialProfiles.IDs()}
}

// AdmissionProfiles returns detached caller admission metadata.
func (g *Generation) AdmissionProfiles() AdmissionProfiles {
	if g == nil {
		return AdmissionProfiles{}
	}

	return AdmissionProfiles{ids: g.admissionProfiles.IDs()}
}

// Bindings returns detached indexes over the captured prepared binding owners.
func (g *Generation) Bindings() *BindingSet {
	if g == nil {
		return nil
	}

	return g.bindings.Clone()
}

// Settings returns the immutable generation limits and report settings.
func (g *Generation) Settings() GenerationSettings {
	if g == nil {
		return GenerationSettings{}
	}

	return g.settings
}

// Application returns the generation-bound Decision Service authority.
func (g *Generation) Application() Application {
	if g == nil {
		return nil
	}

	return g.application
}

// GenerationStore owns the process-visible atomic generation pointer.
type GenerationStore struct {
	active           atomic.Pointer[Generation]
	generations      map[*Generation]struct{}
	retirementErrs   []error
	shutdownDone     chan struct{}
	mu               sync.Mutex
	shuttingDown     bool
	shutdownComplete bool
}

// NewGenerationStore constructs an empty generation store.
func NewGenerationStore() *GenerationStore {
	return &GenerationStore{
		generations:  make(map[*Generation]struct{}),
		shutdownDone: make(chan struct{}),
	}
}

// Active returns a non-owning diagnostic or preparation view of the current generation.
// Request and session code must use WithActive so retirement cannot invalidate resources.
func (s *GenerationStore) Active() *Generation {
	if s == nil {
		return nil
	}

	return s.active.Load()
}

// RequireActive returns a non-owning current generation or reports missing startup publication.
func (s *GenerationStore) RequireActive() (*Generation, error) {
	active := s.Active()
	if active == nil {
		return nil, ErrGenerationUnavailable
	}

	return active, nil
}

// candidateResourceOwnership releases failed candidate resources in reverse order once.
type candidateResourceOwnership struct {
	resources []CandidateResource
	err       error
	once      sync.Once
}

// add takes candidate ownership of every non-nil returned resource.
func (o *candidateResourceOwnership) add(resources ...CandidateResource) {
	for _, resource := range resources {
		if nilInterface(resource) {
			continue
		}

		o.resources = append(o.resources, resource)
	}
}

// dispose releases all candidate-owned resources exactly once in reverse order.
func (o *candidateResourceOwnership) dispose(ctx context.Context) error {
	if o == nil {
		return nil
	}

	o.once.Do(func() {
		cleanupCtx, cancelCleanup := newGenerationCleanupContext(ctx)
		defer cancelCleanup()

		errs := make([]error, 0, len(o.resources))
		for index := len(o.resources) - 1; index >= 0; index-- {
			if err := o.resources[index].Dispose(cleanupCtx); err != nil {
				errs = append(errs, err)
			}
		}

		o.err = errors.Join(errs...)
	})

	return o.err
}

// normalizedProfileIDs validates, sorts, and owns one profile identity set.
func normalizedProfileIDs(ids []string) ([]string, error) {
	owned := append([]string(nil), ids...)
	sort.Strings(owned)

	for index, id := range owned {
		if !validProfileID(id) {
			return nil, fmt.Errorf("%w: invalid profile identity %q", ErrInvalidGeneration, id)
		}

		if index > 0 && owned[index-1] == id {
			return nil, fmt.Errorf("%w: duplicate profile identity %q", ErrInvalidGeneration, id)
		}
	}

	return owned, nil
}

// validProfileID preserves exact bounded UTF-8 OAuth and internal profile identities.
func validProfileID(id string) bool {
	return id != "" && len(id) <= 512 && strings.TrimSpace(id) == id && utf8.ValidString(id)
}

// cloneAuthenticationInputs validates ownership through the transport-neutral constructor.
func cloneAuthenticationInputs(input map[string]decision.AuthenticationInput) map[string]decision.AuthenticationInput {
	if len(input) == 0 {
		return nil
	}

	result := make(map[string]decision.AuthenticationInput, len(input))
	for id, presentation := range input {
		cloned, err := decision.NewAuthenticationInput(decision.AuthenticationEvidence{
			Kind: presentation.Kind(), Credential: presentation.Credential(),
			TransportKind: presentation.TransportKind(), Listener: presentation.Listener(),
			HTTPRoute: presentation.HTTPRoute(), GRPCMethod: presentation.GRPCMethod(),
			Peer: presentation.Peer(), MTLSIdentity: presentation.MTLSIdentity(),
			Protected: presentation.Protected(),
		})
		if err == nil {
			result[id] = cloned
		}
	}

	return result
}

// validAuthenticationInput verifies one owned presentation has the complete constructor invariant.
func validAuthenticationInput(input decision.AuthenticationInput) bool {
	_, err := decision.NewAuthenticationInput(decision.AuthenticationEvidence{
		Kind: input.Kind(), Credential: input.Credential(), TransportKind: input.TransportKind(),
		Listener: input.Listener(), HTTPRoute: input.HTTPRoute(), GRPCMethod: input.GRPCMethod(),
		Peer: input.Peer(), MTLSIdentity: input.MTLSIdentity(), Protected: input.Protected(),
	})

	return err == nil
}

// cloneDefinitionContributions rebuilds detached immutable contribution DTOs.
func cloneDefinitionContributions(input []registry.DefinitionContribution) []registry.DefinitionContribution {
	result := make([]registry.DefinitionContribution, 0, len(input))
	for _, contribution := range input {
		cloned, err := registry.NewCompleteDefinitionContribution(registry.DefinitionContributionInput{
			Ownership:  contribution.Ownership(),
			Targets:    contribution.Targets(),
			Schemas:    contribution.Schemas(),
			PolicySets: contribution.PolicySets(),
			Plans:      contribution.Plans(),
			Providers:  contribution.Providers(),
			Effects:    contribution.Effects(),
		})
		if err == nil {
			result = append(result, cloned)
		}
	}

	return result
}
