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
	"log/slog"
	"sync/atomic"

	"github.com/croessner/nauthilus/v3/server/config"
	"github.com/croessner/nauthilus/v3/server/policy/registry"
)

const (
	candidateStatePrepared uint32 = iota
	candidateStateValidating
	candidateStateValidated
	candidateStateCommitting
	candidateStateCommitted
	candidateStateDiscarded
)

// PrepareInput identifies one complete decoded configuration candidate.
type PrepareInput struct {
	Config config.File
	ID     uint64
}

// PreparationInput is the shared immutable input for independent preparation slots.
type PreparationInput struct {
	config   config.File
	previous config.File
	id       uint64
}

// Config returns the complete decoded candidate configuration.
func (i PreparationInput) Config() config.File {
	return i.config
}

// ID returns the candidate generation identity.
func (i PreparationInput) ID() uint64 {
	return i.id
}

// PreviousConfig returns the active full config captured before preparation, when present.
func (i PreparationInput) PreviousConfig() config.File {
	return i.previous
}

// PolicyPreparation contains one exact off-side policy view and its resources.
type PolicyPreparation struct {
	Snapshot  *Snapshot
	Resources []CandidateResource
}

// ExtensionPreparation contains immutable definitions, bindings, and their resources.
type ExtensionPreparation struct {
	Bindings    *BindingSet
	Definitions []registry.DefinitionContribution
	Resources   []CandidateResource
}

// CatalogPreparationInput contains definitions required to compile exact targets.
type CatalogPreparationInput struct {
	base        PreparationInput
	definitions []registry.DefinitionContribution
}

// Config returns the complete decoded candidate configuration.
func (i CatalogPreparationInput) Config() config.File {
	return i.base.Config()
}

// ID returns the candidate generation identity.
func (i CatalogPreparationInput) ID() uint64 {
	return i.base.ID()
}

// Definitions returns detached namespace-owned contributions.
func (i CatalogPreparationInput) Definitions() []registry.DefinitionContribution {
	return cloneDefinitionContributions(i.definitions)
}

// CatalogPreparation contains one compiled exact target catalog and its resources.
type CatalogPreparation struct {
	Catalog   *TargetCatalog
	Resources []CandidateResource
}

// AuthorityPreparationInput contains the complete candidate views needed by caller auth.
type AuthorityPreparationInput struct {
	base     PreparationInput
	catalog  *TargetCatalog
	bindings *BindingSet
}

// Config returns the complete decoded candidate configuration.
func (i AuthorityPreparationInput) Config() config.File {
	return i.base.Config()
}

// ID returns the candidate generation identity.
func (i AuthorityPreparationInput) ID() uint64 {
	return i.base.ID()
}

// TargetCatalog returns a detached exact candidate catalog.
func (i AuthorityPreparationInput) TargetCatalog() *TargetCatalog {
	return i.catalog.Clone()
}

// Bindings returns detached indexes over prepared candidate bindings.
func (i AuthorityPreparationInput) Bindings() *BindingSet {
	return i.bindings.Clone()
}

// CallerAuthenticationPreparation contains caller credential authority and metadata.
type CallerAuthenticationPreparation struct {
	Authenticator CallerAuthenticator
	Credentials   CredentialProfiles
	Resources     []CandidateResource
}

// AdmissionPreparationInput contains candidate caller and target authority metadata.
type AdmissionPreparationInput struct {
	base        PreparationInput
	catalog     *TargetCatalog
	credentials CredentialProfiles
}

// Config returns the complete decoded candidate configuration.
func (i AdmissionPreparationInput) Config() config.File {
	return i.base.Config()
}

// ID returns the candidate generation identity.
func (i AdmissionPreparationInput) ID() uint64 {
	return i.base.ID()
}

// TargetCatalog returns a detached exact candidate catalog.
func (i AdmissionPreparationInput) TargetCatalog() *TargetCatalog {
	return i.catalog.Clone()
}

// CredentialProfiles returns detached caller credential metadata.
func (i AdmissionPreparationInput) CredentialProfiles() CredentialProfiles {
	return CredentialProfiles{ids: i.credentials.IDs()}
}

// AdmissionPreparation contains caller admission authority and immutable profiles.
type AdmissionPreparation struct {
	Authority AdmissionAuthority
	Profiles  AdmissionProfiles
	Resources []CandidateResource
}

// SettingsPreparationInput contains every candidate view needed to derive limits.
type SettingsPreparationInput struct {
	base    PreparationInput
	policy  *Snapshot
	catalog *TargetCatalog
}

// Config returns the complete decoded candidate configuration.
func (i SettingsPreparationInput) Config() config.File {
	return i.base.Config()
}

// ID returns the candidate generation identity.
func (i SettingsPreparationInput) ID() uint64 {
	return i.base.ID()
}

// PolicySnapshot returns a detached exact candidate policy view.
func (i SettingsPreparationInput) PolicySnapshot() *Snapshot {
	return i.policy.Clone()
}

// TargetCatalog returns a detached exact candidate catalog.
func (i SettingsPreparationInput) TargetCatalog() *TargetCatalog {
	return i.catalog.Clone()
}

// SettingsPreparation contains immutable limits, report settings, and resources.
type SettingsPreparation struct {
	Settings  GenerationSettings
	Resources []CandidateResource
}

// ApplicationPreparationInput contains every prepared candidate application dependency.
type ApplicationPreparationInput struct {
	config        config.File
	policy        *Snapshot
	catalog       *TargetCatalog
	authenticator CallerAuthenticator
	admission     AdmissionAuthority
	bindings      *BindingSet
	settings      GenerationSettings
	id            uint64
}

// Config returns the complete decoded candidate configuration.
func (i ApplicationPreparationInput) Config() config.File {
	return i.config
}

// ID returns the candidate generation identity.
func (i ApplicationPreparationInput) ID() uint64 {
	return i.id
}

// PolicySnapshot returns a detached exact candidate policy view.
func (i ApplicationPreparationInput) PolicySnapshot() *Snapshot {
	return i.policy.Clone()
}

// TargetCatalog returns a detached exact candidate catalog.
func (i ApplicationPreparationInput) TargetCatalog() *TargetCatalog {
	return i.catalog.Clone()
}

// CallerAuthenticator returns the prepared caller-authentication authority.
func (i ApplicationPreparationInput) CallerAuthenticator() CallerAuthenticator {
	return i.authenticator
}

// AdmissionAuthority returns the prepared caller-admission authority.
func (i ApplicationPreparationInput) AdmissionAuthority() AdmissionAuthority {
	return i.admission
}

// Bindings returns detached indexes over prepared candidate bindings.
func (i ApplicationPreparationInput) Bindings() *BindingSet {
	return i.bindings.Clone()
}

// Settings returns the prepared immutable limits and report settings.
func (i ApplicationPreparationInput) Settings() GenerationSettings {
	return i.settings
}

// ApplicationPreparation contains the final generation-bound application authority.
type ApplicationPreparation struct {
	Application Application
	Resources   []CandidateResource
}

// PolicyPreparationSlot prepares the exact policy configuration view off-side.
type PolicyPreparationSlot interface {
	Prepare(context.Context, PreparationInput) (PolicyPreparation, error)
}

// ExtensionPreparationSlot prepares definitions and immutable extension bindings off-side.
type ExtensionPreparationSlot interface {
	Prepare(context.Context, PreparationInput) (ExtensionPreparation, error)
}

// CatalogPreparationSlot compiles the exact target catalog off-side.
type CatalogPreparationSlot interface {
	Prepare(context.Context, CatalogPreparationInput) (CatalogPreparation, error)
}

// CallerAuthenticationPreparationSlot prepares caller credential authority off-side.
type CallerAuthenticationPreparationSlot interface {
	Prepare(context.Context, AuthorityPreparationInput) (CallerAuthenticationPreparation, error)
}

// AdmissionPreparationSlot prepares caller admission authority off-side.
type AdmissionPreparationSlot interface {
	Prepare(context.Context, AdmissionPreparationInput) (AdmissionPreparation, error)
}

// SettingsPreparationSlot prepares immutable limits and report settings off-side.
type SettingsPreparationSlot interface {
	Prepare(context.Context, SettingsPreparationInput) (SettingsPreparation, error)
}

// ApplicationPreparationSlot assembles the generation-bound application authority off-side.
type ApplicationPreparationSlot interface {
	Prepare(context.Context, ApplicationPreparationInput) (ApplicationPreparation, error)
}

// GenerationValidator cross-validates one complete unpublished generation.
type GenerationValidator interface {
	Validate(context.Context, *Generation) error
}

// PolicyPreparationFunc adapts a function to PolicyPreparationSlot.
type PolicyPreparationFunc func(context.Context, PreparationInput) (PolicyPreparation, error)

// Prepare invokes the wrapped policy preparation function.
func (f PolicyPreparationFunc) Prepare(ctx context.Context, input PreparationInput) (PolicyPreparation, error) {
	return f(ctx, input)
}

// ExtensionPreparationFunc adapts a function to ExtensionPreparationSlot.
type ExtensionPreparationFunc func(context.Context, PreparationInput) (ExtensionPreparation, error)

// Prepare invokes the wrapped extension preparation function.
func (f ExtensionPreparationFunc) Prepare(ctx context.Context, input PreparationInput) (ExtensionPreparation, error) {
	return f(ctx, input)
}

// CatalogPreparationFunc adapts a function to CatalogPreparationSlot.
type CatalogPreparationFunc func(context.Context, CatalogPreparationInput) (CatalogPreparation, error)

// Prepare invokes the wrapped catalog preparation function.
func (f CatalogPreparationFunc) Prepare(ctx context.Context, input CatalogPreparationInput) (CatalogPreparation, error) {
	return f(ctx, input)
}

// CallerAuthenticationPreparationFunc adapts a function to its preparation slot.
type CallerAuthenticationPreparationFunc func(
	context.Context,
	AuthorityPreparationInput,
) (CallerAuthenticationPreparation, error)

// Prepare invokes the wrapped caller-authentication preparation function.
func (f CallerAuthenticationPreparationFunc) Prepare(
	ctx context.Context,
	input AuthorityPreparationInput,
) (CallerAuthenticationPreparation, error) {
	return f(ctx, input)
}

// AdmissionPreparationFunc adapts a function to AdmissionPreparationSlot.
type AdmissionPreparationFunc func(context.Context, AdmissionPreparationInput) (AdmissionPreparation, error)

// Prepare invokes the wrapped admission preparation function.
func (f AdmissionPreparationFunc) Prepare(
	ctx context.Context,
	input AdmissionPreparationInput,
) (AdmissionPreparation, error) {
	return f(ctx, input)
}

// SettingsPreparationFunc adapts a function to SettingsPreparationSlot.
type SettingsPreparationFunc func(context.Context, SettingsPreparationInput) (SettingsPreparation, error)

// Prepare invokes the wrapped settings preparation function.
func (f SettingsPreparationFunc) Prepare(
	ctx context.Context,
	input SettingsPreparationInput,
) (SettingsPreparation, error) {
	return f(ctx, input)
}

// ApplicationPreparationFunc adapts a function to ApplicationPreparationSlot.
type ApplicationPreparationFunc func(context.Context, ApplicationPreparationInput) (ApplicationPreparation, error)

// Prepare invokes the wrapped application preparation function.
func (f ApplicationPreparationFunc) Prepare(
	ctx context.Context,
	input ApplicationPreparationInput,
) (ApplicationPreparation, error) {
	return f(ctx, input)
}

// GenerationValidationFunc adapts a function to GenerationValidator.
type GenerationValidationFunc func(context.Context, *Generation) error

// Validate invokes the wrapped complete-generation validator.
func (f GenerationValidationFunc) Validate(ctx context.Context, generation *Generation) error {
	return f(ctx, generation)
}

// PreparationSlots contains every mandatory policy-critical candidate owner.
type PreparationSlots struct {
	Policy               PolicyPreparationSlot
	Extensions           ExtensionPreparationSlot
	Catalog              CatalogPreparationSlot
	CallerAuthentication CallerAuthenticationPreparationSlot
	Admission            AdmissionPreparationSlot
	Settings             SettingsPreparationSlot
	Application          ApplicationPreparationSlot
	Validators           []GenerationValidator
}

// CoordinatorConfig contains the sole store, preparation slots, and safe logger.
type CoordinatorConfig struct {
	Store  *GenerationStore
	Logger *slog.Logger
	Slots  PreparationSlots
}

// Coordinator owns the only prepare, validate, and atomic commit protocol.
type Coordinator struct {
	store  *GenerationStore
	logger *slog.Logger
	slots  PreparationSlots
}

// Candidate owns one complete unpublished generation until commit or discard.
type Candidate struct {
	previous   *Generation
	generation *Generation
	resources  *candidateResourceOwnership
	state      atomic.Uint32
}

type candidateBuilder struct {
	coordinator *Coordinator
	previous    *Generation
	resources   *candidateResourceOwnership
	lifetime    *generationLifetime
	config      config.File
	policy      PolicyPreparation
	extensions  ExtensionPreparation
	catalog     CatalogPreparation
	caller      CallerAuthenticationPreparation
	admission   AdmissionPreparation
	settings    SettingsPreparation
	application ApplicationPreparation
	bindings    *BindingSet
	base        PreparationInput
}

// NewCoordinator validates every mandatory preparation slot.
func NewCoordinator(input CoordinatorConfig) (*Coordinator, error) {
	if input.Store == nil || nilInterface(input.Slots.Policy) || nilInterface(input.Slots.Extensions) ||
		nilInterface(input.Slots.Catalog) || nilInterface(input.Slots.CallerAuthentication) ||
		nilInterface(input.Slots.Admission) || nilInterface(input.Slots.Settings) ||
		nilInterface(input.Slots.Application) {
		return nil, fmt.Errorf("%w: complete preparation slots and generation store are required", ErrInvalidGeneration)
	}

	validators := append([]GenerationValidator(nil), input.Slots.Validators...)
	for index, validator := range validators {
		if nilInterface(validator) {
			return nil, fmt.Errorf("%w: validator %d is nil", ErrInvalidGeneration, index)
		}
	}

	slots := input.Slots
	slots.Validators = validators

	return &Coordinator{store: input.Store, logger: input.Logger, slots: slots}, nil
}

// Apply prepares, validates, and commits one candidate or leaves the active pointer untouched.
func (c *Coordinator) Apply(ctx context.Context, input PrepareInput) (*Generation, error) {
	candidate, err := c.Prepare(ctx, input)
	if err != nil {
		return nil, err
	}

	if err = c.Validate(ctx, candidate); err != nil {
		return nil, err
	}

	return c.Commit(ctx, candidate)
}

// Prepare constructs every policy-critical component without publishing any candidate state.
func (c *Coordinator) Prepare(ctx context.Context, input PrepareInput) (*Candidate, error) {
	ctx = normalizedGenerationContext(ctx)

	if c == nil || c.store == nil || nilInterface(input.Config) || input.ID == 0 {
		return nil, fmt.Errorf("%w: candidate config and positive identity are required", ErrInvalidGeneration)
	}

	previous := c.store.Active()
	if previous != nil && input.ID <= previous.ID() {
		return nil, fmt.Errorf("%w: candidate identity %d is not newer than %d", ErrInvalidGeneration, input.ID, previous.ID())
	}

	builder := newCandidateBuilder(c, input, previous)
	if err := builder.prepare(ctx); err != nil {
		return nil, err
	}

	return builder.candidate(), nil
}

// newCandidateBuilder creates one stateful off-side assembly owner.
func newCandidateBuilder(
	coordinator *Coordinator,
	input PrepareInput,
	previous *Generation,
) *candidateBuilder {
	base := PreparationInput{config: input.Config, id: input.ID}
	resources := &candidateResourceOwnership{}
	if previous != nil {
		base.previous = previous.Config()
	}

	return &candidateBuilder{
		coordinator: coordinator,
		previous:    previous,
		resources:   resources,
		lifetime:    newGenerationLifetime(input.ID, resources, coordinator.logger),
		config:      input.Config,
		base:        base,
	}
}

// prepare runs the fixed dependency-ordered candidate preparation protocol.
func (b *candidateBuilder) prepare(ctx context.Context) error {
	steps := []func(context.Context) error{
		b.preparePolicy,
		b.prepareExtensions,
		b.prepareCatalog,
		b.prepareCallerAuthentication,
		b.prepareAdmission,
		b.prepareSettings,
		b.prepareApplication,
	}

	for _, step := range steps {
		if err := step(ctx); err != nil {
			return err
		}
	}

	return nil
}

// preparePolicy builds and owns the exact legacy policy candidate.
func (b *candidateBuilder) preparePolicy(ctx context.Context) error {
	prepared, err := b.coordinator.slots.Policy.Prepare(ctx, b.base)

	return completePreparation(ctx, b, "policy", prepared, prepared.Resources, err, &b.policy)
}

// prepareExtensions builds and owns immutable definitions and provider bindings.
func (b *candidateBuilder) prepareExtensions(ctx context.Context) error {
	prepared, err := b.coordinator.slots.Extensions.Prepare(ctx, b.base)

	return completePreparation(ctx, b, "extensions", prepared, prepared.Resources, err, &b.extensions)
}

// prepareCatalog compiles the exact catalog from prepared definitions.
func (b *candidateBuilder) prepareCatalog(ctx context.Context) error {
	prepared, err := b.coordinator.slots.Catalog.Prepare(ctx, CatalogPreparationInput{
		base: b.base, definitions: b.extensions.Definitions,
	})

	return completePreparation(ctx, b, "catalog", prepared, prepared.Resources, err, &b.catalog)
}

// prepareCallerAuthentication builds caller credentials against candidate authority.
func (b *candidateBuilder) prepareCallerAuthentication(ctx context.Context) error {
	prepared, err := b.coordinator.slots.CallerAuthentication.Prepare(ctx, AuthorityPreparationInput{
		base: b.base, catalog: b.catalog.Catalog, bindings: b.extensions.Bindings,
	})

	return completePreparation(ctx, b, "caller authentication", prepared, prepared.Resources, err, &b.caller)
}

// prepareAdmission builds request admission against candidate credentials and catalog.
func (b *candidateBuilder) prepareAdmission(ctx context.Context) error {
	prepared, err := b.coordinator.slots.Admission.Prepare(ctx, AdmissionPreparationInput{
		base: b.base, catalog: b.catalog.Catalog, credentials: b.caller.Credentials,
	})

	return completePreparation(ctx, b, "admission", prepared, prepared.Resources, err, &b.admission)
}

// prepareSettings derives bounded report and evaluation settings.
func (b *candidateBuilder) prepareSettings(ctx context.Context) error {
	prepared, err := b.coordinator.slots.Settings.Prepare(ctx, SettingsPreparationInput{
		base: b.base, policy: b.policy.Snapshot, catalog: b.catalog.Catalog,
	})

	return completePreparation(ctx, b, "settings", prepared, prepared.Resources, err, &b.settings)
}

// prepareApplication assembles the final generation-bound application authority.
func (b *candidateBuilder) prepareApplication(ctx context.Context) error {
	b.bindings = b.extensions.Bindings.withGenerationLifetime(b.lifetime)

	prepared, err := b.coordinator.slots.Application.Prepare(ctx, ApplicationPreparationInput{
		config: b.config, policy: b.policy.Snapshot, catalog: b.catalog.Catalog,
		authenticator: b.caller.Authenticator, admission: b.admission.Authority,
		bindings: b.bindings, settings: b.settings.Settings, id: b.base.ID(),
	})

	return completePreparation(ctx, b, "application", prepared, prepared.Resources, err, &b.application)
}

// completePreparation records returned ownership and the typed slot result before error cleanup.
func completePreparation[T any](
	ctx context.Context,
	builder *candidateBuilder,
	component string,
	prepared T,
	resources []CandidateResource,
	err error,
	destination *T,
) error {
	builder.resources.add(resources...)

	*destination = prepared

	return builder.preparationError(ctx, component, err)
}

// preparationError disposes all partial ownership after one failed slot.
func (b *candidateBuilder) preparationError(ctx context.Context, component string, err error) error {
	if err == nil {
		return nil
	}

	return b.coordinator.failPreparation(ctx, b.base.ID(), component, b.resources, err)
}

// candidate freezes the complete prepared component graph for validation.
func (b *candidateBuilder) candidate() *Candidate {
	generation := &Generation{
		config: b.config, policy: b.policy.Snapshot.Clone(), catalog: b.catalog.Catalog.Clone(),
		authenticator: b.caller.Authenticator, admission: b.admission.Authority,
		bindings: b.bindings.Clone(), application: b.application.Application,
		resourceOwnership:  b.resources,
		lifetime:           b.lifetime,
		definitions:        append([]registry.DefinitionContribution(nil), b.extensions.Definitions...),
		credentialProfiles: CredentialProfiles{ids: b.caller.Credentials.IDs()},
		admissionProfiles:  AdmissionProfiles{ids: b.admission.Profiles.IDs()},
		settings:           b.settings.Settings, id: b.base.ID(),
	}

	return &Candidate{previous: b.previous, generation: generation, resources: b.resources}
}

// Validate cross-validates every complete candidate component before publication.
func (c *Coordinator) Validate(ctx context.Context, candidate *Candidate) error {
	ctx = normalizedGenerationContext(ctx)

	if c == nil || candidate == nil || candidate.generation == nil ||
		!candidate.state.CompareAndSwap(candidateStatePrepared, candidateStateValidating) {
		return ErrCandidateConsumed
	}

	if err := validateCompleteGeneration(candidate.generation); err != nil {
		return c.failValidation(ctx, candidate, err)
	}

	for index, validator := range c.slots.Validators {
		if err := validator.Validate(ctx, candidate.generation); err != nil {
			return c.failValidation(ctx, candidate, fmt.Errorf("validator %d: %w", index, err))
		}
	}

	if !candidate.state.CompareAndSwap(candidateStateValidating, candidateStateValidated) {
		return ErrCandidateConsumed
	}

	return nil
}

// Commit publishes one validated generation with the store's sole pointer swap.
func (c *Coordinator) Commit(ctx context.Context, candidate *Candidate) (*Generation, error) {
	ctx = normalizedGenerationContext(ctx)

	if c == nil || c.store == nil || candidate == nil || candidate.generation == nil ||
		!candidate.state.CompareAndSwap(candidateStateValidated, candidateStateCommitting) {
		return nil, ErrCandidateConsumed
	}

	committed, retirementErr := c.store.commit(ctx, candidate.previous, candidate.generation)
	if !committed {
		candidate.state.Store(candidateStateDiscarded)
		cleanupErr := candidate.resources.dispose(ctx)

		if retirementErr != nil {
			return nil, errors.Join(retirementErr, cleanupErr)
		}

		return nil, errors.Join(ErrGenerationChanged, cleanupErr)
	}

	candidate.state.Store(candidateStateCommitted)

	if c.logger != nil {
		c.logger.InfoContext(
			ctx,
			"policy runtime generation committed",
			slog.Uint64("runtime_generation", candidate.generation.ID()),
		)
	}

	if retirementErr != nil && c.logger != nil {
		c.logger.ErrorContext(
			ctx,
			"previous policy runtime generation retirement failed",
			slog.Uint64("runtime_generation", candidate.previous.ID()),
			slog.Any("error", retirementErr),
		)
	}

	if retirementErr != nil {
		return candidate.generation, newGenerationCommitError(candidate.generation.ID(), retirementErr)
	}

	return candidate.generation, nil
}

// Discard releases an uncommitted candidate exactly once.
func (c *Coordinator) Discard(ctx context.Context, candidate *Candidate) error {
	if candidate == nil {
		return nil
	}

	for {
		state := candidate.state.Load()
		switch state {
		case candidateStateCommitted:
			return ErrCandidateConsumed
		case candidateStateDiscarded:
			return candidate.resources.dispose(normalizedGenerationContext(ctx))
		case candidateStateValidating, candidateStateCommitting:
			return ErrCandidateConsumed
		default:
			if candidate.state.CompareAndSwap(state, candidateStateDiscarded) {
				return candidate.resources.dispose(normalizedGenerationContext(ctx))
			}
		}
	}
}

// failPreparation disposes owned partial resources and returns one bounded stage error.
func (c *Coordinator) failPreparation(
	ctx context.Context,
	id uint64,
	component string,
	resources *candidateResourceOwnership,
	cause error,
) error {
	cleanupErr := resources.dispose(ctx)

	err := fmt.Errorf("prepare runtime generation %d %s: %w", id, component, cause)
	if cleanupErr != nil {
		err = fmt.Errorf("%w; candidate cleanup: %v", err, cleanupErr)
	}

	if c.logger != nil {
		c.logger.ErrorContext(
			ctx,
			"policy runtime generation preparation failed",
			slog.Uint64("runtime_generation", id),
			slog.String("component", component),
			slog.Any("error", cause),
		)
	}

	return err
}

// failValidation marks and disposes one rejected complete candidate.
func (c *Coordinator) failValidation(ctx context.Context, candidate *Candidate, cause error) error {
	if candidate.state.CompareAndSwap(candidateStateValidating, candidateStateDiscarded) {
		cleanupErr := candidate.resources.dispose(ctx)
		if cleanupErr != nil {
			cause = fmt.Errorf("%w; candidate cleanup: %v", cause, cleanupErr)
		}
	}

	if c.logger != nil {
		c.logger.ErrorContext(
			ctx,
			"policy runtime generation validation failed",
			slog.Uint64("runtime_generation", candidate.generation.ID()),
			slog.Any("error", cause),
		)
	}

	return fmt.Errorf("validate runtime generation %d: %w", candidate.generation.ID(), cause)
}

// validateCompleteGeneration enforces cross-component identity and authority invariants.
func validateCompleteGeneration(generation *Generation) error {
	if err := validateGenerationComponents(generation); err != nil {
		return err
	}

	if err := validateGenerationIdentities(generation); err != nil {
		return err
	}

	if err := generation.settings.Validate(); err != nil {
		return err
	}

	if err := generation.admissionProfiles.ValidateCredentials(generation.credentialProfiles); err != nil {
		return err
	}

	if err := generation.bindings.ValidateCatalog(generation.catalog); err != nil {
		return err
	}

	return validateGenerationDefinitions(generation.definitions)
}

// validateGenerationComponents rejects every incomplete authority or owned view.
func validateGenerationComponents(generation *Generation) error {
	if generation == nil || generation.id == 0 || nilInterface(generation.config) {
		return fmt.Errorf("%w: config and identity are mandatory", ErrInvalidGeneration)
	}

	if generation.policy == nil || generation.catalog == nil || generation.bindings == nil {
		return fmt.Errorf("%w: policy, catalog, and bindings are mandatory", ErrInvalidGeneration)
	}

	if nilInterface(generation.authenticator) || nilInterface(generation.admission) {
		return fmt.Errorf("%w: caller authorities are mandatory", ErrInvalidGeneration)
	}

	if nilInterface(generation.application) || generation.resourceOwnership == nil {
		return fmt.Errorf("%w: application and resource ownership are mandatory", ErrInvalidGeneration)
	}

	return nil
}

// validateGenerationIdentities rejects policy or application views from another candidate.
func validateGenerationIdentities(generation *Generation) error {
	if generation.policy.Generation != generation.id || generation.application.GenerationID() != generation.id {
		return fmt.Errorf("%w: component generation identities differ", ErrInvalidGeneration)
	}

	return nil
}

// validateGenerationDefinitions validates every immutable namespace contribution.
func validateGenerationDefinitions(definitions []registry.DefinitionContribution) error {
	for index, contribution := range definitions {
		if err := contribution.Validate(); err != nil {
			return fmt.Errorf("%w: definition contribution %d: %v", ErrInvalidGeneration, index, err)
		}
	}

	return nil
}

// normalizedGenerationContext supplies a non-nil context for cleanup and logging.
func normalizedGenerationContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}

	return ctx
}

// retirementGenerationContext preserves values without starting cleanup time before final release.
func retirementGenerationContext(ctx context.Context) context.Context {
	return context.WithoutCancel(normalizedGenerationContext(ctx))
}

// newGenerationCleanupContext starts one bounded cleanup budget when disposal actually begins.
func newGenerationCleanupContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(retirementGenerationContext(ctx), generationResourceCleanupTimeout)
}
