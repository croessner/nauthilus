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

package registry

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/croessner/nauthilus/v3/server/policy/decision"
	"github.com/croessner/nauthilus/v3/server/policy/internal/identifier"
)

const maximumSchemaVersionDigits = 9

var (
	// ErrInvalidNamespace identifies a non-canonical namespace.
	ErrInvalidNamespace = errors.New("invalid policy namespace")

	// ErrInvalidAction identifies a non-canonical action.
	ErrInvalidAction = errors.New("invalid policy action")

	// ErrInvalidSchemaIdentity identifies an incomplete qualified schema identity.
	ErrInvalidSchemaIdentity = errors.New("invalid policy schema identity")

	// ErrInvalidSchemaVersion identifies a non-exact schema version.
	ErrInvalidSchemaVersion = errors.New("invalid policy schema version")

	// ErrTargetSchemaMismatch identifies a schema that does not belong to its target.
	ErrTargetSchemaMismatch = errors.New("policy target and schema do not match")

	// ErrDuplicateNamespace identifies repeated namespace ownership in one contribution.
	ErrDuplicateNamespace = errors.New("duplicate owned policy namespace")

	// ErrNamespaceOwnership identifies a definition outside its contributor namespace bounds.
	ErrNamespaceOwnership = errors.New("policy namespace is not owned by contributor")

	// ErrDuplicateDefinition identifies a repeated definition inside one contribution.
	ErrDuplicateDefinition = errors.New("duplicate policy catalog definition")

	// ErrInvalidContribution identifies a contribution that bypassed its immutable constructor.
	ErrInvalidContribution = errors.New("invalid policy catalog contribution")

	// ErrInvalidFactSchema identifies an invalid target fact schema.
	ErrInvalidFactSchema = errors.New("invalid policy fact schema")

	// ErrFactSchemaMismatch identifies a fact that violates the selected exact schema.
	ErrFactSchemaMismatch = errors.New("policy fact does not match selected schema")
)

// ValidationError carries an exact internal compiler path and identity.
type ValidationError struct {
	cause    error
	path     string
	identity string
	reason   string
}

// Error returns deterministic path- and identity-aware validation text.
func (e *ValidationError) Error() string {
	if e.identity == "" {
		return fmt.Sprintf("%s: %s", e.path, e.reason)
	}

	return fmt.Sprintf("%s: %s: %s", e.path, e.identity, e.reason)
}

// Unwrap exposes the stable validation category.
func (e *ValidationError) Unwrap() error {
	return e.cause
}

// Path returns the exact internal input path.
func (e *ValidationError) Path() string {
	return e.path
}

// Identity returns the rejected canonical identity when available.
func (e *ValidationError) Identity() string {
	return e.identity
}

// SchemaVersion is one immutable exact catalog schema version.
type SchemaVersion struct {
	value  string
	number uint32
}

// NewSchemaVersion validates an exact positive vN schema version.
func NewSchemaVersion(value string) (SchemaVersion, error) {
	if !validSchemaVersion(value) {
		return SchemaVersion{}, newValidationError(
			ErrInvalidSchemaVersion,
			"schema.version",
			value,
			"must be an exact positive vN version without ranges or aliases",
		)
	}

	number, err := strconv.ParseUint(value[1:], 10, 32)
	if err != nil {
		return SchemaVersion{}, newValidationError(
			ErrInvalidSchemaVersion,
			"schema.version",
			value,
			"must fit an unsigned 32-bit version",
		)
	}

	return SchemaVersion{value: value, number: uint32(number)}, nil
}

// String returns the exact schema version spelling.
func (v SchemaVersion) String() string {
	return v.value
}

// Number returns the positive numeric version.
func (v SchemaVersion) Number() uint32 {
	return v.number
}

// valid reports whether the schema version satisfies its constructor invariant.
func (v SchemaVersion) valid() bool {
	return validSchemaVersion(v.value) && v.number > 0
}

// SchemaIdentity identifies one immutable namespace-local schema version.
type SchemaIdentity struct {
	namespace string
	name      string
	version   SchemaVersion
}

// NewSchemaIdentity validates and constructs a qualified exact schema identity.
func NewSchemaIdentity(namespace string, name string, version string) (SchemaIdentity, error) {
	if !identifier.Namespace(namespace) {
		return SchemaIdentity{}, newValidationError(
			ErrInvalidNamespace,
			"schema.namespace",
			namespace,
			"must contain lowercase ASCII segments separated by dots",
		)
	}

	if !identifier.Action(name) {
		return SchemaIdentity{}, newValidationError(
			ErrInvalidSchemaIdentity,
			"schema.name",
			name,
			"must be a canonical action-shaped local name",
		)
	}

	schemaVersion, err := NewSchemaVersion(version)
	if err != nil {
		return SchemaIdentity{}, err
	}

	return SchemaIdentity{namespace: namespace, name: name, version: schemaVersion}, nil
}

// ParseSchemaIdentity parses exactly namespace/name/vN without normalization.
func ParseSchemaIdentity(path string, value string) (SchemaIdentity, error) {
	parts := strings.Split(value, "/")
	if len(parts) != 3 {
		return SchemaIdentity{}, newValidationError(
			ErrInvalidSchemaIdentity,
			path,
			value,
			"must use exact namespace/name/vN form",
		)
	}

	identity, err := NewSchemaIdentity(parts[0], parts[1], parts[2])
	if err != nil {
		var validationError *ValidationError
		if errors.As(err, &validationError) {
			return SchemaIdentity{}, newValidationError(validationError.cause, path, value, validationError.reason)
		}

		return SchemaIdentity{}, err
	}

	return identity, nil
}

// Namespace returns the exact schema namespace.
func (i SchemaIdentity) Namespace() string {
	return i.namespace
}

// Name returns the exact namespace-local schema name.
func (i SchemaIdentity) Name() string {
	return i.name
}

// Version returns the exact immutable schema version.
func (i SchemaIdentity) Version() SchemaVersion {
	return i.version
}

// String returns the canonical qualified schema identity.
func (i SchemaIdentity) String() string {
	return i.namespace + "/" + i.name + "/" + i.version.String()
}

// valid reports whether the schema identity satisfies its constructor invariant.
func (i SchemaIdentity) valid() bool {
	return identifier.Namespace(i.namespace) && identifier.Action(i.name) && i.version.valid()
}

// TargetActivation is an immutable operator-owned exact target/schema selection.
type TargetActivation struct {
	policySetBindings []PolicySetImport
	target            decision.Target
	schema            SchemaIdentity
	defaultPolicySet  PolicySetID
	report            TargetReportSettings
	noMatch           NoMatchBehavior
	path              string
	authorityMode     AuthorityMode
	policyConfigured  bool
}

// NewTargetActivation validates one explicit operator target activation.
func NewTargetActivation(path string, namespace string, action string, schemaReference string) (TargetActivation, error) {
	target, err := newTargetAtPath(path, namespace, action)
	if err != nil {
		return TargetActivation{}, err
	}

	schema, err := ParseSchemaIdentity(path+".schema", schemaReference)
	if err != nil {
		return TargetActivation{}, err
	}

	if schema.namespace != target.Namespace() || schema.name != target.Action() {
		return TargetActivation{}, newValidationError(
			ErrTargetSchemaMismatch,
			path+".schema",
			schema.String(),
			"must belong to the exact activated namespace/action",
		)
	}

	return TargetActivation{target: target, schema: schema, path: path}, nil
}

// Target returns the exact activated target.
func (a TargetActivation) Target() decision.Target {
	return a.target
}

// Schema returns the exact selected schema identity.
func (a TargetActivation) Schema() SchemaIdentity {
	return a.schema
}

// Path returns the operator-owned activation path.
func (a TargetActivation) Path() string {
	return a.path
}

// WithPolicy returns an activation with its exact default and no-match selection.
func (a TargetActivation) WithPolicy(defaultPolicySet string, noMatch string) (TargetActivation, error) {
	if _, err := decision.NewTarget(a.target.Namespace(), a.target.Action()); err != nil || !a.schema.valid() {
		return TargetActivation{}, newValidationError(
			ErrTargetSchemaMismatch,
			a.path,
			a.target.String(),
			"activation must be constructor validated before policy selection",
		)
	}

	var (
		defaultSet PolicySetID
		err        error
	)

	if defaultPolicySet != "" {
		defaultSet, err = ParsePolicySetID(a.path+".default_policy", defaultPolicySet)
		if err != nil {
			return TargetActivation{}, err
		}
	}

	a.defaultPolicySet = defaultSet
	a.noMatch = parseNoMatch(noMatch)
	a.authorityMode = AuthorityModeEnforce
	a.policyConfigured = true

	return a, nil
}

// WithAuthorityMode returns an activation with one explicit enforce or observe authority contract.
func (a TargetActivation) WithAuthorityMode(mode AuthorityMode) (TargetActivation, error) {
	if !a.policyConfigured || !mode.Valid() {
		return TargetActivation{}, newValidationError(
			ErrInvalidAuthorityMode,
			a.path+".mode",
			string(mode),
			"must select enforce or observe after policy configuration",
		)
	}

	a.authorityMode = mode

	return a, nil
}

// AuthorityMode returns the exact target authority selection.
func (a TargetActivation) AuthorityMode() AuthorityMode {
	return a.authorityMode
}

// DefaultPolicySet returns the exact configured target fallback set.
func (a TargetActivation) DefaultPolicySet() PolicySetID {
	return a.defaultPolicySet
}

// NoMatch returns the configured generic fallback or unset authn value.
func (a TargetActivation) NoMatch() NoMatchBehavior {
	return a.noMatch
}

// PolicyConfigured reports whether policy selection passed the immutable builder.
func (a TargetActivation) PolicyConfigured() bool {
	return a.policyConfigured
}

// WithPolicySetBindings returns an activation with explicit target/checkpoint set references.
func (a TargetActivation) WithPolicySetBindings(bindings []PolicySetImport) (TargetActivation, error) {
	for _, binding := range bindings {
		if binding.Target().String() != a.target.String() {
			return TargetActivation{}, newValidationError(
				ErrTargetSchemaMismatch,
				binding.Path(),
				binding.Target().String(),
				"policy-set binding must belong to the exact activated target",
			)
		}
	}

	a.policySetBindings = clonePolicySetImports(bindings)

	return a, nil
}

// PolicySetBindings returns detached explicit target/checkpoint set references.
func (a TargetActivation) PolicySetBindings() []PolicySetImport {
	return clonePolicySetImports(a.policySetBindings)
}

// TargetReportSettings is one immutable target-local diagnostic report selection.
type TargetReportSettings struct {
	enabled           bool
	includeFSM        bool
	includeChecks     bool
	includeAttributes bool
}

// NewTargetReportSettings constructs one exact target report selection.
func NewTargetReportSettings(
	enabled bool,
	includeFSM bool,
	includeChecks bool,
	includeAttributes bool,
) TargetReportSettings {
	return TargetReportSettings{
		enabled: enabled, includeFSM: includeFSM,
		includeChecks: includeChecks, includeAttributes: includeAttributes,
	}
}

// Enabled reports whether target report construction is selected.
func (s TargetReportSettings) Enabled() bool {
	return s.enabled
}

// IncludeFSM reports whether the authentication state machine is retained.
func (s TargetReportSettings) IncludeFSM() bool {
	return s.includeFSM
}

// IncludeChecks reports whether provider/check diagnostics are retained.
func (s TargetReportSettings) IncludeChecks() bool {
	return s.includeChecks
}

// IncludeAttributes reports whether report attributes are retained.
func (s TargetReportSettings) IncludeAttributes() bool {
	return s.includeAttributes
}

// WithReport returns an activation with one immutable diagnostic report selection.
func (a TargetActivation) WithReport(settings TargetReportSettings) (TargetActivation, error) {
	if _, err := decision.NewTarget(a.target.Namespace(), a.target.Action()); err != nil || !a.schema.valid() {
		return TargetActivation{}, newValidationError(
			ErrTargetSchemaMismatch,
			a.path+".report",
			a.target.String(),
			"activation must be constructor validated before report selection",
		)
	}

	a.report = settings

	return a, nil
}

// Report returns the exact target-local diagnostic report selection.
func (a TargetActivation) Report() TargetReportSettings {
	return a.report
}

// ClientAdmissionReference is an immutable future client-profile target/schema reference.
type ClientAdmissionReference struct {
	target decision.Target
	schema SchemaIdentity
	path   string
}

// NewClientAdmissionReference validates a client grant reference without granting authorization.
func NewClientAdmissionReference(path string, namespace string, action string, schemaReference string) (ClientAdmissionReference, error) {
	activation, err := NewTargetActivation(path, namespace, action, schemaReference)
	if err != nil {
		return ClientAdmissionReference{}, err
	}

	return ClientAdmissionReference{
		target: activation.Target(),
		schema: activation.Schema(),
		path:   path,
	}, nil
}

// Target returns the referenced exact target.
func (r ClientAdmissionReference) Target() decision.Target {
	return r.target
}

// Schema returns the referenced exact schema.
func (r ClientAdmissionReference) Schema() SchemaIdentity {
	return r.schema
}

// Path returns the future client-profile reference path.
func (r ClientAdmissionReference) Path() string {
	return r.path
}

// newTargetAtPath validates target parts while preserving the caller-owned path.
func newTargetAtPath(path string, namespace string, action string) (decision.Target, error) {
	if !identifier.Namespace(namespace) {
		return decision.Target{}, newValidationError(
			ErrInvalidNamespace,
			path+".namespace",
			namespace,
			"must contain lowercase ASCII segments separated by dots",
		)
	}

	if !identifier.Action(action) {
		return decision.Target{}, newValidationError(
			ErrInvalidAction,
			path+".action",
			action,
			"must contain lowercase ASCII words separated by hyphens or underscores",
		)
	}

	target, err := decision.NewTarget(namespace, action)
	if err != nil {
		return decision.Target{}, err
	}

	return target, nil
}

// validSchemaVersion enforces exact positive vN spelling without normalization.
func validSchemaVersion(value string) bool {
	if len(value) < 2 || len(value) > maximumSchemaVersionDigits+1 || value[0] != 'v' || value[1] == '0' {
		return false
	}

	for index := 1; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}

	return true
}

// newValidationError constructs one deterministic internal catalog validation error.
func newValidationError(cause error, path string, identity string, reason string) error {
	return &ValidationError{cause: cause, path: path, identity: identity, reason: reason}
}
