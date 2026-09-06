package pluginapi

// ExecutionIdentityView identifies the host-selected registration and target of a callback.
// Hosts derive this value from the captured registry, never from caller facts or arguments.
type ExecutionIdentityView struct {
	module         string
	component      string
	extensionPoint string
	operation      string
	target         DecisionTargetSelector
}

// NewExecutionIdentityView validates and captures immutable execution metadata.
func NewExecutionIdentityView(module, component, extensionPoint, operation string, target DecisionTargetSelector) (ExecutionIdentityView, error) {
	identity := ExecutionIdentityView{module: module, component: component, extensionPoint: extensionPoint, operation: operation, target: target}
	if !identity.valid() {
		return ExecutionIdentityView{}, invalidDecisionContract("execution identity", "contains invalid registration or target metadata")
	}

	return identity, nil
}

// valid rejects incomplete or malformed host registration metadata.
func (v ExecutionIdentityView) valid() bool {
	return ValidateModuleName(v.module) == nil && ValidateComponentName(v.component) == nil &&
		validDecisionAction(v.extensionPoint) && validDecisionAction(v.operation) && validateDecisionTargetSelector(v.target) == nil
}

// Module returns the configured module instance.
func (v ExecutionIdentityView) Module() string { return v.module }

// Component returns the registered component name.
func (v ExecutionIdentityView) Component() string { return v.component }

// ExtensionPoint returns the host-selected callback family.
func (v ExecutionIdentityView) ExtensionPoint() string { return v.extensionPoint }

// Operation returns the selected operation within the component.
func (v ExecutionIdentityView) Operation() string { return v.operation }

// Target returns the exact admitted target by value.
func (v ExecutionIdentityView) Target() DecisionTargetSelector { return v.target }

// NewObligationRequest binds an obligation input to validated host execution metadata.
func NewObligationRequest(input ObligationRequest, identity ExecutionIdentityView) (ObligationRequest, error) {
	if !identity.valid() {
		return ObligationRequest{}, invalidDecisionContract("obligation request", "requires host execution identity")
	}

	input.executionIdentity = identity

	return input, nil
}

// ExecutionIdentity returns the immutable host-selected obligation identity.
func (r ObligationRequest) ExecutionIdentity() ExecutionIdentityView { return r.executionIdentity }

// NewPostActionRequest binds a post-action input to validated host execution metadata.
func NewPostActionRequest(input PostActionRequest, identity ExecutionIdentityView) (PostActionRequest, error) {
	if !identity.valid() {
		return PostActionRequest{}, invalidDecisionContract("post-action request", "requires host execution identity")
	}

	input.executionIdentity = identity

	return input, nil
}

// ExecutionIdentity returns the immutable host-selected post-action identity.
func (r PostActionRequest) ExecutionIdentity() ExecutionIdentityView { return r.executionIdentity }
