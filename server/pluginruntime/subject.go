package pluginruntime

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	pluginapi "github.com/croessner/nauthilus/pluginapi/v1"
	"github.com/croessner/nauthilus/server/backend/bktype"
	"github.com/croessner/nauthilus/server/core"
	"github.com/croessner/nauthilus/server/definitions"
	"github.com/croessner/nauthilus/server/lualib"
	"github.com/croessner/nauthilus/server/lualib/pipeline"
	"github.com/croessner/nauthilus/server/pluginregistry"
	"github.com/croessner/nauthilus/server/policy"
	policycollection "github.com/croessner/nauthilus/server/policy/collection"
	policyregistry "github.com/croessner/nauthilus/server/policy/registry"

	"github.com/gin-gonic/gin"
	"golang.org/x/sync/errgroup"
)

const (
	pluginSubjectCheckPrefix     = "plugin_subject_"
	pluginSubjectConfigRefPrefix = "plugins.modules."
	pluginErrorDetailKey         = "reason_code"
	pluginErrorReason            = "plugin_error"
)

var _ core.PluginSubjectSourceBridge = (*SubjectSourceBridge)(nil)

// SubjectSourceBridge adapts native plugin subject sources into the post-backend flow.
type SubjectSourceBridge struct {
	runner *Runner
}

// NewSubjectSourceBridge returns a bridge bound to one plugin runner.
func NewSubjectSourceBridge(runner *Runner) *SubjectSourceBridge {
	return &SubjectSourceBridge{runner: runner}
}

// Analyze executes registered native subject sources after the existing Lua subject flow.
func (b *SubjectSourceBridge) Analyze(
	ctx *gin.Context,
	view *core.StateView,
	passDBResult *core.PassDBResult,
	current definitions.AuthResult,
) (definitions.AuthResult, bool) {
	auth := authFromView(view)
	if b == nil || b.runner == nil || auth == nil || passDBResult == nil {
		return current, false
	}

	components := b.runner.registry.SubjectSources()
	if len(components) == 0 {
		return current, false
	}

	if current == definitions.AuthResultTempFail {
		return current, true
	}

	outcome, err := b.evaluate(ctx, auth, passDBResult, components, current)
	if err != nil {
		auth.Runtime.Authorized = false

		return definitions.AuthResultTempFail, true
	}

	if outcome.rejected {
		auth.Runtime.Authorized = false

		return definitions.AuthResultFail, true
	}

	auth.Runtime.Authorized = current == definitions.AuthResultOK

	return current, true
}

type subjectBridgeOutcome struct {
	rejected bool
}

type subjectExecutionResult struct {
	err       error
	component pluginregistry.Component
	result    pluginapi.SubjectResult
	duration  time.Duration
	index     int
}

func (b *SubjectSourceBridge) evaluate(
	ctx *gin.Context,
	auth *core.AuthState,
	passDBResult *core.PassDBResult,
	components []pluginregistry.Component,
	current definitions.AuthResult,
) (subjectBridgeOutcome, error) {
	plan, err := subjectPlan(components, subjectMode(auth, passDBResult, current))
	if err != nil {
		return subjectBridgeOutcome{}, err
	}

	if pipeline.PlannedNodeCount(plan) == 0 {
		return subjectBridgeOutcome{}, nil
	}

	runtimeValues := runtimeSnapshot(auth)
	backendResult := pluginBackendResultFromPassDB(passDBResult)
	policyCtx := auth.PolicyDecisionContext(ctx)
	outcome := subjectBridgeOutcome{}

	for _, level := range plan.Levels {
		levelResults, err := b.evaluateSubjectLevel(ctx, auth, backendResult, runtimeValues, level)
		if err != nil {
			return subjectBridgeOutcome{}, err
		}

		if err := applySubjectLevelResults(ctx, auth, passDBResult, policyCtx, runtimeValues, &backendResult, levelResults, &outcome); err != nil {
			return subjectBridgeOutcome{}, err
		}
	}

	applyRuntimeValues(auth, runtimeValues)

	return outcome, nil
}

func (b *SubjectSourceBridge) evaluateSubjectLevel(
	ctx *gin.Context,
	auth *core.AuthState,
	backendResult pluginapi.BackendResult,
	runtimeValues map[string]any,
	level []pipeline.PlannedNode,
) ([]subjectExecutionResult, error) {
	results := make([]subjectExecutionResult, len(level))
	group, groupCtx := errgroup.WithContext(contextFromGin(ctx))

	for levelIndex, planned := range level {
		planned := planned
		levelIndex := levelIndex
		component := planned.Value.(pluginregistry.Component)

		group.Go(func() error {
			result := subjectExecutionResult{
				component: component,
				index:     planned.Index,
			}
			started := time.Now()

			request, err := subjectRequest(b.runner, auth, component, backendResult, runtimeValues)
			if err != nil {
				result.err = err
				result.duration = time.Since(started)
				results[levelIndex] = result

				return err
			}

			callCtx, cancel := subjectCallContext(groupCtx, component.SourceDescriptor.Timeout)
			defer cancel()

			result.result, result.err = b.runner.EvaluateSubject(callCtx, component.QualifiedName, request)
			result.duration = time.Since(started)
			results[levelIndex] = result

			return nil
		})
	}

	if err := group.Wait(); err != nil {
		return results, err
	}

	sortSubjectResults(results)

	return results, nil
}

func applySubjectLevelResults(
	ctx *gin.Context,
	auth *core.AuthState,
	passDBResult *core.PassDBResult,
	policyCtx *policycollection.DecisionContext,
	runtimeValues map[string]any,
	backendResult *pluginapi.BackendResult,
	results []subjectExecutionResult,
	outcome *subjectBridgeOutcome,
) error {
	deltas := make([]pluginapi.RuntimeDelta, 0, len(results))

	for _, item := range results {
		factAttributes, factErr := pluginPolicyFactAttributes(policyCtx, item.result.Facts)
		recordPluginSubjectResult(ctx, policyCtx, item, factAttributes, factErr)

		if item.err != nil {
			return item.err
		}

		applySubjectStatus(auth, item.result.Status)
		applySubjectLogs(auth, item.result.Logs)
		auth.ApplyPluginResponseMutation(ctx, item.result.Response)

		if factErr != nil {
			return factErr
		}

		applySubjectAttributePatch(auth, passDBResult, backendResult, item.result.BackendAttributes)
		applySubjectBackendRef(auth, passDBResult, item.result.SelectedBackend)

		if err := applySubjectBackendResultPatch(auth, passDBResult, backendResult, item.result.BackendResultPatch); err != nil {
			return err
		}

		deltas = append(deltas, item.result.RuntimeDelta)

		if item.result.Rejected {
			outcome.rejected = true
		}
	}

	merged, err := MergeRuntimeDeltas(contextFromGin(ctx), runtimeValues, nil, deltas...)
	if err != nil {
		return err
	}

	clearMap(runtimeValues)

	for key, value := range merged {
		runtimeValues[key] = value
	}

	return nil
}

func subjectPlan(components []pluginregistry.Component, mode pipeline.ModeMask) (pipeline.Plan, error) {
	nodes := make([]pipeline.Node, 0, len(components))
	for index, component := range components {
		dependencies := append([]string(nil), component.SourceDescriptor.Requires...)
		dependencies = append(dependencies, component.SourceDescriptor.After...)
		nodes = append(nodes, pipeline.Node{
			Name:      component.QualifiedName,
			DependsOn: dependencies,
			Index:     index,
			Modes:     pipeline.ModeAuthenticated | pipeline.ModeUnauthenticated | pipeline.ModeNoAuth,
			Value:     component,
		})
	}

	return pipeline.BuildPlan(nodes, mode)
}

func subjectMode(auth *core.AuthState, passDBResult *core.PassDBResult, current definitions.AuthResult) pipeline.ModeMask {
	if auth != nil && auth.Request.NoAuth {
		return pipeline.ModeNoAuth
	}

	if (passDBResult != nil && passDBResult.Authenticated) || current == definitions.AuthResultOK {
		return pipeline.ModeAuthenticated
	}

	return pipeline.ModeUnauthenticated
}

func subjectRequest(
	runner *Runner,
	auth *core.AuthState,
	component pluginregistry.Component,
	backendResult pluginapi.BackendResult,
	runtimeValues map[string]any,
) (pluginapi.SubjectRequest, error) {
	runtimeContext, err := NewRuntimeContext(runtimeValues)
	if err != nil {
		return pluginapi.SubjectRequest{}, err
	}

	return pluginapi.SubjectRequest{
		Snapshot:      NewRequestSnapshotFromAuthState(auth, WithSnapshotConfig(auth.Cfg())),
		Runtime:       runtimeContext,
		BackendResult: backendResult,
		Credentials: NewCredentialProvider(
			auth.Ctx(),
			auth.GetPassword(),
			subjectRunnerCapabilities(runner, component.ModuleName),
		),
	}, nil
}

func subjectRunnerCapabilities(runner *Runner, moduleName string) []pluginapi.Capability {
	if runner == nil {
		return nil
	}

	return runner.ModuleCapabilities(moduleName)
}

func subjectCallContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return ctx, func() {}
	}

	return context.WithTimeout(ctx, timeout)
}

func pluginBackendResultFromPassDB(passDBResult *core.PassDBResult) pluginapi.BackendResult {
	if passDBResult == nil {
		return pluginapi.BackendResult{}
	}

	return pluginapi.BackendResult{
		Attributes:    pluginAttributesFromMapping(passDBResult.Attributes),
		Account:       passDBResult.Account,
		AccountField:  passDBResult.AccountField,
		Authenticated: passDBResult.Authenticated,
		UserFound:     passDBResult.UserFound,
		BackendServer: pluginBackendRefFromCore(passDBResult.BackendRef),
	}
}

func pluginAttributesFromMapping(attributes bktype.AttributeMapping) map[string][]string {
	if len(attributes) == 0 {
		return nil
	}

	mapped := make(map[string][]string, len(attributes))
	for key, values := range attributes {
		for _, value := range values {
			if text, ok := value.(string); ok {
				mapped[key] = append(mapped[key], text)
			}
		}
	}

	return mapped
}

func pluginBackendRefFromCore(ref core.RemoteBackendRef) *pluginapi.BackendServerRef {
	if ref.IsZero() {
		return nil
	}

	host, port := splitBackendServerToken(ref.OpaqueToken)

	return &pluginapi.BackendServerRef{
		Name:      ref.Name,
		Protocol:  ref.Protocol,
		Authority: ref.Authority,
		Address:   host,
		Port:      port,
	}
}

func splitBackendServerToken(token string) (string, string) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", ""
	}

	if host, port, err := net.SplitHostPort(token); err == nil {
		return host, port
	}

	if strings.Count(token, ":") > 1 {
		return token, ""
	}

	host, port, ok := strings.Cut(token, ":")
	if !ok {
		return token, ""
	}

	return host, port
}

func applySubjectStatus(auth *core.AuthState, status *pluginapi.StatusMessage) {
	applyPluginStatus(auth, status)
}

func applySubjectLogs(auth *core.AuthState, fields []pluginapi.LogField) {
	if auth == nil || len(fields) == 0 {
		return
	}

	for _, field := range fields {
		if field.Key == "" {
			continue
		}

		auth.Runtime.AdditionalLogs = append(auth.Runtime.AdditionalLogs, field.Key, field.Value)
	}
}

func applySubjectAttributePatch(
	auth *core.AuthState,
	passDBResult *core.PassDBResult,
	backendResult *pluginapi.BackendResult,
	patch pluginapi.AttributePatch,
) {
	if auth == nil || passDBResult == nil {
		return
	}

	if passDBResult.Attributes == nil {
		passDBResult.Attributes = make(bktype.AttributeMapping)
	}

	if backendResult.Attributes == nil {
		backendResult.Attributes = make(map[string][]string)
	}

	for _, name := range patch.Delete {
		if name == "" {
			continue
		}

		delete(passDBResult.Attributes, name)
		delete(backendResult.Attributes, name)
		auth.DeleteAttribute(name)
	}

	for name, values := range patch.Set {
		if name == "" {
			continue
		}

		attributeValues := stringsToAnySlice(values)

		passDBResult.Attributes[name] = attributeValues

		backendResult.Attributes[name] = append([]string(nil), values...)
		auth.SetAttributeValues(name, attributeValues)
	}
}

// applySubjectBackendResultPatch applies explicit value-only backend result changes from a subject source.
func applySubjectBackendResultPatch(
	auth *core.AuthState,
	passDBResult *core.PassDBResult,
	backendResult *pluginapi.BackendResult,
	patch *pluginapi.BackendResultPatch,
) error {
	if patch == nil {
		return nil
	}

	applySubjectAttributePatch(auth, passDBResult, backendResult, patch.Attributes)

	if err := applySubjectAccountPatch(auth, passDBResult, backendResult, patch); err != nil {
		return err
	}

	if patch.Authenticated != nil {
		passDBResult.Authenticated = *patch.Authenticated
		backendResult.Authenticated = *patch.Authenticated
	}

	if patch.UserFound != nil {
		passDBResult.UserFound = *patch.UserFound
		backendResult.UserFound = *patch.UserFound
	}

	applySubjectBackendRef(auth, passDBResult, patch.SelectedBackend)

	if patch.SelectedBackend != nil {
		backendResult.BackendServer = pluginBackendRefFromCore(passDBResult.BackendRef)
	}

	return nil
}

// applySubjectAccountPatch updates account identity fields and keeps the selected attribute materialized.
func applySubjectAccountPatch(
	auth *core.AuthState,
	passDBResult *core.PassDBResult,
	backendResult *pluginapi.BackendResult,
	patch *pluginapi.BackendResultPatch,
) error {
	if passDBResult == nil || backendResult == nil {
		return nil
	}

	accountField, err := subjectPatchAccountField(passDBResult, backendResult, patch)
	if err != nil {
		return err
	}

	if accountField != "" {
		passDBResult.AccountField = accountField
		backendResult.AccountField = accountField
	}

	if patch.Account == "" {
		return nil
	}

	passDBResult.Account = patch.Account
	backendResult.Account = patch.Account

	materializeSubjectAccount(auth, passDBResult, backendResult, accountField, patch.Account)

	return nil
}

// subjectPatchAccountField determines the account field used by a subject backend-result patch.
func subjectPatchAccountField(
	passDBResult *core.PassDBResult,
	backendResult *pluginapi.BackendResult,
	patch *pluginapi.BackendResultPatch,
) (string, error) {
	switch {
	case patch == nil:
		return "", nil
	case patch.AccountField != "":
		if err := pluginapi.ValidateBackendAttributeName(patch.AccountField); err != nil {
			return "", err
		}

		return patch.AccountField, nil
	case backendResult != nil && backendResult.AccountField != "":
		return backendResult.AccountField, nil
	case passDBResult != nil && passDBResult.AccountField != "":
		return passDBResult.AccountField, nil
	case patch.Account != "":
		return pluginBackendAccountField, nil
	default:
		return "", nil
	}
}

// materializeSubjectAccount writes the patched account under the selected backend attribute.
func materializeSubjectAccount(
	auth *core.AuthState,
	passDBResult *core.PassDBResult,
	backendResult *pluginapi.BackendResult,
	accountField string,
	account string,
) {
	if accountField == "" {
		return
	}

	if passDBResult.Attributes == nil {
		passDBResult.Attributes = make(bktype.AttributeMapping)
	}

	if backendResult.Attributes == nil {
		backendResult.Attributes = make(map[string][]string)
	}

	values := []any{account}
	passDBResult.Attributes[accountField] = values
	backendResult.Attributes[accountField] = []string{account}

	if auth != nil {
		auth.SetAttributeValues(accountField, values)
	}
}

func applySubjectBackendRef(auth *core.AuthState, passDBResult *core.PassDBResult, ref *pluginapi.BackendServerRef) {
	if ref == nil {
		return
	}

	applyPluginBackendServerRef(auth, ref)

	if passDBResult != nil {
		passDBResult.BackendRef = pluginBackendServerRef(ref)
	}

	if auth == nil {
		return
	}

	auth.Runtime.UsedBackendIP = ref.Address
	if port, err := strconv.Atoi(strings.TrimSpace(ref.Port)); err == nil {
		auth.Runtime.UsedBackendPort = port
	}
}

func recordPluginSubjectResult(
	ctx *gin.Context,
	policyCtx *policycollection.DecisionContext,
	item subjectExecutionResult,
	factAttributes []policycollection.AttributeValue,
	factErr error,
) {
	if policyCtx == nil || item.component.QualifiedName == "" {
		return
	}

	attributes := []policycollection.AttributeValue{
		policycollection.BoolAttribute(
			pluginSubjectAttributeID(item.component, "rejected"),
			policy.StageSubjectAnalysis,
			policyCtx.Report().Operation,
			item.result.Rejected,
			pluginStatusDetails(item.result.Status),
		),
	}

	if factErr == nil {
		attributes = append(attributes, factAttributes...)
	} else if item.err == nil {
		item.err = factErr
	}

	if item.err != nil {
		attributes = append(attributes, policycollection.BoolAttribute(
			pluginSubjectAttributeID(item.component, "error"),
			policy.StageSubjectAnalysis,
			policyCtx.Report().Operation,
			true,
			map[string]policycollection.DetailValue{pluginErrorDetailKey: policycollection.InternalDetail(pluginErrorReason)},
		))
	}

	check := policyCtx.BeginCheck(contextFromGin(ctx), policycollection.CheckSelector{
		CheckType: policy.CheckTypePluginSubjectSource,
		Stage:     policy.StageSubjectAnalysis,
		Name:      pluginSubjectCheckName(item.component),
		ConfigRef: pluginSubjectConfigRef(item.component),
	})
	check.Finish(policycollection.CheckResult{
		Err:          item.err,
		Status:       pluginSubjectStatus(item.err),
		Reason:       pluginSubjectReason(item.err),
		Matched:      item.result.Rejected || item.err != nil,
		DecisionHint: pluginSubjectDecision(item.result.Rejected, item.err),
		Duration:     item.duration,
		Attributes:   attributes,
	})
}

func pluginPolicyFactAttributes(
	policyCtx *policycollection.DecisionContext,
	facts []pluginapi.PolicyFact,
) ([]policycollection.AttributeValue, error) {
	return pluginPolicyFactAttributesForStage(policyCtx, facts, policy.StageSubjectAnalysis)
}

// pluginPolicyFactAttributesForStage validates plugin facts against one policy stage registry.
func pluginPolicyFactAttributesForStage(
	policyCtx *policycollection.DecisionContext,
	facts []pluginapi.PolicyFact,
	stage policy.Stage,
) ([]policycollection.AttributeValue, error) {
	if len(facts) == 0 {
		return nil, nil
	}

	if policyCtx == nil {
		return nil, nil
	}

	validated, err := validatePluginPolicyFacts(facts)
	if err != nil {
		return nil, err
	}

	snapshot := policyCtx.Snapshot()
	if snapshot == nil {
		return nil, nil
	}

	operation := policyCtx.Report().Operation
	attributes := make([]policycollection.AttributeValue, 0, len(validated))

	for _, fact := range validated {
		definition, ok := snapshot.AttributeRegistry[fact.Attribute]
		if !ok {
			return nil, fmt.Errorf("%w: unknown policy fact %q", ErrInvalidRuntimeKey, fact.Attribute)
		}

		if definition.Stage != stage {
			return nil, fmt.Errorf("%w: policy fact %q has stage %q", ErrInvalidRuntimeKey, fact.Attribute, definition.Stage)
		}

		if !policyOperationAllowed(definition.Operations, operation) {
			return nil, fmt.Errorf("%w: policy fact %q does not allow operation %q", ErrInvalidRuntimeKey, fact.Attribute, operation)
		}

		value, err := policyFactValue(definition, fact.Value)
		if err != nil {
			return nil, err
		}

		attributes = append(attributes, policycollection.AttributeValue{
			ID:        fact.Attribute,
			Stage:     definition.Stage,
			Operation: operation,
			Value:     value,
		})
	}

	return attributes, nil
}

func policyFactValue(definition policyregistry.AttributeDefinition, value any) (any, error) {
	switch definition.Type {
	case policyregistry.AttributeTypeBool:
		typed, ok := value.(bool)
		if !ok {
			return nil, fmt.Errorf("%w: policy fact %q must be bool", ErrUnsupportedRuntimeValue, definition.ID)
		}

		return typed, nil
	case policyregistry.AttributeTypeString:
		typed, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("%w: policy fact %q must be string", ErrUnsupportedRuntimeValue, definition.ID)
		}

		return typed, nil
	case policyregistry.AttributeTypeNumber:
		return numberPolicyFactValue(definition.ID, value)
	case policyregistry.AttributeTypeStringList:
		return stringListPolicyFactValue(definition.ID, value)
	case policyregistry.AttributeTypeIP:
		return ipPolicyFactValue(definition.ID, value)
	default:
		return value, nil
	}
}

func numberPolicyFactValue(id string, value any) (float64, error) {
	switch typed := value.(type) {
	case int:
		return float64(typed), nil
	case int64:
		return float64(typed), nil
	case uint64:
		return float64(typed), nil
	case float64:
		return typed, nil
	default:
		return 0, fmt.Errorf("%w: policy fact %q must be number", ErrUnsupportedRuntimeValue, id)
	}
}

func stringListPolicyFactValue(id string, value any) ([]string, error) {
	values, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("%w: policy fact %q must be string list", ErrUnsupportedRuntimeValue, id)
	}

	converted := make([]string, 0, len(values))
	for _, item := range values {
		text, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("%w: policy fact %q must contain only strings", ErrUnsupportedRuntimeValue, id)
		}

		converted = append(converted, text)
	}

	return converted, nil
}

func ipPolicyFactValue(id string, value any) (netip.Addr, error) {
	switch typed := value.(type) {
	case netip.Addr:
		return typed, nil
	case string:
		addr, err := netip.ParseAddr(typed)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("%w: policy fact %q must be IP", ErrUnsupportedRuntimeValue, id)
		}

		return addr, nil
	default:
		return netip.Addr{}, fmt.Errorf("%w: policy fact %q must be IP", ErrUnsupportedRuntimeValue, id)
	}
}

func policyOperationAllowed(operations []policy.Operation, operation policy.Operation) bool {
	for _, candidate := range operations {
		if candidate == operation {
			return true
		}
	}

	return false
}

func pluginSubjectCheckName(component pluginregistry.Component) string {
	return pluginSubjectCheckPrefix + strings.ReplaceAll(component.QualifiedName, ".", "_")
}

func pluginSubjectConfigRef(component pluginregistry.Component) string {
	return pluginSubjectConfigRefPrefix + component.ModuleName + ".subject"
}

func pluginSubjectAttributeID(component pluginregistry.Component, suffix string) string {
	return "auth.plugin.subject." + component.ModuleName + "." + component.LocalName + "." + suffix
}

func pluginStatusDetails(status *pluginapi.StatusMessage) map[string]policycollection.DetailValue {
	if status == nil || status.DefaultText == "" {
		return nil
	}

	return map[string]policycollection.DetailValue{
		"status_message": policycollection.PublicMessageDetail(status.DefaultText),
	}
}

func pluginSubjectStatus(err error) policy.CheckStatus {
	if err != nil {
		return policy.CheckStatusError
	}

	return policy.CheckStatusOK
}

func pluginSubjectReason(err error) string {
	if err != nil {
		return pluginErrorReason
	}

	return ""
}

func pluginSubjectDecision(rejected bool, err error) policy.Decision {
	if err != nil {
		return policy.DecisionTempFail
	}

	if rejected {
		return policy.DecisionDeny
	}

	return policy.DecisionNeutral
}

func runtimeSnapshot(auth *core.AuthState) map[string]any {
	if auth == nil || auth.Runtime.Context == nil {
		return map[string]any{}
	}

	return auth.Runtime.Context.Snapshot()
}

func applyRuntimeValues(auth *core.AuthState, values map[string]any) {
	if auth == nil {
		return
	}

	if auth.Runtime.Context == nil {
		auth.Runtime.Context = lualib.NewContext()
	}

	before := auth.Runtime.Context.Snapshot()

	for key := range before {
		if _, ok := values[key]; !ok {
			auth.Runtime.Context.Delete(key)
		}
	}

	for key, value := range values {
		auth.Runtime.Context.Set(key, value)
	}
}

func clearMap(values map[string]any) {
	for key := range values {
		delete(values, key)
	}
}

func sortSubjectResults(results []subjectExecutionResult) {
	for i := 1; i < len(results); i++ {
		item := results[i]
		j := i - 1

		for j >= 0 && results[j].index > item.index {
			results[j+1] = results[j]
			j--
		}

		results[j+1] = item
	}
}

func authFromView(view *core.StateView) *core.AuthState {
	if view == nil {
		return nil
	}

	return view.Auth()
}

func contextFromGin(ctx *gin.Context) context.Context {
	if ctx != nil && ctx.Request != nil {
		return ctx.Request.Context()
	}

	return context.Background()
}
