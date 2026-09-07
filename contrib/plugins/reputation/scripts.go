package main

import (
	_ "embed"
	"fmt"
)

//go:embed scripts/override.lua
var overrideScript string

//go:embed scripts/assessment.lua
var assessmentScript string

//go:embed scripts/override_state.lua
var overrideStateScript string

//go:embed scripts/state.lua
var stateScript string

//go:embed scripts/common.lua
var commonScript string

//go:embed scripts/metadata.lua
var metadataScript string

//go:embed scripts/control.lua
var controlScript string

//go:embed scripts/manifest.lua
var manifestScript string

//go:embed scripts/ingestion.lua
var ingestionScript string

const (
	scriptOverride   = "reputation.override.v1"
	scriptAssessment = "reputation.assessment.v1"
	scriptMetadata   = "reputation.metadata.v1"
	scriptControl    = "reputation.control.v1"
	scriptManifest   = "reputation.manifest.v1"
	scriptIngestion  = "reputation.ingestion.v1"
)

// reputationScripts returns named sources for host-owned upload, routing and bounded NOSCRIPT recovery.
func reputationScripts() map[string]string {
	preamble := fmt.Sprintf("local state_schema = %q\nlocal manifest_schema = %q\nlocal override_schema = %q\nlocal audit_schema = %q\n", stateSchema, manifestSchema, overrideSchema, managementAuditSchema)
	shared := preamble + commonScript + stateScript + overrideStateScript

	return map[string]string{
		scriptOverride:   shared + overrideScript,
		scriptAssessment: shared + assessmentScript, scriptMetadata: shared + metadataScript, scriptControl: shared + controlScript,
		scriptManifest: shared + manifestScript, scriptIngestion: shared + ingestionScript}
}
