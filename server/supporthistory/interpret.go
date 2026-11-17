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

package supporthistory

import "strings"

// Stages of an interpreted event.
const (
	stagePrimary       = "primary_authentication"
	stageSecondFactor  = "second_factor"
	stagePreCredential = "pre_credential"
	stageLegacy        = "legacy"
)

// Results of an interpreted event.
const (
	resultSucceeded      = "succeeded"
	resultRejected       = "rejected"
	resultTechnicalError = "technical_error"
	resultUnknown        = "unknown"
	resultAccepted       = "accepted"
	resultInvalid        = "invalid"
	resultRateLimited    = "rate_limited"
	resultStateRejected  = "state_rejected"
)

// Categories of an interpreted event or finding.
const (
	categorySuccess       = "success"
	categoryCredential    = "credential"
	categorySecondFactor  = "second_factor"
	categoryPreCredential = "pre_credential"
	categoryPolicy        = "policy"
	categoryTechnical     = "technical"
	categoryFlowState     = "flow_state"
	categoryUnknown       = "unknown"
)

// Contract values (DIAGNOSTIC_CONTRACT.md §4, §7).
const (
	outcomeOK       = "ok"
	outcomeFail     = "fail"
	outcomeTempfail = "tempfail"

	stagePreAuth = "pre_auth"

	markerAuthFailure      = "auth.outcome.auth_failure"
	markerEmptyPassword    = "auth.outcome.empty_password"
	markerEmptyUsername    = "auth.outcome.empty_username"
	markerBruteForceReject = "auth.outcome.brute_force_reject"
	markerRBLReject        = "auth.outcome.rbl_reject"
	markerRelayReject      = "auth.outcome.relay_domain_reject"
	markerTLSRequired      = "auth.outcome.tls_required"

	tempfailBackend     = "backend_tempfail"
	tempfailBruteForce  = "brute_force_error"
	tempfailPolicy      = "policy_indeterminate"
	tempfailFSMGuard    = "auth_fsm_guard"
	tempfailEnvironment = "environment_tempfail"

	eventTypeMFA           = "mfa.verification"
	supportedEventVersion  = 1
	factorRoleSecond       = "second_factor"
	flowEffectCompleted    = "step_up_completed"
	flowEffectFailureKept  = "primary_failure_kept"
	eventResultSuccess     = "success"
	eventResultInvalid     = "invalid"
	eventResultError       = "error"
	eventResultRateLimited = "rate_limited"
	eventResultRejected    = "rejected"
	reasonInvalidCode      = "invalid_code"
	reasonAssertion        = "assertion_rejected"
)

// Event and finding codes. They are the stable interface for UIs.
const (
	CodePrimarySucceeded        = "PRIMARY_AUTHENTICATION_SUCCEEDED"
	CodeAuthenticationAccepted  = "AUTHENTICATION_ACCEPTED"
	CodeCredentialsRejected     = "CREDENTIALS_REJECTED"
	CodeCredentialsIncomplete   = "CREDENTIALS_INCOMPLETE"
	CodeBruteForceRejected      = "REJECTED_BY_BRUTE_FORCE_PROTECTION"
	CodeRBLRejected             = "REJECTED_BY_RBL"
	CodeRelayDomainRejected     = "REJECTED_BY_RELAY_DOMAIN_POLICY"
	CodeEnvironmentRejected     = "REJECTED_BY_ENVIRONMENT_CONTROL"
	CodePreCredentialRejected   = "REJECTED_BEFORE_CREDENTIAL_CHECK"
	CodeSubjectRejected         = "REJECTED_BY_SUBJECT_CONTROL"
	CodePolicyRejected          = "REJECTED_BY_POLICY"
	CodeTLSRequired             = "REJECTED_TLS_REQUIRED"
	CodeTechnicalBackend        = "TECHNICAL_ERROR_BACKEND"
	CodeTechnicalBruteForce     = "TECHNICAL_ERROR_BRUTE_FORCE"
	CodeTechnicalPolicy         = "TECHNICAL_ERROR_POLICY"
	CodeTechnicalInternal       = "TECHNICAL_ERROR_INTERNAL_GUARD"
	CodeTechnicalEnvironment    = "TECHNICAL_ERROR_ENVIRONMENT"
	CodeTechnical               = "TECHNICAL_ERROR"
	CodeOutcomeNotRecorded      = "OUTCOME_NOT_RECORDED"
	CodeLegacyUninterpreted     = "LEGACY_UNINTERPRETED"
	CodeFactorAccepted          = "SECOND_FACTOR_ACCEPTED"
	CodeFactorVerifiedKept      = "SECOND_FACTOR_VERIFIED_PRIMARY_FAILURE_KEPT"
	CodeFactorRejected          = "SECOND_FACTOR_REJECTED"
	CodeFactorChallengeMissing  = "SECOND_FACTOR_CHALLENGE_UNAVAILABLE"
	CodeFactorTechnical         = "SECOND_FACTOR_TECHNICAL_ERROR"
	CodeFactorAttemptLimit      = "SECOND_FACTOR_ATTEMPT_LIMIT"
	CodeFlowStateError          = "FLOW_STATE_ERROR"
	CodeStepUpConflict          = "STEP_UP_CONFLICT"
	CodeStepUpExpired           = "STEP_UP_EXPIRED"
	CodeFlowResumeConflict      = "FLOW_RESUME_CONFLICT"
	CodeFactorUnclassified      = "SECOND_FACTOR_UNCLASSIFIED"
	CodeFactorOnLatchedFlow     = "SECOND_FACTOR_ON_LATCHED_FLOW"
	CodeUnsupportedEventVersion = "UNSUPPORTED_EVENT_VERSION"
)

// Uncertainty codes attached to findings whose recorded value can hide another cause.
const (
	uncertainTOTPVerifierError   = "TOTP_INVALID_MAY_INCLUDE_VERIFIER_ERROR"
	uncertainRecoveryInTOTPForm  = "RECOVERY_CODE_IN_TOTP_FORM_REPORTED_AS_TOTP"
	uncertainRecoveryReuse       = "RECOVERY_CODE_REUSE_NOT_DISTINGUISHABLE"
	uncertainWebAuthnHelper      = "WEBAUTHN_HELPER_FAILURES_REPORTED_AS_REJECTED"
	uncertainCredentialNotRecord = "CREDENTIAL_RESULT_NOT_RECORDED"
	uncertainUnknownVsWrong      = "UNKNOWN_USER_AND_WRONG_PASSWORD_NOT_DISTINGUISHED"
)

// interpretation is the contract reading of one record.
type interpretation struct {
	uncertainty []string
	stage       string
	result      string
	code        string
	category    string
	finding     bool
}

// simple builds an interpretation that is also a finding when it is not a success.
func simple(stage, result, code, category string, uncertainty ...string) interpretation {
	return interpretation{stage: stage, result: result, code: code, category: category,
		finding: category != categorySuccess, uncertainty: uncertainty}
}

// interpretLogin reads one login row under the terminal outcome contract (§4.3); legacy rows get no cause.
func interpretLogin(record LoginRecord, kind AttemptKind) interpretation {
	if record.ContractVersion < 1 {
		return interpretation{stage: stageLegacy, result: resultUnknown, code: CodeLegacyUninterpreted,
			category: categoryUnknown}
	}

	switch record.Outcome {
	case outcomeOK:
		if kind == AttemptFlow {
			return simple(stagePrimary, resultSucceeded, CodePrimarySucceeded, categorySuccess)
		}

		return simple(stagePrimary, resultSucceeded, CodeAuthenticationAccepted, categorySuccess)
	case outcomeFail:
		return interpretFailure(record)
	case outcomeTempfail:
		return interpretTempfail(record)
	default:
		return simple(stagePrimary, resultUnknown, CodeOutcomeNotRecorded, categoryUnknown)
	}
}

// interpretFailure separates credential failures from rejections before or beside the credential check.
func interpretFailure(record LoginRecord) interpretation {
	switch marker := record.OutcomeMarker; {
	case marker == markerAuthFailure:
		return simple(stagePrimary, resultRejected, CodeCredentialsRejected, categoryCredential, uncertainUnknownVsWrong)
	case marker == markerEmptyPassword || marker == markerEmptyUsername:
		return simple(stagePrimary, resultRejected, CodeCredentialsIncomplete, categoryCredential)
	case marker == markerBruteForceReject:
		return simple(stagePreCredential, resultRejected, CodeBruteForceRejected, categoryPreCredential)
	case marker == markerRBLReject:
		return simple(stagePreCredential, resultRejected, CodeRBLRejected, categoryPreCredential)
	case marker == markerRelayReject:
		return simple(stagePreCredential, resultRejected, CodeRelayDomainRejected, categoryPreCredential)
	case strings.Contains(marker, "_environment.") && strings.HasSuffix(marker, ".reject"):
		return simple(stagePreCredential, resultRejected, CodeEnvironmentRejected, categoryPreCredential)
	case record.OutcomeStage == stagePreAuth:
		return simple(stagePreCredential, resultRejected, CodePreCredentialRejected, categoryPreCredential)
	case strings.Contains(marker, "_subject.") && strings.HasSuffix(marker, ".reject"):
		return simple(stagePrimary, resultRejected, CodeSubjectRejected, categoryPolicy, uncertainCredentialNotRecord)
	default:
		return simple(stagePrimary, resultRejected, CodePolicyRejected, categoryPolicy, uncertainCredentialNotRecord)
	}
}

// interpretTempfail separates deliberate TLS rejections from technical failures.
func interpretTempfail(record LoginRecord) interpretation {
	stage := stagePrimary
	if record.OutcomeStage == stagePreAuth {
		stage = stagePreCredential
	}

	switch {
	case record.OutcomeMarker == markerTLSRequired:
		return simple(stagePreCredential, resultRejected, CodeTLSRequired, categoryPreCredential)
	case record.TempFailReason == tempfailBackend:
		return simple(stagePrimary, resultTechnicalError, CodeTechnicalBackend, categoryTechnical)
	case record.TempFailReason == tempfailBruteForce:
		return simple(stagePreCredential, resultTechnicalError, CodeTechnicalBruteForce, categoryTechnical)
	case record.TempFailReason == tempfailPolicy:
		return simple(stage, resultTechnicalError, CodeTechnicalPolicy, categoryTechnical)
	case record.TempFailReason == tempfailFSMGuard:
		return simple(stage, resultTechnicalError, CodeTechnicalInternal, categoryTechnical)
	case record.TempFailReason == tempfailEnvironment:
		return simple(stage, resultTechnicalError, CodeTechnicalEnvironment, categoryTechnical)
	default:
		return simple(stage, resultTechnicalError, CodeTechnical, categoryTechnical)
	}
}

// mfaReading maps one (result, reason) pair of the observable MFA outcomes table (§7.4).
type mfaReading struct {
	result   string
	code     string
	category string
}

// mfaReadings is the complete §7.4 table; unknown pairs stay unclassified.
var mfaReadings = map[[2]string]mfaReading{
	{eventResultInvalid, reasonInvalidCode}:      {resultInvalid, CodeFactorRejected, categorySecondFactor},
	{eventResultInvalid, reasonAssertion}:        {resultInvalid, CodeFactorRejected, categorySecondFactor},
	{eventResultInvalid, "ceremony_unavailable"}: {resultStateRejected, CodeFactorChallengeMissing, categoryFlowState},
	{eventResultError, "verifier_error"}:         {resultTechnicalError, CodeFactorTechnical, categoryTechnical},
	{eventResultError, "attempt_store_error"}:    {resultTechnicalError, CodeFactorTechnical, categoryTechnical},
	{eventResultError, "state_error"}:            {resultTechnicalError, CodeFlowStateError, categoryTechnical},
	{eventResultRateLimited, "attempt_limit"}:    {resultRateLimited, CodeFactorAttemptLimit, categorySecondFactor},
	{eventResultRejected, "step_up_conflict"}:    {resultStateRejected, CodeStepUpConflict, categoryFlowState},
	{eventResultRejected, "step_up_expired"}:     {resultStateRejected, CodeStepUpExpired, categoryFlowState},
	{eventResultRejected, "resume_conflict"}:     {resultStateRejected, CodeFlowResumeConflict, categoryFlowState},
	{eventResultSuccess, "verified"}:             {resultAccepted, CodeFactorAccepted, categorySuccess},
	{eventResultSuccess, flowEffectFailureKept}:  {resultAccepted, CodeFactorVerifiedKept, categoryCredential},
}

// interpretAuthEvent reads one second-factor event; a factor attempt is never a terminal flow failure.
func interpretAuthEvent(record AuthEventRecord) interpretation {
	if record.EventType != eventTypeMFA || record.EventVersion != supportedEventVersion ||
		record.FactorRole != factorRoleSecond {
		return interpretation{stage: stageSecondFactor, result: resultUnknown, code: CodeUnsupportedEventVersion,
			category: categoryUnknown, finding: true}
	}

	key := [2]string{record.Result, record.Reason}
	if record.Result == eventResultSuccess && record.FlowEffect == flowEffectFailureKept {
		key[1] = flowEffectFailureKept
	}

	reading, ok := mfaReadings[key]
	if !ok {
		return simple(stageSecondFactor, resultUnknown, CodeFactorUnclassified, categoryUnknown)
	}

	result := simple(stageSecondFactor, reading.result, reading.code, reading.category, factorUncertainty(record)...)
	if reading.code == CodeFactorVerifiedKept {
		result.finding = true
	}

	return result
}

// factorUncertainty names the documented verifier limits that can hide another cause behind a rejection (§7.4).
func factorUncertainty(record AuthEventRecord) []string {
	if record.Result != eventResultInvalid {
		return nil
	}

	switch {
	case record.Method == "totp" && record.Reason == reasonInvalidCode:
		return []string{uncertainTOTPVerifierError, uncertainRecoveryInTOTPForm}
	case record.Method == "recovery_codes" && record.Reason == reasonInvalidCode:
		return []string{uncertainRecoveryReuse}
	case record.Method == "webauthn" && record.Reason == reasonAssertion:
		return []string{uncertainWebAuthnHelper}
	default:
		return nil
	}
}
