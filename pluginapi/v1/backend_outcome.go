package pluginapi

import (
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// BackendOutcomeStatus identifies independent credential verification evidence.
type BackendOutcomeStatus string

// Closed independent credential verification outcomes.
const (
	BackendOutcomeAuthenticated  BackendOutcomeStatus = "authenticated"
	BackendOutcomeBadCredentials BackendOutcomeStatus = "bad_credentials"
)

// BackendOutcomeView retains host-captured evidence before subject or Policy mutations.
// Its zero value means no independent credential result was observed.
type BackendOutcomeView struct {
	eventID    string
	account    string
	observedAt time.Time
	status     BackendOutcomeStatus
}

// NewBackendOutcomeView captures bounded host metadata without credentials or final Policy outcomes.
func NewBackendOutcomeView(eventID, account string, status BackendOutcomeStatus, observedAt time.Time) (BackendOutcomeView, error) {
	if eventID == "" || len(eventID) > 128 || len(account) > 1024 || !utf8.ValidString(eventID) ||
		!utf8.ValidString(account) || strings.ContainsFunc(eventID, unicode.IsControl) ||
		strings.ContainsFunc(account, unicode.IsControl) || observedAt.IsZero() ||
		(status != BackendOutcomeAuthenticated && status != BackendOutcomeBadCredentials) {
		return BackendOutcomeView{}, invalidDecisionContract("backend outcome", "contains invalid host evidence")
	}

	return BackendOutcomeView{eventID: eventID, account: account, status: status, observedAt: observedAt.UTC()}, nil
}

// Observed reports whether the host captured an independent backend result.
func (v BackendOutcomeView) Observed() bool { return v.eventID != "" }

// EventID returns the stable host request identity.
func (v BackendOutcomeView) EventID() string { return v.eventID }

// Account returns the backend-normalized account before later subject patches.
func (v BackendOutcomeView) Account() string { return v.account }

// Status returns only the original credential verification result.
func (v BackendOutcomeView) Status() BackendOutcomeStatus { return v.status }

// ObservedAt returns the host capture time by value.
func (v BackendOutcomeView) ObservedAt() time.Time { return v.observedAt }
