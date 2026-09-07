package main

import (
	"bytes"
	"errors"
	projection "github.com/croessner/nauthilus/v4/contrib/plugins/internal/dkim2projection"
	view "github.com/croessner/nauthilus/v4/contrib/plugins/internal/reputationview"
	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

var errCorrelation = errors.New("incomplete or mismatched DKIM2 evidence correlation")

type assessedSubject struct {
	binding            []byte
	tuple              view.Tuple
	role, kind, domain string
	sequence, instance int64
}

type correlatedSubjects struct {
	signers []view.Tuple
	peers   map[string]view.Tuple
}

// correlateSubjects requires exact ordered signer coverage and preserves independent current-peer tuples.
func correlateSubjects(source projection.Projection, subjects []assessedSubject, profile string) (correlatedSubjects, error) {
	result := correlatedSubjects{peers: make(map[string]view.Tuple)}
	if len(source.Chain) < 1 || len(source.Chain) > maximumChainRecords || len(subjects) > maximumChainRecords+3 {
		return result, errCorrelation
	}

	last := source.Chain[len(source.Chain)-1]
	if last.Sequence != source.TargetSequence || last.MessageInstance != source.TargetMessageInstance {
		return result, errCorrelation
	}

	for _, subject := range subjects {
		if err := result.addSubject(source.Chain, subject, profile); err != nil {
			return correlatedSubjects{}, err
		}
	}

	if len(result.signers) != len(source.Chain) {
		return correlatedSubjects{}, errCorrelation
	}

	for _, kind := range []string{valueIP, valueNetwork, valueAsn} {
		if _, present := result.peers[kind]; !present {
			result.peers[kind] = view.Tuple{State: view.Unavailable, Profile: profile, Band: view.Unavailable, Override: view.NoOverride}
		}
	}

	return result, nil
}

// matchesSigner binds the domain assessment to the exact verifier record, never merely a repeated domain name.
func matchesSigner(hop projection.Hop, subject assessedSubject) bool {
	return subject.kind == "dns_domain" && subject.sequence == hop.Sequence && subject.instance == hop.MessageInstance &&
		subject.domain == hop.SignerDomain && len(subject.binding) == 32 && bytes.Equal(subject.binding, hop.HopBinding)
}

// peerSubjectKind closes role-to-identity mapping for the current SMTP peer.
func peerSubjectKind(role string) (string, bool) {
	switch role {
	case "smtp_peer_ip":
		return valueIP, true
	case "smtp_peer_network":
		return valueNetwork, true
	case "smtp_peer_asn":
		return valueAsn, true
	default:
		return "", false
	}
}

// decodeSubjects rejects unknown or partial assessment records before any correlation output is built.
func decodeSubjects(value pluginapi.DecisionValue) ([]assessedSubject, error) {
	list, ok := value.Records()
	if !ok || len(list.Records()) > maximumChainRecords+3 {
		return nil, errCorrelation
	}

	subjects := make([]assessedSubject, 0, len(list.Records()))
	for _, record := range list.Records() {
		subject, err := decodeSubject(record)
		if err != nil {
			return nil, err
		}

		subjects = append(subjects, subject)
	}

	return subjects, nil
}

// decodeSubject separates exact identity metadata from the shared closed tuple decoder.
func decodeSubject(record pluginapi.DecisionRecord) (assessedSubject, error) {
	fields := recordFields(record)

	role, ok := fields[valueRole].Value().StringValue()
	if !ok {
		return assessedSubject{}, errCorrelation
	}

	kind, ok := fields[valueKind].Value().StringValue()
	if !ok {
		return assessedSubject{}, errCorrelation
	}

	delete(fields, valueRole)
	delete(fields, valueKind)

	result := assessedSubject{role: role, kind: kind}
	if role == valueSigner {
		if err := decodeSignerIdentity(fields, &result); err != nil {
			return assessedSubject{}, err
		}
	} else if _, valid := peerSubjectKind(role); !valid {
		return assessedSubject{}, errCorrelation
	}

	tuple, err := view.Decode(fields)
	if err != nil {
		return assessedSubject{}, err
	}

	result.tuple = tuple

	return result, nil
}

// decodeSignerIdentity consumes the complete record-local binding metadata without exposing subject tags.
func decodeSignerIdentity(fields map[string]pluginapi.DecisionRecordFieldValue, result *assessedSubject) error {
	var ok bool

	result.sequence, ok = fields[valueSequence].Value().Integer()
	if !ok {
		return errCorrelation
	}

	result.instance, ok = fields[valueMessageInstance].Value().Integer()
	if !ok {
		return errCorrelation
	}

	result.binding, ok = fields[valueHopBinding].Value().Bytes()
	if !ok || len(result.binding) != 32 {
		return errCorrelation
	}

	result.domain, ok = fields[valueSignerDomain].Value().StringValue()
	if !ok || !projection.CanonicalDomain(result.domain) {
		return errCorrelation
	}

	for _, name := range []string{valueSequence, valueMessageInstance, valueHopBinding, valueSignerDomain} {
		delete(fields, name)
	}

	return nil
}

// recordFields creates an owned map from the immutable unique-field record contract.
func recordFields(record pluginapi.DecisionRecord) map[string]pluginapi.DecisionRecordFieldValue {
	fields := make(map[string]pluginapi.DecisionRecordFieldValue, len(record.Fields()))
	for _, field := range record.Fields() {
		fields[field.Name()] = field.Value()
	}

	return fields
}

// addSubject validates one ordered signer or one independent peer assessment.
func (r *correlatedSubjects) addSubject(chain []projection.Hop, subject assessedSubject, profile string) error {
	if subject.tuple.Profile != profile || subject.tuple.Validate() != nil {
		return errCorrelation
	}

	if subject.role == valueSigner {
		if len(r.signers) >= len(chain) || !matchesSigner(chain[len(r.signers)], subject) {
			return errCorrelation
		}

		r.signers = append(r.signers, subject.tuple)

		return nil
	}

	kind, valid := peerSubjectKind(subject.role)
	if !valid || !subject.validPeerIdentity(kind) {
		return errCorrelation
	}

	if _, duplicate := r.peers[kind]; duplicate {
		return errCorrelation
	}

	r.peers[kind] = subject.tuple

	return nil
}

// validPeerIdentity excludes all historical signer metadata from a current-peer tuple.
func (s assessedSubject) validPeerIdentity(kind string) bool {
	return s.kind == kind && s.sequence == 0 && s.instance == 0 && s.domain == "" && len(s.binding) == 0
}
