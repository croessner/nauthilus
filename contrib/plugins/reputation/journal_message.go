package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"io"
	"time"

	pluginapi "github.com/croessner/nauthilus/v4/pluginapi/v1"
)

const journalSchema = "reputation-journal.v1"

type journalMessage struct {
	Topic      string
	Schema     string
	Allocation string
	Payload    string
	Expires    float64
}

type journalEnvelope struct {
	Message       journalMessage
	Authenticator string
}

type journalCodec struct {
	tagger pluginapi.OpaqueIdentifierTagger
	scope  string
	topic  string
}

// authenticate binds the entire detached contribution, allocation and absolute replay deadline.
func (c journalCodec) authenticate(ctx context.Context, message journalMessage) (string, error) {
	encoded, err := json.Marshal(message)
	if err != nil {
		return "", errManifestPlan
	}

	tag, err := c.tagger.Tag(ctx, pluginapi.OpaqueIdentifierInput{Scope: c.scope, Kind: "journal", Value: string(encoded)})
	if err != nil {
		return "", errStateUnavailable
	}

	return tag.String(), nil
}

// encode seals an already admitted immutable plan without retaining raw observation inputs.
func (c journalCodec) encode(ctx context.Context, allocation, payload string, expiry float64) ([]byte, error) {
	message := journalMessage{Schema: journalSchema, Topic: c.topic, Allocation: allocation, Payload: payload, Expires: expiry}

	authenticator, err := c.authenticate(ctx, message)
	if err != nil {
		return nil, err
	}

	encoded, err := json.Marshal(journalEnvelope{Message: message, Authenticator: authenticator})
	if err != nil || len(encoded) > maximumJournalRecordBytes {
		return nil, errManifestPlan
	}

	return encoded, nil
}

// decode verifies the sealed record before allowing any Redis mutation or replay.
func (c journalCodec) decode(ctx context.Context, key string, encoded []byte, now time.Time) (journalMessage, error) {
	if len(encoded) == 0 || len(encoded) > maximumJournalRecordBytes {
		return journalMessage{}, errManifestPlan
	}

	var envelope journalEnvelope

	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(&envelope); err != nil || decoder.Decode(new(any)) != io.EOF {
		return journalMessage{}, errManifestPlan
	}

	message := envelope.Message
	if !message.valid(key) || message.Topic != c.topic {
		return journalMessage{}, errManifestPlan
	}

	expected, err := c.authenticate(ctx, message)
	if err != nil {
		return journalMessage{}, err
	}

	if subtle.ConstantTimeCompare([]byte(expected), []byte(envelope.Authenticator)) != 1 {
		return journalMessage{}, errManifestPlan
	}

	if message.Expires <= float64(now.UnixNano())/1e9 {
		return journalMessage{}, errEventTime
	}

	return message, nil
}

// valid enforces bounded envelope fields before authenticating detached content.
func (m journalMessage) valid(key string) bool {
	return m.Schema == journalSchema && m.Allocation == key && len(key) > 0 && len(key) <= 128 &&
		len(m.Payload) > 0 && len(m.Payload) <= maximumManifestPayload && positiveBound(m.Expires, 1e11)
}
