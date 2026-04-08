package idp

import (
	"testing"

	"github.com/croessner/nauthilus/server/definitions"
	devicecode "github.com/croessner/nauthilus/server/idp"
	"github.com/stretchr/testify/assert"
)

func TestApplyDeviceCodeMFASessionStateCopiesCompletedMethod(t *testing.T) {
	request := &devicecode.DeviceCodeRequest{}
	mgr := &mockCookieManager{data: map[string]any{
		definitions.SessionKeyMFACompleted: true,
		definitions.SessionKeyMFAMethod:    "webauthn",
	}}

	applyDeviceCodeMFASessionState(mgr, request)

	assert.True(t, request.MFACompleted)
	assert.Equal(t, "webauthn", request.MFAMethod)
}
