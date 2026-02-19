//go:build linux && cgo
// +build linux,cgo

package main

/*
#cgo LDFLAGS: -lpam
#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <syslog.h>
#include <stdlib.h>

// Forward declaration to keep the wrapper call portable across build environments.
int pam_get_user(pam_handle_t *pamh, const char **user, const char *prompt);

// nauthilus_pam_info wraps pam_prompt to emit informational messages to the user.
static int nauthilus_pam_info(pam_handle_t *pamh, const char *message) {
    return pam_prompt(pamh, PAM_TEXT_INFO, NULL, "%s", message);
}

// nauthilus_pam_get_user wraps pam_get_user to avoid cgo varargs handling.
static int nauthilus_pam_get_user(pam_handle_t *pamh, const char **user) {
    return pam_get_user(pamh, user, NULL);
}

// nauthilus_pam_syslog wraps pam_syslog to provide a non-variadic entry point for cgo.
static void nauthilus_pam_syslog(pam_handle_t *pamh, int priority, const char *message) {
    pam_syslog(pamh, priority, "%s", message);
}
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unsafe"
)

// main is required for c-shared builds even though this module is loaded by PAM.
func main() {}

// pam_sm_authenticate executes the Device Code flow and validates the user claim.
//
//export pam_sm_authenticate
func pam_sm_authenticate(pamh *C.pam_handle_t, flags C.int, argc C.int, argv **C.char) C.int {
	args := pamArgs(argc, argv)

	settings, err := parseArgs(args)
	if err != nil {
		pamLog(pamh, C.LOG_ERR, "pam_nauthilus config error: %v", err)

		return C.PAM_SERVICE_ERR
	}

	username, err := pamUser(pamh)
	if err != nil {
		pamLog(pamh, C.LOG_ERR, "pam_nauthilus user error: %v", err)

		return C.PAM_SERVICE_ERR
	}

	flow, err := NewDeviceFlow(settings, nil, nil)
	if err != nil {
		pamLog(pamh, C.LOG_ERR, "pam_nauthilus flow init error: %v", err)

		return C.PAM_SERVICE_ERR
	}

	ctx, cancel := context.WithTimeout(context.Background(), settings.Timeout)
	defer cancel()

	device, err := flow.StartDeviceAuthorization(ctx)
	if err != nil {
		pamLog(pamh, C.LOG_ERR, "pam_nauthilus device authorization failed")

		return C.PAM_AUTH_ERR
	}

	showDeviceInstruction(pamh, device)

	deadline := resolveDeadline(ctx, flow.clock.Now(), device.ExpiresIn)
	if deadline.IsZero() {
		deadline = flow.clock.Now().Add(settings.Timeout)
	}

	token, err := flow.PollToken(ctx, device.DeviceCode, device.Interval, deadline)
	if err != nil {
		return handleAuthError(pamh, err)
	}

	if err := flow.VerifyTokenSignature(ctx, token.AccessToken); err != nil {
		pamLog(pamh, C.LOG_ERR, "pam_nauthilus JWKS signature verification failed")

		return handleAuthError(pamh, err)
	}

	if err := flow.IntrospectToken(ctx, token.AccessToken); err != nil {
		pamLog(pamh, C.LOG_ERR, "pam_nauthilus token introspection failed")

		return handleAuthError(pamh, err)
	}

	claims, err := flow.FetchUserInfo(ctx, token.AccessToken)
	if err != nil {
		pamLog(pamh, C.LOG_ERR, "pam_nauthilus userinfo failed")

		return C.PAM_AUTH_ERR
	}

	if err := flow.VerifyUser(claims, username); err != nil {
		return handleAuthError(pamh, err)
	}

	return C.PAM_SUCCESS
}

// pam_sm_setcred is a no-op credential handler required by the PAM module API.
//
//export pam_sm_setcred
func pam_sm_setcred(pamh *C.pam_handle_t, flags C.int, argc C.int, argv **C.char) C.int {
	return C.PAM_SUCCESS
}

// pamArgs converts PAM arguments to Go strings.
func pamArgs(argc C.int, argv **C.char) []string {
	if argc == 0 || argv == nil {
		return nil
	}

	items := unsafe.Slice(argv, int(argc))
	args := make([]string, 0, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}

		args = append(args, C.GoString(item))
	}

	return args
}

// pamUser retrieves the PAM username from the current session.
func pamUser(pamh *C.pam_handle_t) (string, error) {
	var user *C.char
	if C.nauthilus_pam_get_user(pamh, (**C.char)(unsafe.Pointer(&user))) != C.PAM_SUCCESS {
		return "", errors.New("pam_get_user failed")
	}

	if user == nil {
		return "", errors.New("pam user is empty")
	}

	return C.GoString(user), nil
}

// pamLog writes a formatted message to PAM syslog.
func pamLog(pamh *C.pam_handle_t, level C.int, format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	cstring := C.CString(message)
	defer C.free(unsafe.Pointer(cstring))

	C.nauthilus_pam_syslog(pamh, level, cstring)
}

// pamInfo shows a formatted message to the user through the PAM conversation.
func pamInfo(pamh *C.pam_handle_t, format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	cstring := C.CString(message)
	defer C.free(unsafe.Pointer(cstring))

	_ = C.nauthilus_pam_info(pamh, cstring)
}

// showDeviceInstruction prints the verification URL and user code to the user.
func showDeviceInstruction(pamh *C.pam_handle_t, device DeviceAuthorization) {
	verificationURI := device.VerificationURI
	if verificationURI == "" {
		verificationURI = device.VerificationURIComplete
	}

	if verificationURI != "" {
		pamInfo(pamh, "Open %s to approve the login.", verificationURI)
	}

	if device.UserCode != "" {
		pamInfo(pamh, "Enter this code in the browser: %s", device.UserCode)
	}
}

// resolveDeadline combines the device expiry and context deadline into a single deadline.
func resolveDeadline(ctx context.Context, now time.Time, expiresIn time.Duration) time.Time {
	deadline := time.Time{}
	if expiresIn > 0 {
		deadline = now.Add(expiresIn)
	}

	if ctxDeadline, ok := ctx.Deadline(); ok {
		if deadline.IsZero() || ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}
	}

	return deadline
}

// handleAuthError maps flow errors to PAM return codes and logs them.
func handleAuthError(pamh *C.pam_handle_t, err error) C.int {
	switch {
	case errors.Is(err, ErrTimeout):
		pamLog(pamh, C.LOG_NOTICE, "pam_nauthilus authentication timed out")
		return C.PAM_AUTH_ERR
	case errors.Is(err, ErrAccessDenied):
		pamLog(pamh, C.LOG_NOTICE, "pam_nauthilus authentication denied")
		return C.PAM_AUTH_ERR
	case errors.Is(err, ErrUserMismatch):
		pamLog(pamh, C.LOG_NOTICE, "pam_nauthilus user claim mismatch")
		return C.PAM_AUTH_ERR
	case errors.Is(err, ErrInvalidSignature):
		pamLog(pamh, C.LOG_NOTICE, "pam_nauthilus token signature invalid")
		return C.PAM_AUTH_ERR
	case errors.Is(err, ErrTokenInactive):
		pamLog(pamh, C.LOG_NOTICE, "pam_nauthilus token not active")
		return C.PAM_AUTH_ERR
	default:
		pamLog(pamh, C.LOG_ERR, "pam_nauthilus internal error: %v", err)
		return C.PAM_SERVICE_ERR
	}
}
