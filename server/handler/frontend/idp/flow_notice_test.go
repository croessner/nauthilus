package idp

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/croessner/nauthilus/server/definitions"
	"github.com/gin-gonic/gin"
)

type capturedNoticeRecord struct {
	level   slog.Level
	message string
	attrs   map[string]string
}

type noticeCaptureHandler struct {
	records []capturedNoticeRecord
}

func (h *noticeCaptureHandler) Enabled(context.Context, slog.Level) bool {
	return true
}

func (h *noticeCaptureHandler) Handle(_ context.Context, record slog.Record) error {
	captured := capturedNoticeRecord{
		level:   record.Level,
		message: record.Message,
		attrs:   make(map[string]string, record.NumAttrs()),
	}

	record.Attrs(func(attr slog.Attr) bool {
		captured.attrs[attr.Key] = attr.Value.String()

		return true
	})

	h.records = append(h.records, captured)

	return nil
}

func (h *noticeCaptureHandler) WithAttrs([]slog.Attr) slog.Handler {
	return h
}

func (h *noticeCaptureHandler) WithGroup(string) slog.Handler {
	return h
}

type incomingNoticeTestCase struct {
	name           string
	remoteAddr     string
	trustedProxies []string
	headers        map[string]string
	wantClientIP   string
}

type completedNoticeTestCase struct {
	name           string
	remoteAddr     string
	trustedProxies []string
	headers        map[string]string
	httpStatus     int
	wantClientIP   string
	wantResult     string
	wantMessage    string
}

func TestLogIncomingIDPFlowRequestIncludesClientIP(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	testCases := []incomingNoticeTestCase{
		{
			name:         "direct client ip",
			remoteAddr:   "198.51.100.10:44321",
			wantClientIP: "198.51.100.10",
		},
		{
			name:           "trusted proxy forwarded ip",
			remoteAddr:     "127.0.0.1:44321",
			trustedProxies: []string{"127.0.0.1"},
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.10",
			},
			wantClientIP: "203.0.113.10",
		},
		{
			name:       "forwarded ip without trusted proxies",
			remoteAddr: "127.0.0.1:44321",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.10",
			},
			wantClientIP: "203.0.113.10",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			assertIncomingNoticeClientIP(t, testCase)
		})
	}
}

func assertIncomingNoticeClientIP(t *testing.T, testCase incomingNoticeTestCase) {
	t.Helper()

	logger, handler, ctx := newNoticeTestLoggerContext(t, testCase.remoteAddr, testCase.trustedProxies, testCase.headers)

	logIncomingIDPFlowRequest(ctx, logger, "oidc", "token", "client-1", "", "client_credentials")

	record := requireSingleNoticeRecord(t, handler)

	if got := record.attrs[definitions.LogKeyClientIP]; got != testCase.wantClientIP {
		t.Fatalf("client_ip mismatch: want %q got %q", testCase.wantClientIP, got)
	}
}

func TestLogCompletedIDPFlowRequestIncludesResultAndClientIP(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	testCases := []completedNoticeTestCase{
		{
			name:         "successful direct request",
			remoteAddr:   "198.51.100.10:44321",
			httpStatus:   http.StatusOK,
			wantClientIP: "198.51.100.10",
			wantResult:   "ok",
			wantMessage:  "IdP request was successful",
		},
		{
			name:           "failed trusted proxy request",
			remoteAddr:     "127.0.0.1:44321",
			trustedProxies: []string{"127.0.0.1"},
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.10",
			},
			httpStatus:   http.StatusBadRequest,
			wantClientIP: "203.0.113.10",
			wantResult:   "fail",
			wantMessage:  "IdP request has failed",
		},
		{
			name:       "successful forwarded request without trusted proxies",
			remoteAddr: "127.0.0.1:44321",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.10",
			},
			httpStatus:   http.StatusOK,
			wantClientIP: "203.0.113.10",
			wantResult:   "ok",
			wantMessage:  "IdP request was successful",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase

		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			assertCompletedNoticeResult(t, testCase)
		})
	}
}

func assertCompletedNoticeResult(t *testing.T, testCase completedNoticeTestCase) {
	t.Helper()

	logger, handler, ctx := newNoticeTestLoggerContext(t, testCase.remoteAddr, testCase.trustedProxies, testCase.headers)
	ctx.Status(testCase.httpStatus)

	logCompletedIDPFlowRequest(ctx, logger, "oidc", "token", "client-1", "", "client_credentials")

	record := requireSingleNoticeRecord(t, handler)

	if got := record.attrs[definitions.LogKeyClientIP]; got != testCase.wantClientIP {
		t.Fatalf("client_ip mismatch: want %q got %q", testCase.wantClientIP, got)
	}

	if got := record.attrs[definitions.LogKeyHTTPStatus]; got != strconv.Itoa(testCase.httpStatus) {
		t.Fatalf("http_status mismatch: want %q got %q", strconv.Itoa(testCase.httpStatus), got)
	}

	if got := record.attrs["result"]; got != testCase.wantResult {
		t.Fatalf("result mismatch: want %q got %q", testCase.wantResult, got)
	}

	if record.message != testCase.wantMessage {
		t.Fatalf("message mismatch: want %q got %q", testCase.wantMessage, record.message)
	}
}

func newNoticeTestLoggerContext(
	t *testing.T,
	remoteAddr string,
	trustedProxies []string,
	headers map[string]string,
) (*slog.Logger, *noticeCaptureHandler, *gin.Context) {
	t.Helper()

	handler := &noticeCaptureHandler{}
	logger := slog.New(handler)

	recorder := httptest.NewRecorder()
	ctx, engine := gin.CreateTestContext(recorder)

	if err := engine.SetTrustedProxies(trustedProxies); err != nil {
		t.Fatalf("SetTrustedProxies() failed: %v", err)
	}

	request := httptest.NewRequest(http.MethodPost, "/oidc/token", nil)
	request.RemoteAddr = remoteAddr

	for key, value := range headers {
		request.Header.Set(key, value)
	}

	ctx.Request = request
	ctx.Set(definitions.CtxGUIDKey, "guid-1")

	return logger, handler, ctx
}

func requireSingleNoticeRecord(t *testing.T, handler *noticeCaptureHandler) capturedNoticeRecord {
	t.Helper()

	if len(handler.records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(handler.records))
	}

	return handler.records[0]
}
