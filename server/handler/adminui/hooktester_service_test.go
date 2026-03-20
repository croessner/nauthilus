package adminui

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestNormalizeHookTesterEndpointPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "plain hooks path", input: "/hooks/clickhouse-query", want: "/hooks/clickhouse-query"},
		{name: "custom prefix", input: "/custom/hooks/demo", want: "/hooks/demo"},
		{name: "api custom prefix", input: "/api/v1/custom/hooks/demo", want: "/hooks/demo"},
		{name: "adds leading slash", input: "hooks/demo", want: "/hooks/demo"},
		{name: "path traversal cleaned", input: "/hooks/a/../demo", want: "/hooks/demo"},
		{name: "empty rejected", input: " ", wantErr: true},
		{name: "non hooks rejected", input: "/metrics", wantErr: true},
		{name: "hooks root rejected", input: "/hooks", wantErr: true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := normalizeHookTesterEndpointPath(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("normalizeHookTesterEndpointPath() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr {
				return
			}

			if got != tt.want {
				t.Fatalf("normalizeHookTesterEndpointPath() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDefaultHookTesterServiceSend_TruncatesResponsePreview(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/admin/api/hooktester/send", bytes.NewBufferString(`{"method":"POST","endpoint_path":"/hooks/demo","body":"{}"}`))
	ctx.Request.Header.Set("Content-Type", "application/json")

	service := &defaultHookTesterService{
		handler: func(child *gin.Context) {
			body := bytes.Repeat([]byte("a"), hookTesterMaxResponsePreviewBytes+64)
			child.Header("Content-Type", "application/json")
			child.Data(http.StatusOK, "application/json", body)
		},
	}

	result, err := service.Send(ctx)
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	response, ok := result.(gin.H)
	if !ok {
		t.Fatalf("result type = %T, want gin.H", result)
	}

	if response["status"] != http.StatusOK {
		t.Fatalf("status = %v, want %v", response["status"], http.StatusOK)
	}

	if response["response_body_truncated"] != true {
		t.Fatalf("response_body_truncated = %v, want true", response["response_body_truncated"])
	}

	body, ok := response["response_body"].(string)
	if !ok {
		t.Fatalf("response_body type = %T, want string", response["response_body"])
	}

	if len(body) != hookTesterMaxResponsePreviewBytes {
		t.Fatalf("len(response_body) = %d, want %d", len(body), hookTesterMaxResponsePreviewBytes)
	}
}

func TestDefaultHookTesterServiceSend_RejectsForbiddenHeader(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(
		http.MethodPost,
		"/admin/api/hooktester/send",
		bytes.NewBufferString(`{"method":"GET","endpoint_path":"/hooks/demo","headers":{"Authorization":"Bearer x"}}`),
	)
	ctx.Request.Header.Set("Content-Type", "application/json")

	service := &defaultHookTesterService{
		handler: func(child *gin.Context) {
			child.JSON(http.StatusOK, gin.H{"ok": true})
		},
	}

	_, err := service.Send(ctx)
	if err == nil {
		t.Fatalf("Send() error = nil, want non-nil")
	}
}

func TestDefaultHookTesterServiceSend_RejectsOversizedBody(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	oversized := bytes.Repeat([]byte("b"), hookTesterMaxRequestBodyBytes+1)
	payload := `{"method":"POST","endpoint_path":"/hooks/demo","body":"` + string(oversized) + `"}`

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/admin/api/hooktester/send", bytes.NewBufferString(payload))
	ctx.Request.Header.Set("Content-Type", "application/json")

	service := &defaultHookTesterService{
		handler: func(child *gin.Context) {
			child.JSON(http.StatusOK, gin.H{"ok": true})
		},
	}

	_, err := service.Send(ctx)
	if err == nil {
		t.Fatalf("Send() error = nil, want non-nil")
	}
}
