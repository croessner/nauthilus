// Package adminui contains tests for admin UI helper services.
package adminui

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestNormalizeClickhouseHookPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty defaults", in: "", want: "/hooks/clickhouse-query"},
		{name: "already hook path", in: "/hooks/clickhouse-query", want: "/hooks/clickhouse-query"},
		{name: "api prefix stripped", in: "/api/v1/custom/hooks/clickhouse-query", want: "/hooks/clickhouse-query"},
		{name: "custom prefix stripped", in: "/custom/hooks/clickhouse-query", want: "/hooks/clickhouse-query"},
		{name: "missing leading slash", in: "hooks/clickhouse-query", want: "/hooks/clickhouse-query"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := normalizeClickhouseHookPath(tt.in)
			if got != tt.want {
				t.Fatalf("normalizeClickhouseHookPath() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParsePageAndSize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		pageIn       string
		pageSizeIn   string
		wantPage     int
		wantPageSize int
	}{
		{name: "defaults", pageIn: "", pageSizeIn: "", wantPage: 1, wantPageSize: 25},
		{name: "valid values", pageIn: "3", pageSizeIn: "50", wantPage: 3, wantPageSize: 50},
		{name: "invalid page falls back", pageIn: "-1", pageSizeIn: "25", wantPage: 1, wantPageSize: 25},
		{name: "invalid page size falls back", pageIn: "2", pageSizeIn: "30", wantPage: 2, wantPageSize: 25},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			page, size := parsePageAndSize(tt.pageIn, tt.pageSizeIn)
			if page != tt.wantPage || size != tt.wantPageSize {
				t.Fatalf("parsePageAndSize() = (%d, %d), want (%d, %d)", page, size, tt.wantPage, tt.wantPageSize)
			}
		})
	}
}

func TestProjectClickhouseQueryParams(t *testing.T) {
	t.Parallel()

	in := url.Values{}
	in.Set("action", "recent")
	in.Set("status", "all")
	in.Set("search", "alice")
	in.Set("filter", "username==\"alice\"")
	in.Set("tz", "Europe/Berlin")
	in.Set("limit", "999")
	in.Set("offset", "555")
	in.Set("ignored", "value")

	got := projectClickhouseQueryParams(in, 100, 26)

	if got.Get("action") != "recent" {
		t.Fatalf("action = %q, want %q", got.Get("action"), "recent")
	}

	if got.Get("status") != "all" {
		t.Fatalf("status = %q, want %q", got.Get("status"), "all")
	}

	if got.Get("search") != "alice" {
		t.Fatalf("search = %q, want %q", got.Get("search"), "alice")
	}

	if got.Get("tz") != "Europe/Berlin" {
		t.Fatalf("tz = %q, want %q", got.Get("tz"), "Europe/Berlin")
	}

	if got.Get("offset") != "100" {
		t.Fatalf("offset = %q, want %q", got.Get("offset"), "100")
	}

	if got.Get("limit") != "26" {
		t.Fatalf("limit = %q, want %q", got.Get("limit"), "26")
	}

	if got.Get("ignored") != "" {
		t.Fatalf("ignored should not be forwarded, got %q", got.Get("ignored"))
	}
}

func TestExtractClickhouseRows(t *testing.T) {
	t.Parallel()

	payload := map[string]any{
		"status": "success",
		"clickhouse": map[string]any{
			"query_result": map[string]any{
				"data": []any{
					map[string]any{"username": "alice"},
					map[string]any{"username": "bob"},
				},
			},
		},
	}

	rows := extractClickhouseRows(payload)
	if len(rows) != 2 {
		t.Fatalf("len(rows) = %d, want %d", len(rows), 2)
	}

	if rows[0]["username"] != "alice" {
		t.Fatalf("rows[0].username = %v, want %v", rows[0]["username"], "alice")
	}
}

func TestDefaultClickhouseServiceQuery_PaginationAndProjection(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/admin/api/clickhouse/query?page=2&page_size=25&action=recent&username=alice&ignored=yes", nil)

	service := &defaultClickhouseService{handler: buildClickhouseProjectionHandler(t)}

	result, err := service.Query(ctx)
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}

	assertClickhouseProjectionResult(t, result)
}

func buildClickhouseProjectionHandler(t *testing.T) gin.HandlerFunc {
	t.Helper()

	return func(child *gin.Context) {
		if child.Request.URL.Path != "/api/v1/custom/hooks/clickhouse-query" {
			t.Fatalf("hook path = %q, want %q", child.Request.URL.Path, "/api/v1/custom/hooks/clickhouse-query")
		}

		values := child.Request.URL.Query()
		if values.Get("offset") != "25" {
			t.Fatalf("offset = %q, want %q", values.Get("offset"), "25")
		}

		if values.Get("limit") != "26" {
			t.Fatalf("limit = %q, want %q", values.Get("limit"), "26")
		}

		if values.Get("ignored") != "" {
			t.Fatalf("ignored should not be forwarded, got %q", values.Get("ignored"))
		}

		child.JSON(http.StatusOK, gin.H{
			"clickhouse": gin.H{
				"query_result": gin.H{
					"data": clickhouseRows(26),
				},
			},
		})
	}
}

func clickhouseRows(count int) []any {
	rows := make([]any, 0, count)
	for i := range count {
		rows = append(rows, map[string]any{"idx": i})
	}

	return rows
}

func assertClickhouseProjectionResult(t *testing.T, result any) {
	t.Helper()

	response, ok := result.(gin.H)
	if !ok {
		t.Fatalf("result type = %T, want gin.H", result)
	}

	if response["page"] != 2 {
		t.Fatalf("page = %v, want %v", response["page"], 2)
	}

	if response["page_size"] != 25 {
		t.Fatalf("page_size = %v, want %v", response["page_size"], 25)
	}

	if response["has_more"] != true {
		t.Fatalf("has_more = %v, want %v", response["has_more"], true)
	}

	if response["offset"] != 25 {
		t.Fatalf("offset = %v, want %v", response["offset"], 25)
	}

	rows, ok := response["rows"].([]map[string]any)
	if !ok {
		t.Fatalf("rows type = %T, want []map[string]any", response["rows"])
	}

	if len(rows) != 25 {
		t.Fatalf("len(rows) = %d, want %d", len(rows), 25)
	}
}

func TestDefaultClickhouseServiceQuery_RespectsEndpointPath(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/admin/api/clickhouse/query?endpoint_path=/api/v1/custom/hooks/demo&page=1&page_size=10", nil)

	service := &defaultClickhouseService{
		handler: func(child *gin.Context) {
			if child.Request.URL.Path != "/api/v1/custom/hooks/demo" {
				t.Fatalf("hook path = %q, want %q", child.Request.URL.Path, "/api/v1/custom/hooks/demo")
			}

			if child.Param("hook") != "/hooks/demo" {
				t.Fatalf("hook param = %q, want %q", child.Param("hook"), "/hooks/demo")
			}

			child.JSON(http.StatusOK, gin.H{
				"query_result": gin.H{
					"data": []any{map[string]any{"ok": true}},
				},
			})
		},
	}

	result, err := service.Query(ctx)
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}

	response := result.(gin.H)
	rows := response["rows"].([]map[string]any)
	if len(rows) != 1 {
		t.Fatalf("len(rows) = %d, want %d", len(rows), 1)
	}
}

func TestDefaultClickhouseServiceQuery_HookFailure(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/admin/api/clickhouse/query", nil)

	service := &defaultClickhouseService{
		handler: func(child *gin.Context) {
			child.String(http.StatusInternalServerError, "boom")
		},
	}

	_, err := service.Query(ctx)
	if err == nil {
		t.Fatalf("Query() error = nil, want non-nil")
	}

	want := "clickhouse hook failed with status 500: boom"
	if err.Error() != want {
		t.Fatalf("error = %q, want %q", err.Error(), want)
	}
}

func TestDefaultClickhouseServiceQuery_InvalidPayload(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/admin/api/clickhouse/query", nil)

	service := &defaultClickhouseService{
		handler: func(child *gin.Context) {
			child.Data(http.StatusOK, "application/json", []byte("{broken"))
		},
	}

	_, err := service.Query(ctx)
	if err == nil {
		t.Fatalf("Query() error = nil, want non-nil")
	}
}

func TestDefaultClickhouseServiceQuery_EmptyEndpointPathUsesDefault(t *testing.T) {
	t.Parallel()

	gin.SetMode(gin.TestMode)

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/admin/api/clickhouse/query?endpoint_path=%20%20%20", nil)

	service := &defaultClickhouseService{
		handler: func(child *gin.Context) {
			child.JSON(http.StatusOK, gin.H{
				"query_result": gin.H{
					"data": []any{},
				},
			})
		},
	}

	result, err := service.Query(ctx)
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}

	response := result.(gin.H)
	if response["page"] != 1 || response["page_size"] != 25 {
		t.Fatalf("defaults not applied: page=%v page_size=%v", response["page"], response["page_size"])
	}
}

func TestConvertRowsSkipsInvalidEntries(t *testing.T) {
	t.Parallel()

	data := []any{
		map[string]any{"id": 1},
		"skip",
		map[string]any{"id": 2},
	}

	rows := convertRows(data)
	if len(rows) != 2 {
		t.Fatalf("len(rows) = %d, want %d", len(rows), 2)
	}

	for i, row := range rows {
		expected := i + 1
		if row["id"] != expected {
			t.Fatalf("row[%d].id = %v, want %v", i, row["id"], expected)
		}
	}
}

func TestRowsFromDataNode_JSONString(t *testing.T) {
	t.Parallel()

	input := fmt.Sprintf(`{"data":[{"idx":%s}]}`, strconv.Itoa(7))
	rows := rowsFromDataNode(input)

	if len(rows) != 1 {
		t.Fatalf("len(rows) = %d, want %d", len(rows), 1)
	}

	if rows[0]["idx"] != float64(7) {
		t.Fatalf("rows[0].idx = %v, want %v", rows[0]["idx"], float64(7))
	}
}
