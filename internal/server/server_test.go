package server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/YarKhan02/PathWise/internal/report"
	"github.com/YarKhan02/PathWise/internal/server"
)

func TestHandlerFuzzEndpoint(t *testing.T) {
	var gotReq server.FuzzRequest
	runner := func(_ context.Context, req server.FuzzRequest) ([]server.FuzzFinding, error) {
		gotReq = req
		return []server.FuzzFinding{{Endpoint: "POST /assignments", Kind: "write_read_inconsistency", Payload: "missing:title", Detail: "accepted, read failed"}}, nil
	}
	h := server.Handler(server.BuildScan(&report.Report{Project: "demo", ScanID: "s1"}), nil, nil, runner)

	body := `{"baseUrl":"http://localhost:8080","token":"t","endpoints":["POST /assignments"]}`
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/fuzz", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("/api/fuzz status = %d (%s)", rec.Code, rec.Body)
	}

	// The request decoded, including the token and the explicit selection.
	if gotReq.Token != "t" || len(gotReq.Endpoints) != 1 || gotReq.Endpoints[0] != "POST /assignments" {
		t.Errorf("runner received %+v", gotReq)
	}
	var out []server.FuzzFinding
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode breaks: %v", err)
	}
	if len(out) != 1 || out[0].Kind != "write_read_inconsistency" {
		t.Errorf("breaks = %+v", out)
	}

	// A GET to the fuzz endpoint is rejected — fuzzing only runs on POST.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/fuzz", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /api/fuzz status = %d, want 405", rec.Code)
	}
}

// TestHandlerNoFuzzRunner is the negative control: with no runner injected, the
// fuzz endpoint is not registered and falls through to the SPA, never 200 JSON.
func TestHandlerNoFuzzRunner(t *testing.T) {
	h := server.Handler(server.BuildScan(&report.Report{Project: "demo", ScanID: "s1"}), nil, nil, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/fuzz", strings.NewReader(`{}`)))
	// The catch-all serves index.html (or 501 if assets are absent), never the
	// fuzz handler's JSON.
	if rec.Code == http.StatusOK && strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		t.Errorf("fuzz endpoint must not be active without a runner")
	}
}

func TestHandlerServesScanAndPage(t *testing.T) {
	rep := &report.Report{
		Project: "demo", ScanID: "s1", Roles: []string{"admin"}, Tables: []string{"course"},
		RouteCount: 2, RoleCount: 1, TableCount: 1,
		Endpoints: []report.Endpoint{
			{
				Method: "GET", Path: "/course", Subject: "GET /course", Roles: []string{"admin"},
				Resources: []report.Resource{{Table: "course", Operations: []string{"SELECT"}}},
			},
			// No gate, no tables: its slices must serialize as [], never null.
			{Method: "POST", Path: "/login", Subject: "POST /login"},
		},
	}
	h := server.Handler(server.BuildScan(rep), nil, nil, nil)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/scan", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/api/scan status = %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "null") {
		t.Errorf("scan JSON contains null (nil slice leaked): %s", rec.Body.String())
	}
	var s server.Scan
	if err := json.Unmarshal(rec.Body.Bytes(), &s); err != nil {
		t.Fatalf("decode scan: %v", err)
	}
	if len(s.Endpoints) != 2 || s.Endpoints[0].Path != "/course" {
		t.Errorf("endpoints = %+v", s.Endpoints)
	}
	if len(s.Tables) != 1 || s.Tables[0].Name != "course" || len(s.Tables[0].Endpoints) != 1 {
		t.Errorf("tables = %+v", s.Tables)
	}

	// Client-side route with no file falls back to the SPA entrypoint.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/endpoints", nil))
	if rec.Code != http.StatusOK && rec.Code != http.StatusNotImplemented {
		t.Errorf("SPA fallback status = %d (want 200 with assets, or 501 before they are built)", rec.Code)
	}
}
