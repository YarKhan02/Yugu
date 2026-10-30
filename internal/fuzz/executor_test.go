package fuzz

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSendFillsPathBodyAndToken(t *testing.T) {
	var gotMethod, gotPath, gotAuth, gotCT string
	var gotBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotCT = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(b) // echo
	}))
	defer srv.Close()

	resp, err := NewClient(srv.URL).Send(context.Background(), Request{
		Method:     "POST",
		Path:       "/things/{id}",
		PathParams: map[string]string{"id": "42"},
		Body:       map[string]any{"x": 1},
		Token:      "secret-token",
	})
	if err != nil {
		t.Fatalf("send: %v", err)
	}

	if gotMethod != "POST" {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/things/42" {
		t.Errorf("path = %q, want /things/42 (param substituted)", gotPath)
	}
	if gotAuth != "Bearer secret-token" {
		t.Errorf("auth = %q, want bearer token", gotAuth)
	}
	if gotCT != "application/json" {
		t.Errorf("content-type = %q, want application/json", gotCT)
	}
	if gotBody["x"] != float64(1) {
		t.Errorf("body x = %v, want 1", gotBody["x"])
	}
	if resp.Status != http.StatusCreated {
		t.Errorf("status = %d, want 201", resp.Status)
	}
	if !strings.Contains(string(resp.Body), `"x"`) {
		t.Errorf("response body not captured: %q", resp.Body)
	}
}

// TestSendCapsBody guards the memory bound: a response larger than the cap is
// truncated, never read whole.
func TestSendCapsBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("A", maxBodyCapture*4)))
	}))
	defer srv.Close()

	resp, err := NewClient(srv.URL).Send(context.Background(), Request{Method: "GET", Path: "/big"})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if len(resp.Body) > maxBodyCapture {
		t.Errorf("body length %d exceeds cap %d", len(resp.Body), maxBodyCapture)
	}
}

// TestSendTransportError is the negative control: a dead address is a transport
// error, not a zero-value Response the oracle would misread as a clean run.
func TestSendTransportError(t *testing.T) {
	_, err := NewClient("http://127.0.0.1:0").Send(context.Background(), Request{Method: "GET", Path: "/x"})
	if err == nil {
		t.Errorf("expected a transport error for an unreachable host")
	}
}
