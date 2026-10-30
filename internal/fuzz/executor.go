package fuzz

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxBodyCapture bounds how much of a response the executor reads back. The body
// is evidence for a break (what the app served), held in memory for the run and
// never persisted — a response body can carry sensitive data.
const maxBodyCapture = 8 << 10 // 8 KiB

// Request is one concrete HTTP request the fuzzer sends: a method and path with
// its parameters filled, an optional JSON body, and the caller's bearer token.
type Request struct {
	Method     string
	Path       string            // may contain {name} placeholders
	PathParams map[string]string // values substituted into the path
	Query      map[string]string
	Body       map[string]any // nil sends no body
	Token      string         // bearer credential; sent, never stored
}

// Response is the captured outcome of a Request: the status and a capped body.
type Response struct {
	Status int
	Body   []byte
}

// Client sends fuzz requests at one base URL.
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

// NewClient returns a Client with a conservative timeout, matching the runtime
// verifier's defaults.
func NewClient(baseURL string) Client {
	return Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		HTTP:    &http.Client{Timeout: 10 * time.Second},
	}
}

// Send issues r and returns its status and a capped body. A transport error
// (connection refused, timeout) is returned as an error; an HTTP error status
// is a normal Response for the oracle to judge.
func (c Client) Send(ctx context.Context, r Request) (Response, error) {
	target := c.BaseURL + fillPath(r.Path, r.PathParams)
	if len(r.Query) > 0 {
		q := url.Values{}
		for k, v := range r.Query {
			q.Set(k, v)
		}
		target += "?" + q.Encode()
	}

	var body io.Reader
	if r.Body != nil {
		b, err := json.Marshal(r.Body)
		if err != nil {
			return Response{}, fmt.Errorf("marshal body: %w", err)
		}
		body = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, strings.ToUpper(r.Method), target, body)
	if err != nil {
		return Response{}, fmt.Errorf("build request: %w", err)
	}
	if r.Body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if r.Token != "" {
		req.Header.Set("Authorization", "Bearer "+r.Token)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return Response{}, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyCapture))
	return Response{Status: resp.StatusCode, Body: b}, nil
}

// fillPath substitutes {name} placeholders in a route path with escaped values.
// A placeholder with no supplied value is left in place, so an unresolved path
// parameter is visible rather than silently producing a wrong URL.
func fillPath(p string, params map[string]string) string {
	for name, val := range params {
		p = strings.ReplaceAll(p, "{"+name+"}", url.PathEscape(val))
	}
	return p
}
