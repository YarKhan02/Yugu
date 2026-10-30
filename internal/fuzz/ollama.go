package fuzz

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// defaultOllamaHost is the local Ollama endpoint. The model is chosen per run
// (from the dashboard); the host is fixed to localhost because the fuzzer runs
// beside a local Ollama, and sending field names to a remote service is not
// something to do implicitly.
const defaultOllamaHost = "http://localhost:11434"

// OllamaMutator asks a local Ollama model for adversarial values to fuzz a
// field with. Results are cached per Go type, so a model is queried once per
// distinct type and reused across every field and endpoint of that type —
// keeping a run bounded and fast despite the model call.
//
// It degrades safely: if Ollama is not running, the model is missing, or the
// response does not parse, Values returns nil and the run proceeds with the
// deterministic payloads alone.
type OllamaMutator struct {
	Host  string
	Model string
	HTTP  *http.Client
	N     int // max values to request per type

	mu    sync.Mutex
	cache map[string][]any
}

// NewOllamaMutator returns a mutator for the given model against the local host.
func NewOllamaMutator(model string) *OllamaMutator {
	return &OllamaMutator{
		Host:  defaultOllamaHost,
		Model: model,
		HTTP:  &http.Client{Timeout: 30 * time.Second},
		N:     6,
		cache: map[string][]any{},
	}
}

// Values returns adversarial values for a field, cached by its Go type.
func (o *OllamaMutator) Values(ctx context.Context, f Field) []any {
	o.mu.Lock()
	defer o.mu.Unlock()
	if v, ok := o.cache[f.GoType]; ok {
		return v
	}
	v := o.generate(ctx, f)
	o.cache[f.GoType] = v // cache even nil: a failure is not retried per field
	return v
}

func (o *OllamaMutator) generate(ctx context.Context, f Field) []any {
	prompt := fmt.Sprintf(`You are a security fuzzer for a web API. Return ONLY a JSON array (no prose) of up to %d adversarial values to probe a request field named %q of Go type %q. Include SQL injection, cross-site scripting, very long strings, unicode edge cases, and boundary values. Output a JSON array of strings.`, o.N, f.Name, f.GoType)

	reqBody, err := json.Marshal(map[string]any{"model": o.Model, "prompt": prompt, "stream": false})
	if err != nil {
		return nil
	}
	host := o.Host
	if host == "" {
		host = defaultOllamaHost
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(host, "/")+"/api/generate", bytes.NewReader(reqBody))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := o.HTTP.Do(req)
	if err != nil {
		return nil // Ollama unreachable: deterministic payloads still run
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var out struct {
		Response string `json:"response"`
	}
	if json.NewDecoder(resp.Body).Decode(&out) != nil {
		return nil
	}
	return parseOllamaValues(out.Response, o.N)
}

// parseOllamaValues extracts a JSON string array from a model's free-text
// response, tolerating prose around it, and returns at most n string values.
// Non-string elements are dropped: a fuzz value goes into a request as a value,
// and only strings are safe to place in any field without re-typing.
func parseOllamaValues(s string, n int) []any {
	i := strings.IndexByte(s, '[')
	j := strings.LastIndexByte(s, ']')
	if i < 0 || j <= i {
		return nil
	}
	var arr []any
	if json.Unmarshal([]byte(s[i:j+1]), &arr) != nil {
		return nil
	}
	out := make([]any, 0, len(arr))
	for _, v := range arr {
		if sv, ok := v.(string); ok {
			out = append(out, sv)
			if len(out) >= n {
				break
			}
		}
	}
	return out
}
