package server

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

//go:embed all:assets
var assets embed.FS

// TestRunner executes a runtime verification requested from the dashboard and
// returns its outcomes. It is injected by the CLI so the server stays free of
// the storage and runtime packages. The tokens in the request live only for the
// duration of the call and are never serialized back to the client.
type TestRunner func(ctx context.Context, req TestRequest) ([]RuntimeTest, error)

// HistoryFn returns every recorded runtime run for the project, newest first.
// It is injected so the store stays the source of truth: the server re-reads it
// after each run rather than reconstructing history in memory.
type HistoryFn func(ctx context.Context) ([]TestRun, error)

// TestRequest is the dashboard's run form: where the running app is, who to
// test as, and exactly which endpoints to run as "METHOD /path" strings. The
// set is explicit — a non-GET endpoint present here is its own opt-in; one
// absent is simply not run.
type TestRequest struct {
	BaseURL    string         `json:"baseUrl"`
	Identities []TestIdentity `json:"identities"`
	Endpoints  []string       `json:"endpoints"` // "METHOD /path" strings to run
}

// TestIdentity is one principal to test as. Token is a credential, accepted
// only in a request body and never written back out.
type TestIdentity struct {
	Role  string `json:"role"`
	Token string `json:"token"`
}

// FuzzRunner executes an active mutation-fuzz run requested from the dashboard
// and returns the behavioral breaks found. Injected by the CLI so the server
// does not import the fuzz or storage packages. The token in the request lives
// only for the duration of the call and is never serialized back.
type FuzzRunner func(ctx context.Context, req FuzzRequest) ([]FuzzFinding, error)

// FuzzRequest is the dashboard's fuzz-run form: where the running app is, the
// bearer token to act with, and which endpoints to fuzz as "METHOD /path"
// strings. An empty Endpoints set means every write endpoint — a non-GET fired
// here is the point of the tool, not an opt-in, so selection is the only gate.
type FuzzRequest struct {
	BaseURL   string   `json:"baseUrl"`
	Token     string   `json:"token"`
	Model     string   `json:"model"` // optional Ollama model; empty = deterministic payloads only
	Endpoints []string `json:"endpoints"`
}

// FuzzFinding is one break reported to the dashboard: the endpoint and payload
// that produced it and the oracle's reason. It carries no response body.
type FuzzFinding struct {
	Endpoint string `json:"endpoint"`
	Kind     string `json:"kind"`
	Payload  string `json:"payload"`
	Detail   string `json:"detail"`
}

// Handler returns the dashboard's HTTP handler: the scan as JSON at /api/scan,
// and the embedded single-page app everywhere else. Unknown non-API paths fall
// back to index.html so the app's client-side routes resolve on a hard refresh.
//
// When runner is non-nil, POST /api/test runs a runtime verification and folds
// its results into the served scan, so a refresh shows the latest run.
func Handler(scan Scan, runner TestRunner, history HistoryFn, fuzzRunner FuzzRunner) http.Handler {
	ui, err := fs.Sub(assets, "assets")
	if err != nil {
		panic(err) // the embed path is a constant; it cannot fail at runtime
	}
	fileServer := http.FileServer(http.FS(ui))

	// state is the served scan; POST /api/test replaces its runtime results, so
	// both handlers share it under the lock.
	state := &scan
	var mu sync.Mutex

	mux := http.NewServeMux()
	mux.HandleFunc("/api/scan", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		mu.Lock()
		defer mu.Unlock()
		_ = json.NewEncoder(w).Encode(state)
	})
	if runner != nil {
		mux.HandleFunc("/api/test", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "use POST", http.StatusMethodNotAllowed)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // cap the request at 1 MiB
			var req TestRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid request: "+err.Error(), http.StatusBadRequest)
				return
			}
			rows, err := runner(r.Context(), req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			// Persisted by the runner, so refresh the durable history from the
			// store. The latest run becomes the current picture. Response-body
			// previews are kept only in this immediate response, never re-served
			// from /api/scan (a body can carry sensitive data).
			mu.Lock()
			state.RuntimeTests = stripBodies(rows)
			state.RuntimeTestedAt = time.Now().UTC().Format(time.RFC3339)
			if history != nil {
				if h, herr := history(r.Context()); herr == nil {
					state.History = h
				}
			}
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(rows)
		})
	}
	if fuzzRunner != nil {
		mux.HandleFunc("/api/fuzz", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				http.Error(w, "use POST", http.StatusMethodNotAllowed)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // cap the request at 1 MiB
			var req FuzzRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "invalid request: "+err.Error(), http.StatusBadRequest)
				return
			}
			breaks, err := fuzzRunner(r.Context(), req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			// Breaks are persisted by the runner; the response carries them for the
			// immediate view. They hold no response bodies, so nothing sensitive is
			// returned.
			w.Header().Set("Content-Type", "application/json")
			if breaks == nil {
				breaks = []FuzzFinding{} // a clean run encodes as [], not null
			}
			_ = json.NewEncoder(w).Encode(breaks)
		})
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		if name == "" {
			name = "index.html"
		}
		if f, err := ui.Open(name); err == nil {
			f.Close()
			fileServer.ServeHTTP(w, r)
			return
		}
		serveIndex(w, ui)
	})
	return mux
}

// stripBodies returns the runtime results without their response-body previews,
// for the in-memory copy that /api/scan re-serves on later reloads.
func stripBodies(rows []RuntimeTest) []RuntimeTest {
	out := make([]RuntimeTest, len(rows))
	for i, r := range rows {
		r.Body = ""
		out[i] = r
	}
	return out
}

// serveIndex writes the SPA entrypoint, for a client-side route with no file.
func serveIndex(w http.ResponseWriter, ui fs.FS) {
	f, err := ui.Open("index.html")
	if err != nil {
		http.Error(w, "dashboard assets are not built", http.StatusNotImplemented)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.Copy(w, f)
}

// Serve runs the dashboard on addr until ctx is cancelled, then shuts down
// cleanly. It binds before reporting the URL so the caller can print a link the
// user can actually open.
func Serve(ctx context.Context, addr string, scan Scan, runner TestRunner, history HistoryFn, fuzzRunner FuzzRunner, onReady func(url string)) error {
	srv := &http.Server{Handler: Handler(scan, runner, history, fuzzRunner)}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}
	if onReady != nil {
		onReady("http://" + ln.Addr().String())
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}
