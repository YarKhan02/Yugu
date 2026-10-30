package analyzer_test

import (
	"path/filepath"
	"testing"

	"github.com/YarKhan02/PathWise/internal/analyzer"
	"github.com/YarKhan02/PathWise/internal/loader"
	"golang.org/x/tools/go/ssa"
)

// TestSessionTerminating checks the DB-revocation signal and its controls: a
// handler that DELETEs the table the auth middleware SELECTs is session-
// terminating, while a login INSERT, an unrelated read, and a handler with no
// auth middleware are not.
func TestSessionTerminating(t *testing.T) {
	dir, err := filepath.Abs(filepath.Join("testdata", "sessionterm"))
	if err != nil {
		t.Fatalf("resolve fixture: %v", err)
	}
	loaded, err := loader.Load(dir)
	if err != nil {
		t.Fatalf("load fixture: %v", err)
	}
	cg := analyzer.BuildCallGraph(loaded.Prog)
	funcs := analyzer.FunctionsByName(loaded.Prog)

	fn := func(name string) *ssa.Function {
		f := funcs["main."+name]
		if f == nil {
			t.Fatalf("function %q not found", name)
		}
		return f
	}
	auth := []*ssa.Function{fn("AuthSelect")}

	cases := []struct {
		name       string
		handler    string
		middleware []*ssa.Function
		want       bool
	}{
		{"logout deletes auth table", "LogoutDelete", auth, true},
		{"login inserts, not terminating", "LoginInsert", auth, false},
		{"unrelated read", "ReadWidgets", auth, false},
		{"logout but no auth middleware", "LogoutDelete", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reason, got := analyzer.SessionTerminating(loaded.Prog, cg, fn(tc.handler), tc.middleware, nil)
			if got != tc.want {
				t.Fatalf("SessionTerminating = %v (%q), want %v", got, reason, tc.want)
			}
		})
	}
}

// TestSessionTerminatingCookie checks the cookie-clear signal, including the
// common case where the max-age is passed through a helper (setRefreshCookie),
// so the constant lives at the caller, not the SetCookie site. Login calls the
// same helper with a positive max-age and must not be flagged.
func TestSessionTerminatingCookie(t *testing.T) {
	dir, err := filepath.Abs(filepath.Join("testdata", "cookieclear"))
	if err != nil {
		t.Fatalf("resolve fixture: %v", err)
	}
	loaded, err := loader.Load(dir)
	if err != nil {
		t.Fatalf("load fixture: %v", err)
	}
	cg := analyzer.BuildCallGraph(loaded.Prog)
	funcs := analyzer.FunctionsByName(loaded.Prog)

	for _, tc := range []struct {
		handler string
		want    bool
	}{
		{"Logout", true},    // clears the cookie (max-age -1 via helper)
		{"Login", false},    // same helper, positive max-age
		{"GetThing", false}, // no cookie write
	} {
		t.Run(tc.handler, func(t *testing.T) {
			f := funcs["main."+tc.handler]
			if f == nil {
				t.Fatalf("function %q not found", tc.handler)
			}
			reason, got := analyzer.SessionTerminating(loaded.Prog, cg, f, nil, nil)
			if got != tc.want {
				t.Fatalf("SessionTerminating(%s) = %v (%q), want %v", tc.handler, got, reason, tc.want)
			}
		})
	}
}
