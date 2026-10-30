package analyzer

import (
	"go/constant"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
)

// SessionTerminating reports whether an endpoint ends the caller's own session,
// so runtime testing must not fire it by default: hitting it invalidates the
// very credential later scenarios depend on (the symptom is a logout endpoint
// swept in a GET run, after which every other scenario fails as unauthorized).
//
// Detection is code-confirmed and never name-based — the endpoint being called
// "logout" is irrelevant. Either signal is sufficient:
//
//   - the handler clears an auth cookie: a gin.Context.SetCookie with a
//     non-positive max-age, which expires (deletes) the cookie; or
//   - the handler deletes the credential the auth path reads: a DELETE on a
//     table the endpoint's auth middleware SELECTs to authenticate the request.
//
// It returns a human reason for the skip, or ("", false) when neither holds.
func SessionTerminating(prog *ssa.Program, cg *callgraph.Graph, handler *ssa.Function, middleware []*ssa.Function, embeds EmbedIndex) (string, bool) {
	if handler == nil {
		return "", false
	}
	if clearsAuthCookie(cg, handler) {
		return "handler clears an auth cookie (SetCookie with a non-positive max-age)", true
	}
	if len(middleware) > 0 {
		handlerAcc := AnalyzeReachableDB(prog, cg, []*ssa.Function{handler}, embeds)
		mwAcc := AnalyzeReachableDB(prog, cg, middleware, embeds)
		if t := deletesAuthTable(handlerAcc, mwAcc); t != "" {
			return "handler deletes from " + t + ", the table the auth middleware reads to authenticate the request", true
		}
	}
	return "", false
}

// deletesAuthTable returns a table the handler DELETEs that the middleware reads
// (SELECT). DELETE only: a login INSERT or a token-refresh UPDATE on the same
// table is not revocation and must not be caught.
func deletesAuthTable(handler, middleware DBAccess) string {
	authRead := map[string]bool{}
	for t, ops := range middleware.Tables {
		for _, op := range ops {
			if op == "SELECT" {
				authRead[t] = true
			}
		}
	}
	for t, ops := range handler.Tables {
		if !authRead[t] {
			continue
		}
		for _, op := range ops {
			if op == "DELETE" {
				return t
			}
		}
	}
	return ""
}

// clearsAuthCookie reports whether any function reachable from handler calls
// gin.Context.SetCookie with a non-positive max-age — the idiom for expiring a
// cookie, as a logout does. A positive max-age (setting a cookie, at login) is
// not a match.
//
// The max-age is resolved one hop through a parameter: a logout commonly clears
// the cookie via a helper, h.setRefreshCookie(c, "", -1), so at the SetCookie
// call site the argument is the helper's parameter, and the constant -1 lives at
// the (reachable) caller. Only callers reachable from this handler are
// consulted, so a login that calls the same helper with a positive max-age does
// not cause a false match.
//
// shortcut: Gin only (the single supported framework); net/http.SetCookie
// carries max-age in a struct field, not an argument. Add it when a net/http
// adapter lands.
func clearsAuthCookie(cg *callgraph.Graph, handler *ssa.Function) bool {
	reach := reachableFuncs(cg, []*ssa.Function{handler})

	// Reachable call sites indexed by callee, so a max-age passed as a parameter
	// can be resolved back to the constant the caller supplied.
	callsTo := map[*ssa.Function][]*ssa.Call{}
	for fn := range reach {
		for _, b := range fn.Blocks {
			for _, instr := range b.Instrs {
				if call, ok := instr.(*ssa.Call); ok {
					if callee := call.Call.StaticCallee(); callee != nil {
						callsTo[callee] = append(callsTo[callee], call)
					}
				}
			}
		}
	}

	for fn := range reach {
		for _, b := range fn.Blocks {
			for _, instr := range b.Instrs {
				call, ok := instr.(*ssa.Call)
				if !ok {
					continue
				}
				callee := call.Call.StaticCallee()
				if callee == nil || callee.Name() != "SetCookie" {
					continue
				}
				recv := callee.Signature.Recv()
				if recv == nil || recv.Type().String() != "*github.com/gin-gonic/gin.Context" {
					continue
				}
				// (recv, name, value, maxAge, ...) → max-age at arg index 3.
				if args := call.Call.Args; len(args) >= 4 && nonPositiveInt(args[3], fn, callsTo) {
					return true
				}
			}
		}
	}
	return false
}

// nonPositiveInt reports whether v is a non-positive integer constant, following
// one hop through fn's parameter to the arguments its reachable callers pass.
func nonPositiveInt(v ssa.Value, fn *ssa.Function, callsTo map[*ssa.Function][]*ssa.Call) bool {
	if n, ok := intConst(v); ok {
		return n <= 0
	}
	p, ok := v.(*ssa.Parameter)
	if !ok {
		return false
	}
	idx := -1
	for i, fp := range fn.Params {
		if fp == p {
			idx = i
			break
		}
	}
	if idx < 0 {
		return false
	}
	// A method's receiver is Params[0] and Args[0] alike, so the indices align.
	for _, call := range callsTo[fn] {
		if args := call.Call.Args; idx < len(args) {
			if n, ok := intConst(args[idx]); ok && n <= 0 {
				return true
			}
		}
	}
	return false
}

func intConst(v ssa.Value) (int64, bool) {
	c, ok := v.(*ssa.Const)
	if !ok || c.Value == nil || c.Value.Kind() != constant.Int {
		return 0, false
	}
	return constant.Int64Val(c.Value)
}
