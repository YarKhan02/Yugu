// Package gin discovers the HTTP routes a Gin application registers, together
// with the middleware chain guarding each one.
//
// Route discovery is not import-path recognition. Real applications register
// routes in loops, behind helper wrappers, and from values computed at startup;
// a tool that only spots `gin-gonic/gin` in the imports learns nothing about
// which handler answers which path. This adapter works from SSA instead: it
// finds calls to Gin's routing methods, resolves the receiver back through the
// SSA value graph to the engine or route group it belongs to, and folds the
// path argument to a constant. A path that is not a compile-time constant is
// recorded as a dynamic_route miss, never silently dropped — an invisible route
// is indistinguishable from a route that is safe.
//
// The adapter depends only on the shared model, never the reverse. That is the
// rule that lets a second framework be added without the model knowing.
package gin

import (
	"fmt"
	"go/constant"
	"go/token"
	"go/types"
	"path"
	"reflect"
	"sort"
	"strings"

	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"

	"github.com/YarKhan02/PathWise/internal/model"
)

// ginPkgPath is how Gin identifies itself in the type graph. It is used to
// recognize Gin's own router type and middleware, not to decide that the app
// "uses Gin" — that conclusion comes from finding actual routing calls.
const ginPkgPath = "github.com/gin-gonic/gin"

// routerGroupType is the concrete receiver of every Gin routing method. Engine
// embeds it, so `engine.GET(...)` and `group.GET(...)` are both, in SSA, static
// calls to a method on *gin.RouterGroup.
const routerGroupType = "RouterGroup"

// httpMethods are the verb-named routing methods. Handle and Any are handled
// separately because their HTTP method is not encoded in the method name.
var httpMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "DELETE": true,
	"PATCH": true, "HEAD": true, "OPTIONS": true,
}

// anyMethods is the set Gin's Any registers a handler for. Kept explicit so an
// Any route expands to the same verbs a reader would expect.
var anyMethods = []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}

// Middleware is one entry in a route's guarding chain: the qualified name of
// the handler function and the constant string arguments it was built with.
// The arguments are what turn a bare "guarded by RequireRole" into "requires
// role admin": RequireRole("admin") records Args ["admin"], while Auth(svc,
// redis) records none, because only the string literals are captured.
type Middleware struct {
	Name string
	Args []string
}

// Route is one discovered (method, pattern) pair and its guarding chain.
type Route struct {
	Method  string
	Pattern string // normalized via model.NormalizeRoute
	Handler string // qualified name of the terminal handler, e.g. "main.GetStudent"

	// Middleware is the application middleware chain in execution order, from
	// outermost group down to any inline middleware on the route itself.
	// Framework-internal middleware (gin.Recovery, gin.Logger) is deliberately
	// excluded: it is plumbing, not authorization logic, and listing it would
	// bury the checks that matter.
	Middleware []Middleware

	Pos token.Position
}

// Subject is the route's stable, framework-agnostic identity.
func (r Route) Subject() string {
	return model.RouteSubject(r.Method, r.Pattern)
}

// MiddlewareNames returns just the middleware names, in order — for callers
// that resolve middleware to functions and do not need the arguments.
func (r Route) MiddlewareNames() []string {
	names := make([]string, len(r.Middleware))
	for i, m := range r.Middleware {
		names[i] = m.Name
	}
	return names
}

// Miss is a routing call the adapter recognized but could not fully resolve.
// Misses are reported, never discarded, so coverage gaps are visible.
type Miss struct {
	Reason model.UnresolvedReason
	Detail string
	Pos    token.Position
}

// Result is everything route discovery found in one target.
type Result struct {
	Routes []Route
	Misses []Miss
}

// routerNode is an engine or route group: a prefix and the middleware every
// route under it inherits. Groups form a tree rooted at an engine.
type routerNode struct {
	parent  *routerNode
	base    string      // accumulated path prefix
	groupMW []ssa.Value // handlers passed to the Group() call that created this node
	useMW   []ssa.Value // handlers added by Use() calls on this node

	// effective memoizes the inherited middleware chain once computed.
	effective    []ssa.Value
	effectiveSet bool
}

// discoverer carries the per-target state of one discovery pass.
type discoverer struct {
	prog    *ssa.Program
	appPkgs map[*ssa.Package]bool // the target's own packages, for app-vs-framework

	nodes      map[ssa.Value]*routerNode // memoized router identity per SSA value
	routeCalls []*ssa.Call               // routing calls, processed after the node tree is built

	result Result
}

// Discover walks the SSA of the target's own packages and returns its routes.
// appPkgs are the packages whose code is the application (loader.Loaded.Packages);
// everything else is treated as a dependency.
func Discover(prog *ssa.Program, appPkgs []*ssa.Package) *Result {
	d := &discoverer{
		prog:    prog,
		appPkgs: make(map[*ssa.Package]bool),
		nodes:   make(map[ssa.Value]*routerNode),
	}
	for _, p := range appPkgs {
		if p != nil {
			d.appPkgs[p] = true
		}
	}

	// Pass A: build the engine/group tree and record Use() middleware. Scan
	// every function the application defines — not just package-level ones:
	// real apps register routes from methods (a module's RegisterRoutes) and
	// closures, which a Members-only walk would miss. ssautil.AllFunctions
	// includes methods and anonymous functions; dependency functions have no
	// built body, so scanFunc finds nothing in them. node() resolves Group
	// chains lazily and memoizes them.
	for fn := range ssautil.AllFunctions(d.prog) {
		if fn.Pkg != nil && d.appPkgs[fn.Pkg] {
			d.scanFunc(fn)
		}
	}

	// Pass B: resolve each routing call against the now-complete tree.
	for _, call := range d.routeCalls {
		d.emitRoute(call)
	}

	sort.Slice(d.result.Routes, func(i, j int) bool {
		return d.result.Routes[i].Subject() < d.result.Routes[j].Subject()
	})
	return &d.result
}

// scanFunc classifies the Gin routing calls in one function.
func (d *discoverer) scanFunc(fn *ssa.Function) {
	for _, b := range fn.Blocks {
		for _, instr := range b.Instrs {
			call, ok := instr.(*ssa.Call)
			if !ok {
				continue
			}
			callee := call.Call.StaticCallee()
			if !isGinConstructor(callee) && !isGinRouterMethod(callee) {
				continue
			}
			name := callee.Name()
			switch {
			case name == "New" || name == "Default":
				// Engine constructors are resolved on demand by node().
			case name == "Group":
				// Group nodes are resolved on demand by node().
			case name == "Use":
				if n := d.node(call.Call.Args[0]); n != nil {
					n.useMW = append(n.useMW, variadicArgs(call.Call)...)
				}
			case httpMethods[name] || name == "Handle" || name == "Any":
				d.routeCalls = append(d.routeCalls, call)
			}
		}
	}
}

// node resolves an SSA value to the router it denotes, or nil if the value is
// not a Gin engine or group. Results are memoized so a group tree is built once.
func (d *discoverer) node(v ssa.Value) *routerNode {
	v = unwrap(v)
	if n, ok := d.nodes[v]; ok {
		return n
	}

	switch x := v.(type) {
	case *ssa.Call:
		callee := x.Call.StaticCallee()
		switch {
		case isGinConstructor(callee):
			// gin.New()/gin.Default() set the engine's RouterGroup base path
			// to "/".
			n := &routerNode{base: "/"}
			d.nodes[v] = n
			return n
		case isGinRouterMethod(callee) && callee.Name() == "Group":
			parent := d.node(x.Call.Args[0])
			if parent == nil {
				return nil
			}
			prefix, ok := constString(x.Call.Args[1])
			if !ok {
				d.miss(model.ReasonDynamicRoute,
					"route group prefix is not a constant string",
					d.prog.Fset.Position(x.Pos()))
				return nil
			}
			n := &routerNode{
				parent:  parent,
				base:    joinPaths(parent.base, prefix),
				groupMW: variadicArgs(x.Call),
			}
			d.nodes[v] = n
			return n
		}
		return nil

	case *ssa.FieldAddr:
		// &engine.RouterGroup — a method on the embedded group. The engine and
		// its embedded group are the same router.
		if isRouterGroupPtr(x.Type()) {
			return d.node(x.X)
		}
		return nil

	case *ssa.Parameter:
		// A router passed in as a parameter — the common "func (m *Module)
		// RegisterRoutes(r *gin.Engine)" shape, where the engine is built in a
		// different function we cannot see from here. An *Engine parameter is
		// the root group, whose base path is "/", so routes and their group
		// prefixes within this function resolve correctly.
		//
		// shortcut: a *RouterGroup parameter is also treated as base "/", which
		// is right only when it is the engine's root group. A sub-group passed
		// in (e.g. an "/api" group) would have its ancestor prefix and
		// middleware under-reported; resolving those needs following the call
		// sites that pass the group in. Engine parameters (AcademyEngine's
		// shape) are exact.
		if isGinEnginePtr(x.Type()) || isRouterGroupPtr(x.Type()) {
			n := &routerNode{base: "/"}
			d.nodes[v] = n
			return n
		}
		return nil
	}
	return nil
}

// emitRoute turns one resolved routing call into one or more routes.
func (d *discoverer) emitRoute(call *ssa.Call) {
	callee := call.Call.StaticCallee()
	name := callee.Name()
	pos := d.prog.Fset.Position(call.Pos())

	node := d.node(call.Call.Args[0])
	if node == nil {
		d.miss(model.ReasonDynamicRoute,
			fmt.Sprintf("receiver of %s is not a resolvable Gin router", name), pos)
		return
	}

	// Argument layout differs only for Handle, which carries the HTTP method as
	// its first ordinary argument.
	var methods []string
	var pathArg ssa.Value
	var handlers []ssa.Value

	switch {
	case name == "Handle":
		methodStr, ok := constString(call.Call.Args[1])
		if !ok {
			d.miss(model.ReasonDynamicRoute, "Handle method is not a constant string", pos)
			return
		}
		methods = []string{strings.ToUpper(methodStr)}
		pathArg = call.Call.Args[2]
		handlers = variadicArgs(call.Call)
	case name == "Any":
		methods = anyMethods
		pathArg = call.Call.Args[1]
		handlers = variadicArgs(call.Call)
	default: // GET, POST, ...
		methods = []string{name}
		pathArg = call.Call.Args[1]
		handlers = variadicArgs(call.Call)
	}

	rel, ok := constString(pathArg)
	if !ok {
		d.miss(model.ReasonDynamicRoute,
			fmt.Sprintf("%s path is not a constant string", name), pos)
		return
	}
	pattern := joinPaths(node.base, rel)

	// The terminal handler is the last argument; anything before it is inline
	// middleware specific to this route.
	handler := ""
	var inline []ssa.Value
	if len(handlers) > 0 {
		handler = d.handlerName(handlers[len(handlers)-1])
		inline = handlers[:len(handlers)-1]
	}

	// A route whose handler cannot be identified — handlers spread from a slice
	// built elsewhere, returned by a call, or otherwise opaque to the value
	// tracking here — is recorded as unresolved, not emitted with an empty
	// handler. An empty handler would read as "route exists, guarded by
	// nothing", which is exactly the silent gap the tool must not produce.
	if handler == "" {
		d.miss(model.ReasonDynamicRoute,
			fmt.Sprintf("%s %s handler could not be resolved from its arguments", name, joinPaths(node.base, rel)),
			pos)
		return
	}

	chain := append(d.effectiveMW(node), inline...)
	middleware := d.appMiddleware(chain)

	for _, m := range methods {
		d.result.Routes = append(d.result.Routes, Route{
			Method:     m,
			Pattern:    model.NormalizeRoute(pattern),
			Handler:    handler,
			Middleware: middleware,
			Pos:        pos,
		})
	}
}

// effectiveMW is the inherited middleware chain for routes registered on a
// node, in execution order: the parent's chain, then this node's group
// handlers, then its Use() handlers — the order Gin itself composes them.
func (d *discoverer) effectiveMW(n *routerNode) []ssa.Value {
	if n.effectiveSet {
		return n.effective
	}
	var chain []ssa.Value
	if n.parent != nil {
		chain = append(chain, d.effectiveMW(n.parent)...)
	}
	chain = append(chain, n.groupMW...)
	chain = append(chain, n.useMW...)
	n.effective = chain
	n.effectiveSet = true
	return chain
}

// appMiddleware names the middleware defined in the application, in order,
// dropping framework-internal ones, and captures the constant string arguments
// each was constructed with. An unresolved middleware value is skipped rather
// than guessed at.
func (d *discoverer) appMiddleware(vals []ssa.Value) []Middleware {
	out := make([]Middleware, 0, len(vals))
	for _, v := range vals {
		if fn := d.originFunc(v); fn != nil && d.appPkgs[fn.Pkg] {
			out = append(out, Middleware{Name: qualifiedName(fn), Args: stringArgs(v)})
		}
	}
	return out
}

// stringArgs returns the constant string arguments of a middleware value that
// is a call — RequireRole("admin") yields ["admin"]. A middleware that is a
// bare function reference, or whose arguments are not string literals, yields
// nothing. The receiver of a method call is not a string, so it is naturally
// excluded.
func stringArgs(v ssa.Value) []string {
	call, ok := unwrap(v).(*ssa.Call)
	if !ok {
		return nil
	}
	var args []string
	for _, a := range call.Call.Args {
		if s, ok := constString(a); ok {
			args = append(args, s)
		}
	}
	return args
}

// handlerName is the qualified name of a handler value, or "" if it cannot be
// resolved to a function.
func (d *discoverer) handlerName(v ssa.Value) string {
	if fn := d.originFunc(v); fn != nil {
		return qualifiedName(fn)
	}
	return ""
}

// originFunc finds the function a handler value comes from: a function
// reference directly, a closure's underlying function, or the function called
// to produce a HandlerFunc (the `RequireRole("admin")` pattern — the middleware
// is attributed to RequireRole).
func (d *discoverer) originFunc(v ssa.Value) *ssa.Function {
	switch x := unwrap(v).(type) {
	case *ssa.Function:
		return realFunc(x)
	case *ssa.MakeClosure:
		if fn, ok := x.Fn.(*ssa.Function); ok {
			return realFunc(fn)
		}
	case *ssa.Call:
		if callee := x.Call.StaticCallee(); callee != nil {
			return realFunc(callee)
		}
	}
	return nil
}

// realFunc resolves a synthetic wrapper to the real function it stands for. A
// method value like `m.h.GetCourse` compiles to a bound-method thunk — a
// synthetic function named "GetCourse$bound" with no package — whose only job
// is to call the real method. Reporting the thunk would name the handler
// "GetCourse$bound"; reporting the method it calls names it "pkg.GetCourse".
func realFunc(fn *ssa.Function) *ssa.Function {
	if fn.Pkg != nil && !strings.Contains(fn.Name(), "$") {
		return fn
	}
	if u := underlyingCallee(fn); u != nil {
		return u
	}
	return fn
}

// underlyingCallee returns the single real function a synthetic wrapper calls,
// or nil if its target is not statically known (e.g. a method expression over
// an interface).
func underlyingCallee(fn *ssa.Function) *ssa.Function {
	for _, b := range fn.Blocks {
		for _, instr := range b.Instrs {
			if call, ok := instr.(*ssa.Call); ok {
				if callee := call.Call.StaticCallee(); callee != nil {
					return callee
				}
			}
		}
	}
	return nil
}

func (d *discoverer) miss(reason model.UnresolvedReason, detail string, pos token.Position) {
	d.result.Misses = append(d.result.Misses, Miss{Reason: reason, Detail: detail, Pos: pos})
}

// --- SSA value helpers -----------------------------------------------------

// unwrap peels the indirections pruned SSA leaves around a value so that the
// caller sees the value that actually flows: a load of a single-stored local,
// a phi whose edges agree. This is the value tracking that lets a route group
// assigned to a local (`api := r.Group(...)`) be matched to the calls on it.
func unwrap(v ssa.Value) ssa.Value {
	for {
		switch x := v.(type) {
		case *ssa.ChangeType:
			// A bare func passed where a named func type is wanted — e.g.
			// GetStudent used as a gin.HandlerFunc — appears as a ChangeType
			// around the function. Peel it so the function underneath shows
			// through; without this every directly-referenced handler and
			// middleware reads as unresolved.
			v = x.X
			continue
		case *ssa.UnOp:
			if x.Op == token.MUL { // pointer load
				v = x.X
				continue
			}
			return v
		case *ssa.Alloc:
			if store := soleStore(x); store != nil {
				v = store.Val
				continue
			}
			return v
		case *ssa.Phi:
			if u := soleAgreeingEdge(x); u != nil {
				v = u
				continue
			}
			return v
		default:
			return v
		}
	}
}

// soleStore returns the one Store into an address, or nil if there is not
// exactly one. More than one store means the value is reassigned and cannot be
// resolved to a single router without real flow analysis.
func soleStore(addr ssa.Value) *ssa.Store {
	var found *ssa.Store
	refs := addr.Referrers()
	if refs == nil {
		return nil
	}
	for _, instr := range *refs {
		if st, ok := instr.(*ssa.Store); ok && st.Addr == addr {
			if found != nil {
				return nil
			}
			found = st
		}
	}
	return found
}

// soleAgreeingEdge returns the common value of a phi whose edges all unwrap to
// the same thing, or nil when they diverge.
func soleAgreeingEdge(phi *ssa.Phi) ssa.Value {
	var agreed ssa.Value
	for _, edge := range phi.Edges {
		u := unwrap(edge)
		if agreed == nil {
			agreed = u
		} else if agreed != u {
			return nil
		}
	}
	return agreed
}

// variadicArgs returns the elements passed to a call's trailing variadic
// parameter. SSA collects variadic arguments into an array behind a slice, so
// the elements are recovered from the stores into that array.
func variadicArgs(cc ssa.CallCommon) []ssa.Value {
	sig := cc.Signature()
	if sig == nil || !sig.Variadic() || len(cc.Args) == 0 {
		return nil
	}
	return sliceElements(cc.Args[len(cc.Args)-1])
}

// sliceElements recovers the elements of a freshly constructed slice literal.
func sliceElements(v ssa.Value) []ssa.Value {
	slice, ok := unwrap(v).(*ssa.Slice)
	if !ok {
		return nil // nil slice (no variadic args) or a slice we cannot see into
	}
	alloc, ok := unwrap(slice.X).(*ssa.Alloc)
	if !ok {
		return nil
	}

	// Each element is stored through an IndexAddr into the backing array.
	byIndex := map[int64]ssa.Value{}
	refs := alloc.Referrers()
	if refs == nil {
		return nil
	}
	for _, instr := range *refs {
		idx, ok := instr.(*ssa.IndexAddr)
		if !ok {
			continue
		}
		k, ok := idx.Index.(*ssa.Const)
		if !ok {
			continue
		}
		ref := idx.Referrers()
		if ref == nil {
			continue
		}
		for _, use := range *ref {
			if st, ok := use.(*ssa.Store); ok && st.Addr == idx {
				byIndex[k.Int64()] = st.Val
			}
		}
	}

	out := make([]ssa.Value, 0, len(byIndex))
	for i := int64(0); i < int64(len(byIndex)); i++ {
		v, ok := byIndex[i]
		if !ok {
			return nil // a gap means we misread the construction; report nothing false
		}
		out = append(out, v)
	}
	return out
}

// constString folds an SSA value to a string constant, including the
// concatenation of constant strings. A non-constant value returns false, which
// the caller turns into a dynamic_route miss.
func constString(v ssa.Value) (string, bool) {
	switch x := unwrap(v).(type) {
	case *ssa.Const:
		if x.Value != nil && x.Value.Kind() == constant.String {
			return constant.StringVal(x.Value), true
		}
	case *ssa.BinOp:
		if x.Op == token.ADD {
			l, lok := constString(x.X)
			r, rok := constString(x.Y)
			if lok && rok {
				return l + r, true
			}
		}
	}
	return "", false
}

// --- Gin type recognition --------------------------------------------------

// responseRenderMethods are the *gin.Context methods that write a response
// body. Abort* and Status are deliberately absent: they end a request without
// producing the body an authorization check is meant to guard.
var responseRenderMethods = map[string]bool{
	"JSON": true, "IndentedJSON": true, "SecureJSON": true, "JSONP": true,
	"AsciiJSON": true, "PureJSON": true, "XML": true, "YAML": true,
	"TOML": true, "ProtoBuf": true, "String": true, "Data": true,
	"HTML": true, "Render": true,
}

// IsResponseWrite reports whether call writes a success response body through a
// *gin.Context — the point in a handler an authorization check must dominate.
// A render with an explicit 3xx/4xx/5xx status is an error or redirect, not the
// body a check protects, so it does not count.
func IsResponseWrite(call *ssa.Call) bool {
	callee := call.Call.StaticCallee()
	if callee == nil || callee.Pkg == nil || callee.Pkg.Pkg == nil {
		return false
	}
	if callee.Pkg.Pkg.Path() != ginPkgPath {
		return false
	}
	recv := callee.Signature.Recv()
	if recv == nil || !isNamedPtr(recv.Type(), "Context") {
		return false
	}
	if !responseRenderMethods[callee.Name()] {
		return false
	}
	// Args[0] is the receiver, Args[1] the HTTP status for every render method.
	if len(call.Call.Args) >= 2 {
		if c, ok := call.Call.Args[1].(*ssa.Const); ok && c.Value != nil {
			if code, ok := constant.Int64Val(c.Value); ok && code >= 300 {
				return false
			}
		}
	}
	return true
}

// requestSourceMethods are the *gin.Context methods that return caller-
// controlled data — a path parameter, query string, header or body field. A
// value flowing from one of these is request-derived, the request half of the
// IDOR signature.
var requestSourceMethods = map[string]bool{
	"Param": true, "Query": true, "DefaultQuery": true, "GetQuery": true,
	"PostForm": true, "DefaultPostForm": true, "GetPostForm": true,
	"QueryArray": true, "PostFormArray": true, "GetHeader": true,
	"Params": true, "ShouldBindJSON": true, "ShouldBind": true, "BindJSON": true,
}

// IsRequestSource reports whether fn is a *gin.Context method that returns
// caller-controlled request data.
func IsRequestSource(fn *ssa.Function) bool {
	if fn == nil || fn.Pkg == nil || fn.Pkg.Pkg == nil || fn.Pkg.Pkg.Path() != ginPkgPath {
		return false
	}
	recv := fn.Signature.Recv()
	return recv != nil && isNamedPtr(recv.Type(), "Context") && requestSourceMethods[fn.Name()]
}

// objectBodyMethods are the *gin.Context render methods whose second argument
// (after the status code) is the Go value serialized into the response body.
// String, Data and HTML have different shapes and are not object renders.
var objectBodyMethods = map[string]bool{
	"JSON": true, "IndentedJSON": true, "SecureJSON": true, "JSONP": true,
	"AsciiJSON": true, "PureJSON": true, "XML": true, "YAML": true,
	"TOML": true, "ProtoBuf": true,
}

// ResponseBody returns the Go value a response render serializes — the object
// behind c.JSON(status, obj) — so the response-scope analysis can inspect the
// fields it exposes. The boolean is false for calls that are not object renders.
func ResponseBody(call *ssa.Call) (ssa.Value, bool) {
	callee := call.Call.StaticCallee()
	if callee == nil || callee.Pkg == nil || callee.Pkg.Pkg == nil {
		return nil, false
	}
	if callee.Pkg.Pkg.Path() != ginPkgPath {
		return nil, false
	}
	recv := callee.Signature.Recv()
	if recv == nil || !isNamedPtr(recv.Type(), "Context") {
		return nil, false
	}
	if !objectBodyMethods[callee.Name()] {
		return nil, false
	}
	if len(call.Call.Args) >= 3 { // recv, status, obj
		return call.Call.Args[2], true
	}
	return nil, false
}

// --- request schema --------------------------------------------------------

// RequestField is one input a handler reads from the incoming request: a body
// field decoded by a Bind call, or a query/path parameter read by key.
type RequestField struct {
	Name     string // json field name, query key, or path-parameter name
	In       string // "body", "query", or "path"
	GoType   string // the field's Go type, e.g. "string", "int", "*time.Time"
	Required bool   // a body field carrying a binding:"required" tag
}

// RequestSchema is the set of request inputs one handler consumes, recovered by
// walking its SSA for *gin.Context accessors. It is the raw material for payload
// generation: the fuzzer needs the shape of a valid request before it can craft
// an invalid one. Unknown records parts of the shape that could not be resolved
// (a bind into a non-struct, a non-constant parameter key) so that a gap is
// never mistaken for "this endpoint takes no input".
type RequestSchema struct {
	Fields  []RequestField
	Unknown []string
}

// bodyBindMethods are the *gin.Context methods that decode the request body
// into the struct passed as their argument.
var bodyBindMethods = map[string]bool{
	"Bind": true, "BindJSON": true, "BindXML": true, "BindYAML": true,
	"BindTOML": true, "ShouldBind": true, "ShouldBindJSON": true,
	"ShouldBindXML": true, "ShouldBindYAML": true, "ShouldBindTOML": true,
}

// paramReadMethods map a *gin.Context accessor to the kind of parameter it
// reads by key — a path segment or a query-string value.
var paramReadMethods = map[string]string{
	"Param": "path", "Query": "query", "DefaultQuery": "query",
	"GetQuery": "query", "PostForm": "query",
}

// HandlerSchema walks a handler's SSA for the request inputs it reads. fn may be
// nil (an unresolved handler), in which case the schema is empty.
func HandlerSchema(fn *ssa.Function) RequestSchema {
	var s RequestSchema
	if fn == nil {
		return s
	}
	seen := map[string]bool{} // a field read on several blocks is one field
	add := func(f RequestField) {
		k := f.In + "\x00" + f.Name
		if seen[k] {
			return
		}
		seen[k] = true
		s.Fields = append(s.Fields, f)
	}
	for _, b := range fn.Blocks {
		for _, instr := range b.Instrs {
			call, ok := instr.(*ssa.Call)
			if !ok {
				continue
			}
			name, ok := contextMethod(call)
			if !ok {
				continue
			}
			switch {
			case bodyBindMethods[name]:
				if len(call.Call.Args) < 2 {
					continue
				}
				fields, ok := bindStructFields(call.Call.Args[1])
				if !ok {
					s.Unknown = append(s.Unknown, "bind target of c."+name+" is not a resolvable struct")
					continue
				}
				for _, f := range fields {
					add(f)
				}
			case paramReadMethods[name] != "":
				if len(call.Call.Args) < 2 {
					continue
				}
				key, ok := constString(call.Call.Args[1])
				if !ok {
					s.Unknown = append(s.Unknown, "non-constant key passed to c."+name)
					continue
				}
				add(RequestField{Name: key, In: paramReadMethods[name], GoType: "string"})
			}
		}
	}
	return s
}

// contextMethod reports the method name when call is a method call on a
// *gin.Context. It mirrors the receiver guard ResponseBody uses.
func contextMethod(call *ssa.Call) (string, bool) {
	callee := call.Call.StaticCallee()
	if callee == nil || callee.Pkg == nil || callee.Pkg.Pkg == nil {
		return "", false
	}
	if callee.Pkg.Pkg.Path() != ginPkgPath {
		return "", false
	}
	recv := callee.Signature.Recv()
	if recv == nil || !isNamedPtr(recv.Type(), "Context") {
		return "", false
	}
	return callee.Name(), true
}

// bindStructFields resolves the struct a bind argument points at and returns one
// RequestField per exported field. The argument arrives boxed in an interface
// (the Bind methods take any), so the MakeInterface is peeled first.
//
// shortcut: only top-level fields are recorded; a nested struct becomes one
// field of struct type rather than being flattened. Revisit when the fuzzer
// needs to mutate nested bodies.
func bindStructFields(arg ssa.Value) ([]RequestField, bool) {
	if mi, ok := arg.(*ssa.MakeInterface); ok {
		arg = mi.X
	}
	t := arg.Type()
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	st, ok := t.Underlying().(*types.Struct)
	if !ok {
		return nil, false
	}
	var out []RequestField
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		if !f.Exported() {
			continue
		}
		tag := reflect.StructTag(st.Tag(i))
		name, skip := jsonFieldName(f, tag)
		if skip {
			continue
		}
		out = append(out, RequestField{
			Name:     name,
			In:       "body",
			GoType:   f.Type().String(),
			Required: bindingRequired(tag),
		})
	}
	return out, true
}

// jsonFieldName returns the wire name of a struct field: its json tag when set,
// otherwise the Go field name. A json:"-" field is skipped.
func jsonFieldName(f *types.Var, tag reflect.StructTag) (name string, skip bool) {
	j := tag.Get("json")
	if j == "" {
		return f.Name(), false
	}
	if i := strings.IndexByte(j, ','); i >= 0 {
		j = j[:i]
	}
	switch j {
	case "-":
		return "", true
	case "":
		return f.Name(), false
	default:
		return j, false
	}
}

// bindingRequired reports whether a gin binding tag marks the field required.
func bindingRequired(tag reflect.StructTag) bool {
	for _, part := range strings.Split(tag.Get("binding"), ",") {
		if part == "required" {
			return true
		}
	}
	return false
}

// isGinConstructor reports whether fn is gin.New or gin.Default, the package
// functions that produce an engine. They have no receiver, so they are
// recognized by name within the gin package rather than by receiver type.
func isGinConstructor(fn *ssa.Function) bool {
	if fn == nil || fn.Pkg == nil || fn.Pkg.Pkg == nil {
		return false
	}
	if fn.Pkg.Pkg.Path() != ginPkgPath {
		return false
	}
	if fn.Signature.Recv() != nil {
		return false
	}
	return fn.Name() == "New" || fn.Name() == "Default"
}

// isGinRouterMethod reports whether fn is a routing method on a Gin router.
// HTTP-verb methods and Group live on *gin.RouterGroup; Use is overridden on
// *gin.Engine (it rebuilds the handler chain), so both receivers count.
func isGinRouterMethod(fn *ssa.Function) bool {
	if fn == nil || fn.Pkg == nil || fn.Pkg.Pkg == nil {
		return false
	}
	if fn.Pkg.Pkg.Path() != ginPkgPath {
		return false
	}
	recv := fn.Signature.Recv()
	if recv == nil {
		return false
	}
	return isNamedPtr(recv.Type(), routerGroupType) || isNamedPtr(recv.Type(), "Engine")
}

// isRouterGroupPtr reports whether t is *gin.RouterGroup.
func isRouterGroupPtr(t types.Type) bool {
	return isNamedPtr(t, routerGroupType)
}

// isGinEnginePtr reports whether t is *gin.Engine.
func isGinEnginePtr(t types.Type) bool {
	return isNamedPtr(t, "Engine")
}

// isNamedPtr reports whether t is a pointer to a named type from the gin
// package with the given name.
func isNamedPtr(t types.Type, name string) bool {
	ptr, ok := t.(*types.Pointer)
	if !ok {
		return false
	}
	named, ok := ptr.Elem().(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	return obj.Name() == name && obj.Pkg() != nil && obj.Pkg().Path() == ginPkgPath
}

// --- name and path helpers -------------------------------------------------

// qualifiedName renders a function as package.Function, the form expected.yaml
// and the stored facts use (e.g. "main.GetStudent").
func qualifiedName(fn *ssa.Function) string {
	if fn.Pkg != nil && fn.Pkg.Pkg != nil {
		return fn.Pkg.Pkg.Name() + "." + fn.Name()
	}
	return fn.Name()
}

// joinPaths composes a group prefix with a relative path the way Gin does,
// preserving a trailing slash the caller wrote deliberately.
func joinPaths(absolutePath, relativePath string) string {
	if relativePath == "" {
		return absolutePath
	}
	finalPath := path.Join(absolutePath, relativePath)
	if strings.HasSuffix(relativePath, "/") && !strings.HasSuffix(finalPath, "/") {
		return finalPath + "/"
	}
	return finalPath
}
