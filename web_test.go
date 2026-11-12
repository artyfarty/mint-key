package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testPort = 47999

func testWeb(t *testing.T) (*webServer, http.Handler) {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	data := "mode: software\nsessions_dir: " + filepath.Join(dir, "sessions") + "\n" +
		"scopes:\n  - {name: alpha, principal: p-alpha, ttl: 8h, group: infra/prod}\n"
	if err := os.WriteFile(cfg, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MINTK_CONFIG", cfg)
	store := &credStore{path: filepath.Join(dir, "web-credentials.json")}
	ws := newWebServer(testPort, newWebAuth(store, filepath.Join(dir, "web-enroll.json"), testPort, time.Hour))
	testSession, _ = ws.auth.newSession()
	return ws, ws.handler()
}

// testSession is an unlocked session on the server testWeb built last.
var testSession string

type reqOpt func(*http.Request)

func withCookie(v string) reqOpt {
	return func(r *http.Request) { r.AddCookie(&http.Cookie{Name: "mintk_session_47999", Value: v}) }
}
func withHeader(k, v string) reqOpt { return func(r *http.Request) { r.Header.Set(k, v) } }
func withoutHeader(k string) reqOpt { return func(r *http.Request) { r.Header.Del(k) } }

// do sends a request that passes every check unless an option breaks one.
func do(h http.Handler, method, path, body string, opts ...reqOpt) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Host = "localhost:47999"
	r.AddCookie(&http.Cookie{Name: "mintk_session_47999", Value: testSession})
	r.Header.Set("X-Mintk", "1")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	if method == http.MethodPost {
		r.Header.Set("Origin", "http://localhost:47999")
		r.Header.Set("Content-Type", "application/json")
	}
	for _, o := range opts {
		o(r)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestWebAPIGate(t *testing.T) {
	_, h := testWeb(t)
	const groupAdd = `{"path":"lab"}`
	cases := []struct {
		name   string
		method string
		path   string
		body   string
		opts   []reqOpt
		want   int
	}{
		{"state ok", "GET", "/api/state", "", nil, 200},
		{"no cookie", "GET", "/api/state", "", []reqOpt{func(r *http.Request) { r.Header.Del("Cookie") }}, 401},
		{"wrong cookie", "GET", "/api/state", "", []reqOpt{func(r *http.Request) { r.Header.Del("Cookie") }, withCookie("nope")}, 401},
		{"no X-Mintk", "GET", "/api/state", "", []reqOpt{withoutHeader("X-Mintk")}, 403},
		{"rebinding Host", "GET", "/api/state", "", []reqOpt{func(r *http.Request) { r.Host = "evil.example:47999" }}, 421},
		{"wrong port Host", "GET", "/api/state", "", []reqOpt{func(r *http.Request) { r.Host = "localhost:1" }}, 421},
		{"IP Host on the API", "GET", "/api/state", "", []reqOpt{func(r *http.Request) { r.Host = "127.0.0.1:47999" }}, 421},
		{"IP Host page → localhost", "GET", "/", "", []reqOpt{func(r *http.Request) { r.Host = "127.0.0.1:47999" }}, 307},
		{"auth status without session", "GET", "/api/auth/status", "", []reqOpt{func(r *http.Request) { r.Header.Del("Cookie") }}, 200},
		{"auth status cross-site", "GET", "/api/auth/status", "", []reqOpt{withHeader("Sec-Fetch-Site", "cross-site")}, 403},
		{"cross-site fetch", "GET", "/api/state", "", []reqOpt{withHeader("Sec-Fetch-Site", "cross-site")}, 403},
		{"same-site fetch", "GET", "/api/state", "", []reqOpt{withHeader("Sec-Fetch-Site", "same-site")}, 403},
		{"preflight", "OPTIONS", "/api/mint", "", nil, 403},
		{"post ok", "POST", "/api/groups/add", groupAdd, nil, 200},
		{"post foreign Origin", "POST", "/api/groups/add", groupAdd, []reqOpt{withHeader("Origin", "http://evil.example")}, 403},
		{"post no Origin", "POST", "/api/groups/add", groupAdd, []reqOpt{withoutHeader("Origin")}, 403},
		{"post form type", "POST", "/api/groups/add", groupAdd, []reqOpt{withHeader("Content-Type", "text/plain")}, 415},
		{"get on post route", "GET", "/api/mint", "", nil, 405},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := do(h, c.method, c.path, c.body, c.opts...)
			if w.Code != c.want {
				t.Fatalf("%s %s: got %d, want %d (%s)", c.method, c.path, w.Code, c.want, w.Body.String())
			}
			if w.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Fatalf("never grant CORS, got ACAO=%q", w.Header().Get("Access-Control-Allow-Origin"))
			}
			if w.Header().Get("Content-Security-Policy") == "" {
				t.Fatalf("missing CSP header")
			}
		})
	}
}

func TestWebPageShellIsPublic(t *testing.T) {
	_, h := testWeb(t)
	// The page shell holds nothing; without a session it shows the unlock screen.
	if w := do(h, "GET", "/", "", func(r *http.Request) { r.Header.Del("Cookie") }); w.Code != 200 {
		t.Fatalf("index without cookie: got %d", w.Code)
	}
	if w := do(h, "GET", "/static/app.js", ""); w.Code != 200 {
		t.Fatalf("static asset: got %d", w.Code)
	}
	if w := do(h, "GET", "/enroll?t=nope", ""); w.Code != http.StatusForbidden {
		t.Fatalf("bad enrollment token: got %d", w.Code)
	}
}

func TestWebBusyRefusesSecondAction(t *testing.T) {
	ws, h := testWeb(t)
	ws.actionMu.Lock() // an action is in flight
	ws.setBusy("mint alpha")
	w := do(h, "POST", "/api/mint", `{"scope":"alpha"}`)
	ws.actionMu.Unlock()
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "mint alpha") {
		t.Fatalf("got %d %s", w.Code, w.Body.String())
	}
}

func TestWebStateAndScopeEdits(t *testing.T) {
	_, h := testWeb(t)
	post := func(path, body string) actionResult {
		t.Helper()
		w := do(h, "POST", path, body)
		var r actionResult
		if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
			t.Fatalf("%s: %v (%s)", path, err, w.Body.String())
		}
		return r
	}
	if r := post("/api/scopes/add", `{"name":"beta","principal":"p-beta","ttl":"2h","group":"lab/x"}`); !r.OK {
		t.Fatalf("add: %s", r.Error)
	}
	if r := post("/api/scopes/add", `{"name":"beta","principal":"x","ttl":"2h","group":""}`); r.OK {
		t.Fatal("duplicate scope accepted")
	}
	if r := post("/api/scopes/update", `{"name":"alpha","ttl":"1h","group":"lab"}`); !r.OK {
		t.Fatalf("update: %s", r.Error)
	}
	if r := post("/api/scopes/update", `{"name":"alpha","ttl":"forever"}`); r.OK {
		t.Fatal("bad ttl accepted")
	}
	// Principal edits are deliberately not part of the API.
	if w := do(h, "POST", "/api/scopes/update", `{"name":"alpha","principal":"root"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("principal edit: got %d", w.Code)
	}
	if r := post("/api/groups/delete", `{"path":"lab"}`); r.OK {
		t.Fatal("non-empty group deleted")
	}

	w := do(h, "GET", "/api/state", "")
	var st webState
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	got := map[string]webScope{}
	for _, s := range st.Scopes {
		got[s.Name] = s
	}
	if got["alpha"].TTL != "1h" || got["alpha"].Group != "lab" || got["alpha"].Principal != "p-alpha" {
		t.Fatalf("alpha after edit: %+v", got["alpha"])
	}
	if got["beta"].Group != "lab/x" {
		t.Fatalf("beta: %+v", got["beta"])
	}
	if st.Mode != "software" || st.Secrets.Enabled {
		t.Fatalf("state: mode=%q secrets=%+v", st.Mode, st.Secrets)
	}
}

func TestRequireLoopback(t *testing.T) {
	for addr, ok := range map[string]bool{
		"127.0.0.1:7537": true,
		"[::1]:7537":     true,
		"localhost:7537": true,
		"0.0.0.0:7537":   false,
		":7537":          false,
		"10.0.0.5:7537":  false,
		"example:7537":   false,
	} {
		if err := requireLoopback(addr); (err == nil) != ok {
			t.Errorf("%s: err=%v, want ok=%v", addr, err, ok)
		}
	}
}

func TestParseCertValidity(t *testing.T) {
	from, to, ok := parseCertValidity("        Valid: from 2026-08-10T22:00:00 to 2026-08-11T06:00:00\n")
	if !ok || to.Sub(from).Hours() != 8 {
		t.Fatalf("got %v %v %v", from, to, ok)
	}
	if _, _, ok := parseCertValidity("Valid: forever"); ok {
		t.Fatal("forever parsed")
	}
}

func TestWebUnitText(t *testing.T) {
	got := webUnitText("/opt/my tools/mintk", [][2]string{
		{"SSH_AUTH_SOCK", "/home/u/.ssh/agent.sock"},
		{"MINTK_CONFIG", ""},
		{"ODD", `a"b\c%d`},
	})
	for _, want := range []string{
		`ExecStart="/opt/my tools/mintk" web --no-open`,
		`Environment="SSH_AUTH_SOCK=/home/u/.ssh/agent.sock"`,
		`Environment="ODD=a\"b\\c%%d"`,
		"WantedBy=default.target",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("unit lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "MINTK_CONFIG") {
		t.Errorf("empty env var written:\n%s", got)
	}
}

func TestEnrollTokenFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "rt", "web-enroll.json")
	a := &webAuth{enrollPath: p}
	if a.enrollOK("x") {
		t.Fatal("no file, yet a token was accepted")
	}
	tok, err := issueEnrollToken(p)
	if err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(p); info.Mode().Perm() != 0o600 {
		t.Fatalf("enroll file mode %v", info.Mode().Perm())
	}
	if !a.enrollOK(tok) || a.enrollOK(tok+"x") || a.enrollOK("") {
		t.Fatal("token check wrong")
	}
	// A new link replaces an unused one.
	tok2, _ := issueEnrollToken(p)
	if a.enrollOK(tok) || !a.enrollOK(tok2) {
		t.Fatal("re-issue did not replace the old token")
	}
	a.closeEnroll()
	if a.enrollOK(tok2) {
		t.Fatal("closed window still accepts")
	}
}
