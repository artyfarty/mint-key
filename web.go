package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

// `mintk web` serves the same day-to-day surface as `mintk i` to a browser on
// this machine: the whole scope tree with what's live, one click to mint, secret
// grants, scope management and cleanup. See docs/web.md for the model and the
// threat analysis; the short version is that the listener is loopback-only and
// the page is unlocked with a tap on a registered YubiKey (webauthn.go), and
// every API call must also pass same-origin checks, so neither another local
// user nor a web page in the same browser can drive it.

const defaultWebListen = "localhost:7537"

//go:embed web
var webAssets embed.FS

func webCmd() *cobra.Command {
	var listen string
	var noOpen bool
	cmd := &cobra.Command{
		Use:   "web",
		Short: "Serve the mintk UI to a browser on this machine (mint, grant, manage scopes)",
		Long: `Starts a local web server and opens the browser on it: the full scope tree
with the live certs and their remaining time, one-click minting, secret grants,
scope management and cleanup — everything ` + "`mintk i`" + ` does, minus creating or
editing secrets (that stays in the terminal: plaintext never goes to a browser).
When the server is already running (e.g. as the systemd unit), this just opens the
browser on it.

The UI lives at http://localhost:<port>/ (web.listen in the config, default
` + defaultWebListen + `) and is unlocked with a tap on a registered YubiKey (WebAuthn /
FIDO2, touch only, no PIN). The first key is registered through a one-time link:
printed at start-up while no key is registered, or any time by ` + "`mintk web enroll`" + `.
Registered keys are kept in web-credentials.json next to the config. Every API call
must also come from the page itself: same origin, no CORS, Host checked.

Card operations run one at a time. The YubiKey prompts work as in the terminal:
the tap is physical; a PIN asked by the Windows agent / console comes up in its
own window; a PIN read from a tty (token / wsl-delegate modes) is asked in the
terminal running ` + "`mintk web`" + `.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runWeb(listen, !noOpen)
		},
	}
	cmd.Flags().StringVar(&listen, "listen", "", "loopback address to serve on (default: web.listen, else "+defaultWebListen+")")
	cmd.Flags().BoolVar(&noOpen, "no-open", false, "don't open a browser, just print the URL")
	cmd.AddCommand(webEnrollCmd(), webServiceCmd())
	return cmd
}

func webEnrollCmd() *cobra.Command {
	var noOpen bool
	cmd := &cobra.Command{
		Use:   "enroll",
		Short: "Print a one-time link to register a YubiKey for `mintk web` (add a key, or recover)",
		Long: `Opens a 15-minute window to register one security key and prints the link. Works
whether or not the server is running yet (the token lives in a tmpfs file the server
reads), so it is also how a key gets added to the systemd unit's server. Registering
consumes the link; a new ` + "`enroll`" + ` replaces an unused one.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			port, err := webPort(cfg, "")
			if err != nil {
				return err
			}
			path, err := webEnrollPath()
			if err != nil {
				return err
			}
			tok, err := issueEnrollToken(path)
			if err != nil {
				return err
			}
			url := fmt.Sprintf("%senroll?t=%s", webBaseURL(port), tok)
			fmt.Printf("%s: register a YubiKey (one-time link, valid %s):\n  %s\n", prog, enrollTTL, url)
			if !webRunning(port) {
				fmt.Printf("%s: no server is answering on port %d yet — start `%s web` (or the service) to use it\n", prog, port, prog)
				return nil
			}
			if !noOpen {
				if err := openBrowser(url); err != nil {
					fmt.Printf("%s: could not open a browser (%s) — open the URL above yourself\n", prog, err)
				}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&noOpen, "no-open", false, "don't open a browser, just print the URL")
	return cmd
}

// webListenAddr resolves the listen address: flag, then config, then default.
func webListenAddr(cfg *Config, flag string) string {
	if flag != "" {
		return flag
	}
	if cfg.Web != nil && cfg.Web.Listen != "" {
		return cfg.Web.Listen
	}
	return defaultWebListen
}

// webPort is the configured port — what `enroll` and the already-running check
// need without binding anything.
func webPort(cfg *Config, flag string) (int, error) {
	_, p, err := net.SplitHostPort(webListenAddr(cfg, flag))
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(p)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("web.listen needs a fixed port (got %q)", p)
	}
	return n, nil
}

func webBaseURL(port int) string { return fmt.Sprintf("http://%s:%d/", webRPID, port) }

// webRunning reports whether a mintk web server answers on the port.
func webRunning(port int) bool {
	c := &http.Client{Timeout: 2 * time.Second}
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/static/icon.svg", port), nil)
	req.Host = fmt.Sprintf("%s:%d", webRPID, port)
	resp, err := c.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK && strings.HasPrefix(resp.Header.Get("Content-Type"), "image/svg")
}

func runWeb(listen string, open bool) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	listen = webListenAddr(cfg, listen)
	sessionTTL := defaultSessionTTL
	if cfg.Web != nil && cfg.Web.SessionTTL != "" {
		if sessionTTL, err = parseTTL(cfg.Web.SessionTTL); err != nil {
			return fmt.Errorf("web.session_ttl: %w", err)
		}
	}
	lns, port, err := listenLoopback(listen)
	if err != nil {
		// Already serving (the systemd unit, another terminal): just open it.
		if p, perr := webPort(cfg, listen); perr == nil && errors.Is(err, syscall.EADDRINUSE) && webRunning(p) {
			fmt.Printf("%s: already running at %s\n", prog, webBaseURL(p))
			if open {
				return openBrowser(webBaseURL(p))
			}
			return nil
		}
		return err
	}

	store := &credStore{path: webCredentialsPath(cfg)}
	creds, err := store.load()
	if err != nil {
		return err
	}
	enrollPath, err := webEnrollPath()
	if err != nil {
		return err
	}
	ws := newWebServer(port, newWebAuth(store, enrollPath, port, sessionTTL))
	srv := &http.Server{
		Handler:           ws.handler(),
		ReadHeaderTimeout: 10 * time.Second,
		// No WriteTimeout: a mint legitimately blocks for as long as the YubiKey
		// waits for a tap or the agent's PIN dialog stays open.
	}

	base := webBaseURL(port)
	url := base
	defer pushTermTitle(prog + " web")()
	fmt.Printf("%s: serving on %s  (Ctrl-C to stop)\n", prog, base)
	if len(creds) == 0 {
		tok, err := ws.auth.issueEnroll()
		if err != nil {
			return err
		}
		url = fmt.Sprintf("%senroll?t=%s", base, tok)
		fmt.Printf("%s: no security key registered yet — register one (one-time link, valid %s):\n  %s\n", prog, enrollTTL, url)
		fmt.Printf("%s: (later: `%s web enroll` prints a new link)\n", prog, prog)
	} else {
		fmt.Printf("%s: unlock with a tap on a registered YubiKey (%d registered)\n", prog, len(creds))
	}
	if open {
		if err := openBrowser(url); err != nil {
			fmt.Printf("%s: could not open a browser (%s) — open the URL above yourself\n", prog, err)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, len(lns))
	for _, ln := range lns {
		go func(ln net.Listener) { errc <- srv.Serve(ln) }(ln)
	}
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	fmt.Printf("\n%s: stopping\n", prog)
	shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutCtx)
	return nil
}

// listenLoopback opens the listener(s). "localhost" binds both 127.0.0.1 and ::1
// on the same port: a Windows browser resolving localhost tries ::1 first, and
// WSL forwards whichever the server actually listens on.
func listenLoopback(addr string) ([]net.Listener, int, error) {
	if err := requireLoopback(addr); err != nil {
		return nil, 0, err
	}
	host, port, _ := net.SplitHostPort(addr)
	if host != "localhost" {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, 0, fmt.Errorf("listen on %s: %w", addr, err)
		}
		return []net.Listener{ln}, ln.Addr().(*net.TCPAddr).Port, nil
	}
	v4, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		return nil, 0, fmt.Errorf("listen on %s: %w", addr, err)
	}
	p := v4.Addr().(*net.TCPAddr).Port
	lns := []net.Listener{v4}
	if v6, err := net.Listen("tcp", net.JoinHostPort("::1", strconv.Itoa(p))); err == nil {
		lns = append(lns, v6) // best-effort: a host without IPv6 loopback still works
	}
	return lns, p, nil
}

// requireLoopback refuses any listen address a remote machine could reach. The
// UI can change scopes without a tap; it must never be on the network.
func requireLoopback(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("listen address %q: %w", addr, err)
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("refusing to listen on %q: only loopback addresses (localhost, 127.0.0.1, ::1) are allowed", addr)
	}
	return nil
}

// openBrowser hands the URL to the desktop. Under WSL that's the Windows
// browser: localhost forwarding makes the WSL listener reachable from it.
func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch {
	case inWSL():
		if _, err := exec.LookPath("wslview"); err == nil {
			cmd = exec.Command("wslview", url)
		} else {
			// explorer.exe hands a URL to the default browser. (cmd.exe /c start
			// would need quoting that doesn't survive the WSL→Windows boundary.)
			cmd = exec.Command(winExe("explorer.exe"), url)
		}
	case runtime.GOOS == "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }() // explorer.exe exits 1 even on success
	return nil
}

// --- server ------------------------------------------------------------------

type webServer struct {
	port          int
	host          string // canonical Host header: localhost:<port>
	auth          *webAuth
	sessionCookie string
	enrollCookie  string

	// actionMu serializes everything that touches the card or writes files —
	// two taps racing for one YubiKey is never what anyone wants.
	actionMu sync.Mutex

	busyMu    sync.Mutex
	busy      string // what the running action is, shown to every open tab
	busySince time.Time

	certs certCache
}

func newWebServer(port int, auth *webAuth) *webServer {
	p := strconv.Itoa(port)
	return &webServer{
		port: port,
		host: webRPID + ":" + p,
		auth: auth,
		// Cookies aren't port-scoped; the port in the name keeps two servers (or
		// another localhost app) from clobbering each other's cookie.
		sessionCookie: "mintk_session_" + p,
		enrollCookie:  "mintk_enroll_" + p,
		certs:         certCache{m: map[string]certEntry{}},
	}
}

func (s *webServer) handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(webAssets, "web/static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(static))))
	mux.HandleFunc("GET /{$}", s.index)
	mux.HandleFunc("GET /enroll", s.enroll)

	// Login / registration: same-origin checks, no session required.
	mux.HandleFunc("GET /api/auth/status", s.open(s.authStatus))
	mux.HandleFunc("POST /api/auth/login/begin", s.open(s.loginBegin))
	mux.HandleFunc("POST /api/auth/login/finish", s.open(s.loginFinish))
	mux.HandleFunc("POST /api/auth/register/begin", s.open(s.registerBegin))
	mux.HandleFunc("POST /api/auth/register/finish", s.open(s.registerFinish))
	mux.HandleFunc("POST /api/auth/logout", s.open(s.logout))

	// Everything else: an unlocked session too.
	mux.HandleFunc("GET /api/auth/keys", s.api(s.apiKeys))
	mux.HandleFunc("POST /api/auth/keys/delete", s.api(s.apiKeyDelete))
	mux.HandleFunc("GET /api/state", s.api(s.apiState))
	mux.HandleFunc("POST /api/mint", s.api(s.apiMint))
	mux.HandleFunc("POST /api/drop", s.api(s.apiDrop))
	mux.HandleFunc("POST /api/grant", s.api(s.apiGrant))
	mux.HandleFunc("POST /api/revoke", s.api(s.apiRevoke))
	mux.HandleFunc("POST /api/clean-keys", s.api(s.apiCleanKeys))
	mux.HandleFunc("POST /api/revoke-all", s.api(s.apiRevokeAll))
	mux.HandleFunc("POST /api/scopes/add", s.api(s.apiScopeAdd))
	mux.HandleFunc("POST /api/scopes/update", s.api(s.apiScopeUpdate))
	mux.HandleFunc("POST /api/groups/add", s.api(s.apiGroupAdd))
	mux.HandleFunc("POST /api/groups/rename", s.api(s.apiGroupRename))
	mux.HandleFunc("POST /api/groups/delete", s.api(s.apiGroupDelete))
	return s.guard(mux)
}

// guard applies to every request: hardening headers, the Host check that defeats
// DNS rebinding, and a flat refusal of CORS preflights — no other origin is ever
// granted anything.
func (s *webServer) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; "+
			"img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")

		if r.Host != s.host {
			// WebAuthn can't use an IP origin, so a page opened as 127.0.0.1 is
			// sent to localhost. Anything else — a rebinding name, a wrong port —
			// is not us.
			p := strconv.Itoa(s.port)
			if (r.Host == "127.0.0.1:"+p || r.Host == "[::1]:"+p) && r.Method == http.MethodGet && !strings.HasPrefix(r.URL.Path, "/api/") {
				http.Redirect(w, r, "http://"+s.host+r.URL.RequestURI(), http.StatusTemporaryRedirect)
				return
			}
			http.Error(w, "unexpected Host header — open http://"+s.host+"/", http.StatusMisdirectedRequest)
			return
		}
		if r.Method == http.MethodOptions {
			// A preflight means a cross-origin script is asking. The answer is no,
			// and without Access-Control-Allow-* the browser blocks the real call.
			http.Error(w, "cross-origin requests are not allowed", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// index serves the page shell. It holds nothing: the page asks /api/auth/status
// and shows the unlock or enrollment screen as needed.
func (s *webServer) index(w http.ResponseWriter, r *http.Request) {
	page, err := webAssets.ReadFile("web/index.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(page)
}

// apiFunc handles one API call; it returns the JSON body and a status.
type apiFunc func(r *http.Request) (any, int)

// authFunc is an API handler that may set cookies.
type authFunc func(w http.ResponseWriter, r *http.Request) (any, int)

// errResponse is what every failing call returns.
type errResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
	Log   string `json:"log,omitempty"`
}

func fail(status int, format string, a ...any) (any, int) {
	return errResponse{Error: fmt.Sprintf(format, a...)}, status
}

// open wraps a login/registration call: the same-origin checks, no session.
func (s *webServer) open(h authFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if status, msg := s.checkRequest(r); status != 0 {
			writeJSON(w, status, errResponse{Error: msg})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		body, status := h(w, r)
		writeJSON(w, status, body)
	}
}

// api wraps a call that needs an unlocked session on top of the same-origin
// checks.
func (s *webServer) api(h apiFunc) http.HandlerFunc {
	return s.open(func(w http.ResponseWriter, r *http.Request) (any, int) {
		if !s.authed(r) {
			return fail(http.StatusUnauthorized, "locked — tap your YubiKey to unlock")
		}
		return h(r)
	})
}

// checkRequest refuses anything that isn't the page itself talking:
//   - a custom header, which no cross-origin page can attach without a preflight
//     that guard refuses;
//   - Sec-Fetch-Site / Origin must say same-origin when the browser sends them;
//   - mutations must carry our Origin and be JSON, which a plain HTML form can't
//     produce.
func (s *webServer) checkRequest(r *http.Request) (int, string) {
	if r.Header.Get("X-Mintk") != "1" {
		return http.StatusForbidden, "missing X-Mintk header"
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		return http.StatusForbidden, "cross-site request refused"
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != s.auth.origin {
		return http.StatusForbidden, "cross-origin request refused"
	}
	if r.Method == http.MethodPost {
		if r.Header.Get("Origin") == "" {
			return http.StatusForbidden, "missing Origin header"
		}
		mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if mt != "application/json" {
			return http.StatusUnsupportedMediaType, "expected application/json"
		}
	}
	return 0, ""
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("bad request body: %w", err)
	}
	return nil
}

// --- actions -----------------------------------------------------------------

type actionResult struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Log   string `json:"log"`
}

// action runs one serialized operation with its output captured. A second
// action while one is running is refused rather than queued: a queued mint
// would ask for a tap nobody is expecting any more.
func (s *webServer) action(label string, f func() error) (any, int) {
	if !s.actionMu.TryLock() {
		s.busyMu.Lock()
		cur := s.busy
		s.busyMu.Unlock()
		return fail(http.StatusConflict, "busy: %s is still running", cur)
	}
	defer s.actionMu.Unlock()
	s.setBusy(label)
	defer s.setBusy("")

	var buf syncBuffer
	err := withOutput(&buf, f)
	res := actionResult{OK: err == nil, Log: cleanLog(buf.String())}
	if err != nil {
		res.Error = err.Error()
	}
	return res, http.StatusOK
}

func (s *webServer) setBusy(label string) {
	s.busyMu.Lock()
	defer s.busyMu.Unlock()
	s.busy = label
	s.busySince = time.Now()
}

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\a]*\a|\r`)

// cleanLog strips terminal escapes so the transcript reads as plain text.
func cleanLog(s string) string {
	return strings.TrimRight(ansiRe.ReplaceAllString(s, ""), "\n")
}

type scopeTTLReq struct {
	Scope string `json:"scope"`
	TTL   string `json:"ttl"`
}

func (s *webServer) apiMint(r *http.Request) (any, int) {
	var req scopeTTLReq
	if err := decodeJSON(r, &req); err != nil {
		return fail(http.StatusBadRequest, "%s", err)
	}
	req.TTL = strings.TrimSpace(req.TTL)
	if req.TTL != "" {
		if _, err := normalizeTTL(req.TTL); err != nil {
			return fail(http.StatusBadRequest, "%s", err)
		}
	}
	return s.action("mint "+req.Scope, func() error { return runKey(req.Scope, req.TTL) })
}

// apiDrop forgets one scope's minted identity: out of the agent, then the key
// and cert files. The next mint re-creates the key.
func (s *webServer) apiDrop(r *http.Request) (any, int) {
	var req struct {
		Scope string `json:"scope"`
	}
	if err := decodeJSON(r, &req); err != nil {
		return fail(http.StatusBadRequest, "%s", err)
	}
	return s.action("drop "+req.Scope, func() error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		if _, ok := cfg.scope(req.Scope); !ok {
			return fmt.Errorf("unknown scope %q", req.Scope)
		}
		return dropIdentity(cfg, req.Scope)
	})
}

func dropIdentity(cfg *Config, scope string) error {
	key := filepath.Join(cfg.sessionsDir(), scope)
	if fileExists(key + ".pub") {
		if err := exec.Command("ssh-add", "-d", key+".pub").Run(); err == nil {
			fmt.Fprintf(outW, "%s: removed %s from the agent\n", prog, scope)
		}
	}
	removed := 0
	for _, p := range []string{key + "-cert.pub", key + ".pub", key} {
		if err := os.Remove(p); err == nil {
			removed++
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	fmt.Fprintf(outW, "%s: removed %d file(s) for %s\n", prog, removed, scope)
	return nil
}

func (s *webServer) apiGrant(r *http.Request) (any, int) {
	var req scopeTTLReq
	if err := decodeJSON(r, &req); err != nil {
		return fail(http.StatusBadRequest, "%s", err)
	}
	req.TTL = strings.TrimSpace(req.TTL)
	if req.TTL != "" {
		if _, err := parseTTL(req.TTL); err != nil {
			return fail(http.StatusBadRequest, "%s", err)
		}
	}
	return s.action("grant "+req.Scope, func() error { return runSecretGrant([]string{req.Scope}, req.TTL) })
}

func (s *webServer) apiRevoke(r *http.Request) (any, int) {
	var req struct {
		Scope string `json:"scope"`
	}
	if err := decodeJSON(r, &req); err != nil {
		return fail(http.StatusBadRequest, "%s", err)
	}
	return s.action("revoke "+req.Scope, func() error {
		if err := validScopeName(req.Scope); err != nil {
			return err
		}
		sess, err := openSecrets()
		if err != nil {
			return err
		}
		sess.st.wipe(req.Scope, "")
		fmt.Fprintf(outW, "%s: revoked %s\n", prog, req.Scope)
		return nil
	})
}

func (s *webServer) apiRevokeAll(r *http.Request) (any, int) {
	return s.action("revoke all grants", func() error {
		sess, err := openSecrets()
		if err != nil {
			return err
		}
		grants := sess.st.list()
		if len(grants) == 0 {
			fmt.Fprintf(outW, "%s: no live grants\n", prog)
		}
		for _, g := range grants {
			sess.st.wipe(g.Scope, "")
			fmt.Fprintf(outW, "%s: revoked %s\n", prog, g.Scope)
		}
		return nil
	})
}

func (s *webServer) apiCleanKeys(r *http.Request) (any, int) {
	return s.action("wipe minted identities", func() error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		// The page asked for confirmation already.
		return runCleanKeys(cfg, true)
	})
}

// editScopes runs one scope-list mutation against a freshly loaded config and
// saves it: whatever the CLI wrote since the page last looked is kept.
func (s *webServer) editScopes(label string, f func(cfg *Config) (string, error)) (any, int) {
	return s.action(label, func() error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		msg, err := f(cfg)
		if err != nil {
			return err
		}
		if err := cfg.saveScopes(); err != nil {
			return err
		}
		fmt.Fprintf(outW, "%s: %s (saved %s)\n", prog, msg, cfg.scopesDest())
		return nil
	})
}

func (s *webServer) apiScopeAdd(r *http.Request) (any, int) {
	var req struct {
		Name      string `json:"name"`
		Principal string `json:"principal"`
		TTL       string `json:"ttl"`
		Group     string `json:"group"`
	}
	if err := decodeJSON(r, &req); err != nil {
		return fail(http.StatusBadRequest, "%s", err)
	}
	return s.editScopes("add scope "+req.Name, func(cfg *Config) (string, error) {
		if err := cfg.addScopeChecked(req.Name, req.Principal, req.TTL, req.Group); err != nil {
			return "", err
		}
		sc, _ := cfg.scope(strings.TrimSpace(req.Name))
		return fmt.Sprintf("added scope %s → principal=%s ttl=%s group=%s",
			sc.Name, sc.Principal, sc.TTL, groupDisplay(sc.Group)), nil
	})
}

// apiScopeUpdate changes what `mintk i` lets you change: the default mint time
// and the group. Principal edits and deletion stay in the CLI.
func (s *webServer) apiScopeUpdate(r *http.Request) (any, int) {
	var req struct {
		Name  string  `json:"name"`
		TTL   *string `json:"ttl"`
		Group *string `json:"group"`
	}
	if err := decodeJSON(r, &req); err != nil {
		return fail(http.StatusBadRequest, "%s", err)
	}
	return s.editScopes("update scope "+req.Name, func(cfg *Config) (string, error) {
		var changes []string
		if req.TTL != nil {
			if err := cfg.setScopeTTL(req.Name, *req.TTL); err != nil {
				return "", err
			}
			changes = append(changes, "ttl="+strings.TrimSpace(*req.TTL))
		}
		if req.Group != nil {
			if err := cfg.moveScope(req.Name, *req.Group); err != nil {
				return "", err
			}
			sc, _ := cfg.scope(req.Name)
			changes = append(changes, "group="+groupDisplay(sc.Group))
		}
		if len(changes) == 0 {
			return "", fmt.Errorf("nothing to change")
		}
		return req.Name + " " + strings.Join(changes, " "), nil
	})
}

func (s *webServer) apiGroupAdd(r *http.Request) (any, int) {
	var req struct {
		Path string `json:"path"`
	}
	if err := decodeJSON(r, &req); err != nil {
		return fail(http.StatusBadRequest, "%s", err)
	}
	return s.editScopes("add group "+req.Path, func(cfg *Config) (string, error) {
		p, err := cfg.addGroupChecked(req.Path)
		if err != nil {
			return "", err
		}
		return "added group " + groupDisplay(p), nil
	})
}

func (s *webServer) apiGroupRename(r *http.Request) (any, int) {
	var req struct {
		From string `json:"from"`
		To   string `json:"to"`
	}
	if err := decodeJSON(r, &req); err != nil {
		return fail(http.StatusBadRequest, "%s", err)
	}
	return s.editScopes("rename group "+req.From, func(cfg *Config) (string, error) {
		to, err := cfg.renameGroupChecked(req.From, req.To)
		if err != nil {
			return "", err
		}
		return groupDisplay(cleanGroupPath(req.From)) + " → " + groupDisplay(to), nil
	})
}

func (s *webServer) apiGroupDelete(r *http.Request) (any, int) {
	var req struct {
		Path string `json:"path"`
	}
	if err := decodeJSON(r, &req); err != nil {
		return fail(http.StatusBadRequest, "%s", err)
	}
	return s.editScopes("delete group "+req.Path, func(cfg *Config) (string, error) {
		if err := cfg.deleteGroupChecked(req.Path); err != nil {
			return "", err
		}
		return "deleted group " + groupDisplay(cleanGroupPath(req.Path)), nil
	})
}

// --- state -------------------------------------------------------------------

// webState is everything the page renders. Times are Unix milliseconds so the
// browser can run the countdowns itself between polls; 0 means "none".
type webState struct {
	Host        string     `json:"host"`
	Mode        string     `json:"mode"`
	Config      string     `json:"config"`
	ScopesDest  string     `json:"scopes_dest"`
	Now         int64      `json:"now"`
	Busy        string     `json:"busy,omitempty"`
	BusySince   int64      `json:"busy_since,omitempty"`
	ConfigError string     `json:"config_error,omitempty"`
	Scopes      []webScope `json:"scopes"`
	Groups      []string   `json:"groups"`
	Secrets     webSecrets `json:"secrets"`
	Notes       []string   `json:"notes,omitempty"`
}

type webScope struct {
	Name      string `json:"name"`
	Principal string `json:"principal"`
	TTL       string `json:"ttl"`
	Group     string `json:"group"`
	HasKey    bool   `json:"has_key"`
	From      int64  `json:"from,omitempty"`
	Expires   int64  `json:"expires,omitempty"`
}

type webSecrets struct {
	Enabled bool             `json:"enabled"`
	Error   string           `json:"error,omitempty"`
	Scopes  []webSecretScope `json:"scopes"`
}

type webSecretScope struct {
	Name    string `json:"name"`
	TTL     string `json:"ttl"`
	Format  string `json:"format"`
	From    int64  `json:"from,omitempty"`
	Expires int64  `json:"expires,omitempty"`
}

func (s *webServer) apiState(r *http.Request) (any, int) {
	st := webState{Now: time.Now().UnixMilli(), Scopes: []webScope{}, Groups: []string{}}
	st.Secrets.Scopes = []webSecretScope{}
	st.Host, _ = os.Hostname()

	s.busyMu.Lock()
	if s.busy != "" {
		st.Busy, st.BusySince = s.busy, s.busySince.UnixMilli()
	}
	s.busyMu.Unlock()

	cfg, err := loadConfig()
	if err != nil {
		st.ConfigError = err.Error()
		return st, http.StatusOK
	}
	st.Mode = cfg.Mode
	if st.Mode == "" {
		st.Mode = "token"
	}
	st.Config = cfg.path
	st.ScopesDest = cfg.scopesDest()
	switch st.Mode {
	case "token", "wsl-delegate":
		st.Notes = append(st.Notes, "mode="+st.Mode+": the YubiKey PIN is asked in the terminal running `mintk web`")
	}

	dir := cfg.sessionsDir()
	for _, sc := range cfg.Scopes {
		ws := webScope{Name: sc.Name, Principal: sc.Principal, TTL: sc.TTL, Group: sc.Group}
		ws.HasKey = fileExists(filepath.Join(dir, sc.Name))
		if from, to, ok := s.certs.validity(filepath.Join(dir, sc.Name+"-cert.pub")); ok && time.Now().Before(to) {
			ws.From, ws.Expires = from.UnixMilli(), to.UnixMilli()
		}
		st.Scopes = append(st.Scopes, ws)
	}
	st.Groups = append(st.Groups, cfg.allGroups()...)

	if cfg.Secrets == nil {
		return st, http.StatusOK
	}
	sess, err := openSecrets()
	if err != nil {
		st.Secrets.Error = err.Error()
		return st, http.StatusOK
	}
	st.Secrets.Enabled = true
	for _, n := range sess.sec.listSecretScopes() {
		ss := webSecretScope{Name: n, TTL: sess.sec.scopeTTL(n), Format: sess.sec.scopeFormat(n)}
		if g, ok := sess.st.live(n); ok {
			ss.From, ss.Expires = g.GrantedAt.UnixMilli(), g.ExpiresAt.UnixMilli()
		}
		st.Secrets.Scopes = append(st.Secrets.Scopes, ss)
	}
	return st, http.StatusOK
}

// certCache remembers each cert's validity window by file identity, so polling
// the state doesn't fork `ssh-keygen -L` per scope every few seconds.
type certCache struct {
	mu sync.Mutex
	m  map[string]certEntry
}

type certEntry struct {
	mtime    time.Time
	size     int64
	from, to time.Time
	ok       bool
}

func (c *certCache) validity(path string) (from, to time.Time, ok bool) {
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}, time.Time{}, false
	}
	c.mu.Lock()
	e, hit := c.m[path]
	c.mu.Unlock()
	if hit && e.mtime.Equal(info.ModTime()) && e.size == info.Size() {
		return e.from, e.to, e.ok
	}
	e = certEntry{mtime: info.ModTime(), size: info.Size()}
	if out, err := exec.Command("ssh-keygen", "-L", "-f", path).Output(); err == nil {
		e.from, e.to, e.ok = parseCertValidity(string(out))
	}
	c.mu.Lock()
	c.m[path] = e
	c.mu.Unlock()
	return e.from, e.to, e.ok
}
