package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Login to `mintk web` is a tap on a registered YubiKey, through WebAuthn
// (FIDO2). See docs/web.md for the model. In short:
//
//   - The credentials are *non-resident*: nothing is stored on the key, the
//     credential ID (which wraps the private key) lives in web-credentials.json
//     next to the config, so login is a touch with no PIN and uses no key slots.
//   - The first key is registered through a one-time enrollment URL printed in
//     the terminal; later keys can be added from an unlocked session.
//   - Only what the browser hands over is verified: clientDataJSON (type,
//     challenge, origin), authenticatorData (RP ID hash, user presence, counter)
//     and the signature. The public key at registration comes from the browser's
//     getPublicKey() as SPKI DER, so there is no CBOR to parse and no dependency.
//     Attestation is "none": the enrollment URL is what authorizes a new key.
//
// FIDO2 is a separate applet from PIV: a FIDO2 PIN mistake can never block the
// PIV applet that holds the CA key.

const (
	// webRPID is the WebAuthn relying-party ID. It can't be an IP address, which
	// is why the UI lives at http://localhost:<port>. A credential is bound to the
	// RP ID, not the port, so changing the port keeps the registered keys.
	webRPID = "localhost"

	coseES256 = -7
	coseEdDSA = -8

	flagUP = 0x01 // user present (the tap)
	flagAT = 0x40 // attested credential data included

	enrollTTL         = 15 * time.Minute
	challengeTTL      = 2 * time.Minute
	defaultSessionTTL = 12 * time.Hour
)

var b64u = base64.RawURLEncoding

// --- the protocol pieces (pure, unit-tested) --------------------------------

type clientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}

// parseClientData checks clientDataJSON and returns the challenge it signed.
func parseClientData(raw []byte, wantType, wantOrigin string) (string, error) {
	var cd clientData
	if err := json.Unmarshal(raw, &cd); err != nil {
		return "", fmt.Errorf("bad clientDataJSON: %w", err)
	}
	if cd.Type != wantType {
		return "", fmt.Errorf("clientData type %q, want %q", cd.Type, wantType)
	}
	if cd.Origin != wantOrigin {
		return "", fmt.Errorf("clientData origin %q, want %q", cd.Origin, wantOrigin)
	}
	if cd.CrossOrigin {
		return "", fmt.Errorf("cross-origin WebAuthn call refused")
	}
	return cd.Challenge, nil
}

// parseAuthData checks the fixed head of authenticatorData: the RP ID hash and
// the user-presence flag. It returns the flags and the signature counter.
func parseAuthData(ad []byte) (flags byte, count uint32, err error) {
	if len(ad) < 37 {
		return 0, 0, fmt.Errorf("authenticatorData too short (%d bytes)", len(ad))
	}
	want := sha256.Sum256([]byte(webRPID))
	if !bytes.Equal(ad[:32], want[:]) {
		return 0, 0, fmt.Errorf("authenticatorData is for another relying party")
	}
	flags = ad[32]
	if flags&flagUP == 0 {
		return 0, 0, fmt.Errorf("the key did not report a touch (user presence)")
	}
	return flags, binary.BigEndian.Uint32(ad[33:37]), nil
}

// attestedCredentialID pulls the credential ID out of a registration's
// authenticatorData: rpIdHash(32) flags(1) count(4) aaguid(16) len(2) id(len).
func attestedCredentialID(ad []byte) ([]byte, error) {
	if len(ad) < 55 || ad[32]&flagAT == 0 {
		return nil, fmt.Errorf("authenticatorData carries no attested credential")
	}
	n := int(binary.BigEndian.Uint16(ad[53:55]))
	if len(ad) < 55+n {
		return nil, fmt.Errorf("authenticatorData credential ID truncated")
	}
	return ad[55 : 55+n], nil
}

// parseCredentialKey turns the SPKI DER from getPublicKey() into a key we can
// verify with, refusing anything but the two algorithms we asked for.
func parseCredentialKey(alg int, spki []byte) (any, error) {
	pub, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, fmt.Errorf("bad credential public key: %w", err)
	}
	switch alg {
	case coseES256:
		if k, ok := pub.(*ecdsa.PublicKey); ok && k.Curve == elliptic.P256() {
			return k, nil
		}
	case coseEdDSA:
		if k, ok := pub.(ed25519.PublicKey); ok {
			return k, nil
		}
	}
	return nil, fmt.Errorf("credential key does not match algorithm %d", alg)
}

// verifyAssertion checks a login signature: it covers authenticatorData followed
// by SHA-256(clientDataJSON).
func verifyAssertion(alg int, spki, authData, clientDataJSON, sig []byte) error {
	pub, err := parseCredentialKey(alg, spki)
	if err != nil {
		return err
	}
	cdHash := sha256.Sum256(clientDataJSON)
	signed := append(append([]byte{}, authData...), cdHash[:]...)
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		digest := sha256.Sum256(signed)
		if ecdsa.VerifyASN1(k, digest[:], sig) {
			return nil
		}
	case ed25519.PublicKey:
		if ed25519.Verify(k, signed, sig) {
			return nil
		}
	}
	return fmt.Errorf("signature does not verify")
}

// --- registered keys --------------------------------------------------------

type webCred struct {
	ID        string    `json:"id"`         // base64url credential ID
	PublicKey string    `json:"public_key"` // base64url SPKI DER
	Alg       int       `json:"alg"`        // COSE algorithm
	Name      string    `json:"name"`
	SignCount uint32    `json:"sign_count"`
	Created   time.Time `json:"created"`
	LastUsed  time.Time `json:"last_used,omitempty"`
}

// credStore is web-credentials.json. It holds public keys only — nothing in it
// is secret — but adding an entry grants access, so it is written 0600.
type credStore struct {
	path string
	mu   sync.Mutex
}

func webCredentialsPath(cfg *Config) string {
	if cfg.Web != nil && cfg.Web.CredentialsFile != "" {
		return expandPath(cfg.Web.CredentialsFile)
	}
	p := cfg.path
	if p == "" {
		p = configPath()
	}
	return filepath.Join(filepath.Dir(p), "web-credentials.json")
}

func (c *credStore) load() ([]webCred, error) {
	data, err := os.ReadFile(c.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var doc struct {
		Credentials []webCred `json:"credentials"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", c.path, err)
	}
	return doc.Credentials, nil
}

func (c *credStore) save(creds []webCred) error {
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(struct {
		Credentials []webCred `json:"credentials"`
	}{creds}, "", "  ")
	if err != nil {
		return err
	}
	return writeConfigFile(c.path, append(data, '\n'), 0o600)
}

// --- server-side auth state -------------------------------------------------

type webAuth struct {
	store      *credStore
	origin     string // http://localhost:<port>
	sessionTTL time.Duration
	userID     []byte // WebAuthn user handle; irrelevant for non-resident keys

	// enrollPath is the one-time enrollment token, kept in a file on tmpfs rather
	// than in this process: `mintk web enroll` has to be able to open a window on
	// a server that is already running (a systemd unit), and a reboot must close
	// it. Whoever can write the file can already edit web-credentials.json.
	enrollPath string

	mu         sync.Mutex
	sessions   map[string]time.Time
	challenges map[string]pendingChallenge
}

type pendingChallenge struct {
	purpose string
	until   time.Time
}

func newWebAuth(store *credStore, enrollPath string, port int, sessionTTL time.Duration) *webAuth {
	uid := make([]byte, 16)
	_, _ = rand.Read(uid)
	return &webAuth{
		store:      store,
		enrollPath: enrollPath,
		origin:     fmt.Sprintf("http://%s:%d", webRPID, port),
		sessionTTL: sessionTTL,
		userID:     uid,
		sessions:   map[string]time.Time{},
		challenges: map[string]pendingChallenge{},
	}
}

func randB64(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand failing is not something to limp past
	}
	return b64u.EncodeToString(b)
}

// webEnrollPath is where the one-time enrollment token lives: the tmpfs runtime
// dir, shared by the terminal and the systemd unit.
func webEnrollPath() (string, error) {
	d, err := defaultRuntimeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "web-enroll.json"), nil
}

type enrollRecord struct {
	Token   string    `json:"token"`
	Expires time.Time `json:"expires"`
}

// issueEnrollToken opens a one-time enrollment window (replacing any earlier one)
// and returns its token.
func issueEnrollToken(path string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	rec := enrollRecord{Token: randB64(32), Expires: time.Now().Add(enrollTTL)}
	data, _ := json.Marshal(rec)
	if err := writeFileAtomic(path, data, 0o600); err != nil {
		return "", err
	}
	return rec.Token, nil
}

func (a *webAuth) issueEnroll() (string, error) { return issueEnrollToken(a.enrollPath) }

func (a *webAuth) enrollOK(tok string) bool {
	if tok == "" {
		return false
	}
	data, err := os.ReadFile(a.enrollPath)
	if err != nil {
		return false
	}
	var rec enrollRecord
	if json.Unmarshal(data, &rec) != nil || rec.Token == "" || time.Now().After(rec.Expires) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(tok), []byte(rec.Token)) == 1
}

// closeEnroll ends the window: one link registers one key.
func (a *webAuth) closeEnroll() { _ = os.Remove(a.enrollPath) }

func (a *webAuth) newChallenge(purpose string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	for k, c := range a.challenges {
		if now.After(c.until) {
			delete(a.challenges, k)
		}
	}
	ch := randB64(32)
	a.challenges[ch] = pendingChallenge{purpose: purpose, until: now.Add(challengeTTL)}
	return ch
}

// takeChallenge consumes a challenge: each one verifies at most one response.
func (a *webAuth) takeChallenge(ch, purpose string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	c, ok := a.challenges[ch]
	delete(a.challenges, ch)
	return ok && c.purpose == purpose && time.Now().Before(c.until)
}

func (a *webAuth) newSession() (string, time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()
	id := randB64(32)
	until := time.Now().Add(a.sessionTTL)
	a.sessions[id] = until
	return id, until
}

func (a *webAuth) sessionOK(id string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	until, ok := a.sessions[id]
	if ok && time.Now().After(until) {
		delete(a.sessions, id)
		return false
	}
	return ok
}

func (a *webAuth) endSession(id string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.sessions, id)
}

// --- cookies ----------------------------------------------------------------

func (s *webServer) setCookie(w http.ResponseWriter, name, value string, until time.Time) {
	c := &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode}
	if value == "" {
		c.MaxAge = -1
	} else {
		c.Expires = until
	}
	http.SetCookie(w, c)
}

func (s *webServer) cookieValue(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}

func (s *webServer) authed(r *http.Request) bool {
	return s.auth.sessionOK(s.cookieValue(r, s.sessionCookie))
}

func (s *webServer) enrolling(r *http.Request) bool {
	return s.auth.enrollOK(s.cookieValue(r, s.enrollCookie))
}

// --- handlers ---------------------------------------------------------------

// enroll swaps the one-time enrollment URL for a short-lived cookie, so the token
// leaves the address bar and the page can run the registration.
func (s *webServer) enroll(w http.ResponseWriter, r *http.Request) {
	t := r.URL.Query().Get("t")
	if !s.auth.enrollOK(t) {
		http.Error(w, "this enrollment link is invalid, used or expired — run `mintk web enroll` for a new one", http.StatusForbidden)
		return
	}
	s.setCookie(w, s.enrollCookie, t, time.Now().Add(enrollTTL))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

type authStatus struct {
	Authed    bool `json:"authed"`
	Enrolled  bool `json:"enrolled"`
	Enrolling bool `json:"enrolling"`
}

func (s *webServer) authStatus(w http.ResponseWriter, r *http.Request) (any, int) {
	creds, err := s.auth.store.load()
	if err != nil {
		return fail(http.StatusInternalServerError, "%s", err)
	}
	return authStatus{Authed: s.authed(r), Enrolled: len(creds) > 0, Enrolling: s.enrolling(r)}, http.StatusOK
}

type loginBegin struct {
	Challenge string   `json:"challenge"`
	RPID      string   `json:"rp_id"`
	Allow     []string `json:"allow"`
}

func (s *webServer) loginBegin(w http.ResponseWriter, r *http.Request) (any, int) {
	creds, err := s.auth.store.load()
	if err != nil {
		return fail(http.StatusInternalServerError, "%s", err)
	}
	if len(creds) == 0 {
		return fail(http.StatusConflict, "no security key registered yet — run `mintk web enroll`")
	}
	resp := loginBegin{Challenge: s.auth.newChallenge("login"), RPID: webRPID}
	for _, c := range creds {
		resp.Allow = append(resp.Allow, c.ID)
	}
	return resp, http.StatusOK
}

type loginFinish struct {
	ID                string `json:"id"`
	ClientData        string `json:"client_data"`
	AuthenticatorData string `json:"authenticator_data"`
	Signature         string `json:"signature"`
}

func (s *webServer) loginFinish(w http.ResponseWriter, r *http.Request) (any, int) {
	var req loginFinish
	if err := decodeJSON(r, &req); err != nil {
		return fail(http.StatusBadRequest, "%s", err)
	}
	cd, err1 := b64u.DecodeString(req.ClientData)
	ad, err2 := b64u.DecodeString(req.AuthenticatorData)
	sig, err3 := b64u.DecodeString(req.Signature)
	if err1 != nil || err2 != nil || err3 != nil {
		return fail(http.StatusBadRequest, "bad base64 in the assertion")
	}
	ch, err := parseClientData(cd, "webauthn.get", s.auth.origin)
	if err != nil {
		return fail(http.StatusUnauthorized, "%s", err)
	}
	if !s.auth.takeChallenge(ch, "login") {
		return fail(http.StatusUnauthorized, "unknown or expired challenge — try again")
	}
	_, count, err := parseAuthData(ad)
	if err != nil {
		return fail(http.StatusUnauthorized, "%s", err)
	}

	s.auth.store.mu.Lock()
	defer s.auth.store.mu.Unlock()
	creds, err := s.auth.store.load()
	if err != nil {
		return fail(http.StatusInternalServerError, "%s", err)
	}
	i := credIndex(creds, req.ID)
	if i < 0 {
		return fail(http.StatusUnauthorized, "this key is not registered here")
	}
	c := &creds[i]
	spki, err := b64u.DecodeString(c.PublicKey)
	if err != nil {
		return fail(http.StatusInternalServerError, "stored key for %s is corrupt", c.Name)
	}
	if err := verifyAssertion(c.Alg, spki, ad, cd, sig); err != nil {
		return fail(http.StatusUnauthorized, "%s", err)
	}
	// A counter that stops advancing is the spec's hint of a cloned key. Keys
	// that don't keep one report 0 every time, which is fine.
	if (count != 0 || c.SignCount != 0) && count <= c.SignCount {
		return fail(http.StatusUnauthorized, "signature counter went backwards for %s — refusing (cloned key?)", c.Name)
	}
	c.SignCount = count
	c.LastUsed = time.Now().UTC()
	if err := s.auth.store.save(creds); err != nil {
		return fail(http.StatusInternalServerError, "%s", err)
	}
	id, until := s.auth.newSession()
	s.setCookie(w, s.sessionCookie, id, until)
	return map[string]any{"ok": true, "key": c.Name}, http.StatusOK
}

func credIndex(creds []webCred, id string) int {
	for i := range creds {
		if subtle.ConstantTimeCompare([]byte(creds[i].ID), []byte(id)) == 1 {
			return i
		}
	}
	return -1
}

type registerBegin struct {
	Challenge string   `json:"challenge"`
	RPID      string   `json:"rp_id"`
	UserID    string   `json:"user_id"`
	UserName  string   `json:"user_name"`
	Exclude   []string `json:"exclude"`
}

// registerBegin is allowed from an unlocked session (adding a key) or with the
// enrollment cookie (the very first key, or recovery).
func (s *webServer) registerBegin(w http.ResponseWriter, r *http.Request) (any, int) {
	if !s.authed(r) && !s.enrolling(r) {
		return fail(http.StatusUnauthorized, "unlock first, or use the enrollment link from `mintk web enroll`")
	}
	creds, err := s.auth.store.load()
	if err != nil {
		return fail(http.StatusInternalServerError, "%s", err)
	}
	host, _ := os.Hostname()
	resp := registerBegin{
		Challenge: s.auth.newChallenge("register"),
		RPID:      webRPID,
		UserID:    b64u.EncodeToString(s.auth.userID),
		UserName:  strings.TrimSpace("mintk " + host),
		Exclude:   []string{},
	}
	for _, c := range creds {
		resp.Exclude = append(resp.Exclude, c.ID)
	}
	return resp, http.StatusOK
}

type registerFinish struct {
	ID                string `json:"id"`
	ClientData        string `json:"client_data"`
	AuthenticatorData string `json:"authenticator_data"`
	PublicKey         string `json:"public_key"`
	Alg               int    `json:"alg"`
	Name              string `json:"name"`
}

func (s *webServer) registerFinish(w http.ResponseWriter, r *http.Request) (any, int) {
	authed, enrolling := s.authed(r), s.enrolling(r)
	if !authed && !enrolling {
		return fail(http.StatusUnauthorized, "unlock first, or use the enrollment link from `mintk web enroll`")
	}
	var req registerFinish
	if err := decodeJSON(r, &req); err != nil {
		return fail(http.StatusBadRequest, "%s", err)
	}
	cd, err1 := b64u.DecodeString(req.ClientData)
	ad, err2 := b64u.DecodeString(req.AuthenticatorData)
	spki, err3 := b64u.DecodeString(req.PublicKey)
	rawID, err4 := b64u.DecodeString(req.ID)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		return fail(http.StatusBadRequest, "bad base64 in the registration")
	}
	ch, err := parseClientData(cd, "webauthn.create", s.auth.origin)
	if err != nil {
		return fail(http.StatusBadRequest, "%s", err)
	}
	if !s.auth.takeChallenge(ch, "register") {
		return fail(http.StatusBadRequest, "unknown or expired challenge — try again")
	}
	_, count, err := parseAuthData(ad)
	if err != nil {
		return fail(http.StatusBadRequest, "%s", err)
	}
	credID, err := attestedCredentialID(ad)
	if err != nil {
		return fail(http.StatusBadRequest, "%s", err)
	}
	if !bytes.Equal(credID, rawID) {
		return fail(http.StatusBadRequest, "credential ID mismatch")
	}
	if _, err := parseCredentialKey(req.Alg, spki); err != nil {
		return fail(http.StatusBadRequest, "%s", err)
	}

	s.auth.store.mu.Lock()
	defer s.auth.store.mu.Unlock()
	creds, err := s.auth.store.load()
	if err != nil {
		return fail(http.StatusInternalServerError, "%s", err)
	}
	if credIndex(creds, req.ID) >= 0 {
		return fail(http.StatusConflict, "this key is already registered")
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = fmt.Sprintf("YubiKey %d", len(creds)+1)
	}
	if len(name) > 64 {
		name = name[:64]
	}
	creds = append(creds, webCred{
		ID: req.ID, PublicKey: req.PublicKey, Alg: req.Alg, Name: name,
		SignCount: count, Created: time.Now().UTC(),
	})
	if err := s.auth.store.save(creds); err != nil {
		return fail(http.StatusInternalServerError, "%s", err)
	}
	if enrolling {
		// One link, one key.
		s.auth.closeEnroll()
		s.setCookie(w, s.enrollCookie, "", time.Time{})
	}
	if !authed {
		// The tap that registered the key is as good as a login.
		id, until := s.auth.newSession()
		s.setCookie(w, s.sessionCookie, id, until)
	}
	fmt.Printf("%s: registered security key %q (%s)\n", prog, name, s.auth.store.path)
	return map[string]any{"ok": true, "key": name}, http.StatusOK
}

func (s *webServer) logout(w http.ResponseWriter, r *http.Request) (any, int) {
	s.auth.endSession(s.cookieValue(r, s.sessionCookie))
	s.setCookie(w, s.sessionCookie, "", time.Time{})
	return map[string]any{"ok": true}, http.StatusOK
}

type webKey struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Alg      string `json:"alg"`
	Created  int64  `json:"created"`
	LastUsed int64  `json:"last_used,omitempty"`
}

func (s *webServer) apiKeys(r *http.Request) (any, int) {
	creds, err := s.auth.store.load()
	if err != nil {
		return fail(http.StatusInternalServerError, "%s", err)
	}
	out := []webKey{}
	for _, c := range creds {
		k := webKey{ID: c.ID, Name: c.Name, Alg: "ES256", Created: c.Created.UnixMilli()}
		if c.Alg == coseEdDSA {
			k.Alg = "Ed25519"
		}
		if !c.LastUsed.IsZero() {
			k.LastUsed = c.LastUsed.UnixMilli()
		}
		out = append(out, k)
	}
	return map[string]any{"keys": out, "file": s.auth.store.path}, http.StatusOK
}

// apiKeyDelete removes a key — never the last one, so the UI can't lock itself
// out (`mintk web enroll` would still recover it).
func (s *webServer) apiKeyDelete(r *http.Request) (any, int) {
	var req struct {
		ID string `json:"id"`
	}
	if err := decodeJSON(r, &req); err != nil {
		return fail(http.StatusBadRequest, "%s", err)
	}
	s.auth.store.mu.Lock()
	defer s.auth.store.mu.Unlock()
	creds, err := s.auth.store.load()
	if err != nil {
		return fail(http.StatusInternalServerError, "%s", err)
	}
	i := credIndex(creds, req.ID)
	if i < 0 {
		return fail(http.StatusNotFound, "no such key")
	}
	if len(creds) == 1 {
		return fail(http.StatusConflict, "that is the only registered key — add another one first")
	}
	name := creds[i].Name
	creds = append(creds[:i], creds[i+1:]...)
	if err := s.auth.store.save(creds); err != nil {
		return fail(http.StatusInternalServerError, "%s", err)
	}
	return map[string]any{"ok": true, "removed": name}, http.StatusOK
}
