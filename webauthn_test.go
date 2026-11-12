package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// softKey is a software stand-in for the YubiKey's FIDO2 applet: just enough to
// produce the registration and assertion a browser would hand the server.
type softKey struct {
	t     *testing.T
	priv  *ecdsa.PrivateKey
	id    []byte
	count uint32
}

func newSoftKey(t *testing.T) *softKey {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 48)
	_, _ = rand.Read(id)
	return &softKey{t: t, priv: priv, id: id}
}

func (k *softKey) authData(rpID string, attested bool) []byte {
	h := sha256.Sum256([]byte(rpID))
	ad := append([]byte{}, h[:]...)
	flags := byte(flagUP)
	if attested {
		flags |= flagAT
	}
	k.count++
	ad = append(ad, flags)
	ad = binary.BigEndian.AppendUint32(ad, k.count)
	if attested {
		ad = append(ad, make([]byte, 16)...) // aaguid
		ad = binary.BigEndian.AppendUint16(ad, uint16(len(k.id)))
		ad = append(ad, k.id...)
		ad = append(ad, 0xa0) // stand-in for the COSE key; the server reads SPKI instead
	}
	return ad
}

func clientDataJSON(typ, challenge, origin string) []byte {
	b, _ := json.Marshal(clientData{Type: typ, Challenge: challenge, Origin: origin})
	return b
}

func (k *softKey) sign(ad, cd []byte) []byte {
	cdHash := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, k.priv, digest[:])
	if err != nil {
		k.t.Fatal(err)
	}
	return sig
}

func (k *softKey) spki() []byte {
	der, err := x509.MarshalPKIXPublicKey(&k.priv.PublicKey)
	if err != nil {
		k.t.Fatal(err)
	}
	return der
}

const testOrigin = "http://localhost:47999"

// call posts JSON with only the given cookies (no default session).
func call(h http.Handler, path string, body any, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	r := httptest.NewRequest("POST", path, strings.NewReader(string(b)))
	r.Host = "localhost:47999"
	r.Header.Set("X-Mintk", "1")
	r.Header.Set("Origin", testOrigin)
	r.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func cookieFrom(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name && c.Value != "" {
			return c
		}
	}
	return nil
}

func (k *softKey) register(t *testing.T, h http.Handler, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	w := call(h, "/api/auth/register/begin", struct{}{}, cookies...)
	if w.Code != 200 {
		return w
	}
	var begin registerBegin
	_ = json.Unmarshal(w.Body.Bytes(), &begin)
	ad := k.authData(begin.RPID, true)
	cd := clientDataJSON("webauthn.create", begin.Challenge, testOrigin)
	return call(h, "/api/auth/register/finish", registerFinish{
		ID: b64u.EncodeToString(k.id), ClientData: b64u.EncodeToString(cd),
		AuthenticatorData: b64u.EncodeToString(ad), PublicKey: b64u.EncodeToString(k.spki()),
		Alg: coseES256, Name: "test key",
	}, cookies...)
}

func (k *softKey) login(t *testing.T, h http.Handler, tamper func(*loginFinish)) *httptest.ResponseRecorder {
	w := call(h, "/api/auth/login/begin", struct{}{})
	if w.Code != 200 {
		t.Fatalf("login begin: %d %s", w.Code, w.Body.String())
	}
	var begin loginBegin
	_ = json.Unmarshal(w.Body.Bytes(), &begin)
	ad := k.authData(begin.RPID, false)
	cd := clientDataJSON("webauthn.get", begin.Challenge, testOrigin)
	req := loginFinish{
		ID: b64u.EncodeToString(k.id), ClientData: b64u.EncodeToString(cd),
		AuthenticatorData: b64u.EncodeToString(ad), Signature: b64u.EncodeToString(k.sign(ad, cd)),
	}
	if tamper != nil {
		tamper(&req)
	}
	return call(h, "/api/auth/login/finish", req)
}

func TestWebAuthnEnrollLoginFlow(t *testing.T) {
	ws, h := testWeb(t)
	key := newSoftKey(t)

	// Nothing registered: no login possible, and no registration without the link.
	if w := call(h, "/api/auth/login/begin", struct{}{}); w.Code != http.StatusConflict {
		t.Fatalf("login with no keys: %d", w.Code)
	}
	if w := key.register(t, h); w.Code != http.StatusUnauthorized {
		t.Fatalf("register without enrollment: %d %s", w.Code, w.Body.String())
	}

	// The enrollment link → cookie → register; that also unlocks.
	tok, err := ws.auth.issueEnroll()
	if err != nil {
		t.Fatal(err)
	}
	w := do(h, "GET", "/enroll?t="+tok, "", func(r *http.Request) { r.Header.Del("Cookie") })
	enroll := cookieFrom(w, "mintk_enroll_47999")
	if w.Code != http.StatusSeeOther || enroll == nil {
		t.Fatalf("enroll link: %d", w.Code)
	}
	w = key.register(t, h, enroll)
	if w.Code != 200 {
		t.Fatalf("register: %d %s", w.Code, w.Body.String())
	}
	sess := cookieFrom(w, "mintk_session_47999")
	if sess == nil || !ws.auth.sessionOK(sess.Value) {
		t.Fatal("registration did not unlock")
	}
	// One link, one key.
	if w := newSoftKey(t).register(t, h, enroll); w.Code != http.StatusUnauthorized {
		t.Fatalf("enrollment link reused: %d", w.Code)
	}

	// Login with the key.
	w = key.login(t, h, nil)
	if w.Code != 200 || cookieFrom(w, "mintk_session_47999") == nil {
		t.Fatalf("login: %d %s", w.Code, w.Body.String())
	}

	// Each of these must be refused.
	other := newSoftKey(t)
	for name, tamper := range map[string]func(*loginFinish){
		"bad signature": func(r *loginFinish) {
			sig, _ := b64u.DecodeString(r.Signature)
			sig[len(sig)-1] ^= 1
			r.Signature = b64u.EncodeToString(sig)
		},
		"wrong origin": func(r *loginFinish) {
			cd, _ := b64u.DecodeString(r.ClientData)
			var c clientData
			_ = json.Unmarshal(cd, &c)
			r.ClientData = b64u.EncodeToString(clientDataJSON("webauthn.get", c.Challenge, "http://evil.example"))
		},
		"replayed challenge": func(r *loginFinish) {
			cd, _ := b64u.DecodeString(r.ClientData)
			var c clientData
			_ = json.Unmarshal(cd, &c)
			ws.auth.takeChallenge(c.Challenge, "login") // consumed already
		},
		"unregistered key": func(r *loginFinish) { r.ID = b64u.EncodeToString(other.id) },
	} {
		if w := key.login(t, h, tamper); w.Code != http.StatusUnauthorized {
			t.Errorf("%s: got %d %s", name, w.Code, w.Body.String())
		}
	}

	// A counter going backwards (a cloned key) is refused.
	key.count = 0
	if w := key.login(t, h, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("counter rollback accepted: %d", w.Code)
	}
}

func TestWebAuthnKeyManagement(t *testing.T) {
	ws, h := testWeb(t)
	a := newSoftKey(t)
	sess := &http.Cookie{Name: "mintk_session_47999", Value: testSession}
	// From an unlocked session, keys can be added without an enrollment link.
	if w := a.register(t, h, sess); w.Code != 200 {
		t.Fatalf("add key: %d %s", w.Code, w.Body.String())
	}
	if w := a.register(t, h, sess); w.Code != http.StatusConflict {
		t.Fatalf("duplicate key: %d", w.Code)
	}
	// The only key can't be deleted.
	if w := call(h, "/api/auth/keys/delete", map[string]string{"id": b64u.EncodeToString(a.id)}, sess); w.Code != http.StatusConflict {
		t.Fatalf("delete last key: %d", w.Code)
	}
	b := newSoftKey(t)
	if w := b.register(t, h, sess); w.Code != 200 {
		t.Fatalf("add second key: %d", w.Code)
	}
	if w := call(h, "/api/auth/keys/delete", map[string]string{"id": b64u.EncodeToString(a.id)}, sess); w.Code != 200 {
		t.Fatalf("delete key: %d %s", w.Code, w.Body.String())
	}
	if w := a.login(t, h, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("deleted key still logs in: %d", w.Code)
	}
	// Logout ends the session.
	call(h, "/api/auth/logout", struct{}{}, sess)
	if ws.auth.sessionOK(testSession) {
		t.Fatal("session survived logout")
	}
}

func TestParseAuthDataRejects(t *testing.T) {
	k := newSoftKey(t)
	if _, _, err := parseAuthData(k.authData("evil.example", false)); err == nil {
		t.Fatal("foreign RP ID accepted")
	}
	ad := k.authData(webRPID, false)
	ad[32] &^= flagUP
	if _, _, err := parseAuthData(ad); err == nil {
		t.Fatal("missing user presence accepted")
	}
	if _, _, err := parseAuthData(ad[:20]); err == nil {
		t.Fatal("short authData accepted")
	}
}
