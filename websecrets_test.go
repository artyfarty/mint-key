package main

import (
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testWebSecrets builds a server whose config has a software-mode secrets block:
// a real age, a real git repo, a throwaway X25519 identity.
func testWebSecrets(t *testing.T) (http.Handler, string, string) {
	t.Helper()
	for _, bin := range []string{"age", "age-keygen", "git"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed", bin)
		}
	}
	dir := t.TempDir()
	repo := filepath.Join(dir, "repo")
	id := filepath.Join(dir, "id.txt")
	mustRun(t, "age-keygen", "-o", id)
	out, err := exec.Command("age-keygen", "-y", id).Output()
	if err != nil {
		t.Fatal(err)
	}
	recipient := strings.TrimSpace(string(out))
	mustRun(t, "git", "init", "-q", repo)
	mustRun(t, "git", "-C", repo, "config", "user.email", "test@example.invalid")
	mustRun(t, "git", "-C", repo, "config", "user.name", "test")
	mustRun(t, "git", "-C", repo, "config", "commit.gpgsign", "false")

	cfg := filepath.Join(dir, "config.yaml")
	data := "mode: software\nsessions_dir: " + filepath.Join(dir, "sessions") + "\n" +
		"scopes:\n  - {name: alpha, principal: p-alpha, ttl: 8h}\n" +
		"secrets:\n  mode: software\n  repo: " + repo + "\n  identity: " + id + "\n" +
		"  recipients: [" + recipient + "]\n  runtime_dir: " + filepath.Join(dir, "rt") + "\n" +
		"  allow_non_tmpfs: true\n  default_ttl: 1h\n"
	if err := os.WriteFile(cfg, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MINTK_CONFIG", cfg)
	store := &credStore{path: filepath.Join(dir, "web-credentials.json")}
	ws := newWebServer(testPort, newWebAuth(store, filepath.Join(dir, "web-enroll.json"), testPort, time.Hour))
	testSession, _ = ws.auth.newSession()
	return ws.handler(), repo, id
}

func mustRun(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
}

func decryptBlob(t *testing.T, id, blob string) string {
	t.Helper()
	out, err := exec.Command("age", "-d", "-i", id, blob).Output()
	if err != nil {
		t.Fatalf("decrypt %s: %v", blob, err)
	}
	return string(out)
}

func TestWebSecretManagement(t *testing.T) {
	h, repo, id := testWebSecrets(t)
	blob := filepath.Join(repo, "secrets", "db.age")
	post := func(path string, body any) actionResult {
		t.Helper()
		b, _ := json.Marshal(body)
		w := do(h, "POST", path, string(b))
		var r actionResult
		if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
			t.Fatalf("%s: %v (%s)", path, err, w.Body.String())
		}
		return r
	}
	const secret = "PGPASSWORD=hunter2-very-secret"

	// Create, as env with its own ttl: no tap involved, just the recipients.
	r := post("/api/secrets/store", secretStoreReq{Name: "db", Value: secret, Format: "env", TTL: "15m", Create: true})
	if !r.OK {
		t.Fatalf("create: %s\n%s", r.Error, r.Log)
	}
	if strings.Contains(r.Log, "hunter2") {
		t.Fatalf("the value leaked into the transcript:\n%s", r.Log)
	}
	if got := decryptBlob(t, id, blob); got != secret+"\n" {
		t.Fatalf("blob decrypts to %q", got)
	}
	if log, _ := exec.Command("git", "-C", repo, "log", "--oneline").Output(); !strings.Contains(string(log), "add secret db") {
		t.Fatalf("not committed: %s", log)
	}

	// The state shows the policy, never a value.
	w := do(h, "GET", "/api/state", "")
	if strings.Contains(w.Body.String(), "hunter2") {
		t.Fatal("state carries the value")
	}
	var st webState
	_ = json.Unmarshal(w.Body.Bytes(), &st)
	if len(st.Secrets.Scopes) != 1 || st.Secrets.Scopes[0].TTL != "15m" || !st.Secrets.Scopes[0].TTLSet || st.Secrets.Scopes[0].Format != "env" {
		t.Fatalf("state: %+v", st.Secrets)
	}

	// Refusals: create over an existing one, replace a missing one, env that isn't KEY=VALUE, empty.
	for name, req := range map[string]secretStoreReq{
		"create twice":   {Name: "db", Value: "X=1", Create: true},
		"replace absent": {Name: "nope", Value: "x"},
		"bad env":        {Name: "db", Value: "just a password"},
		"empty":          {Name: "db", Value: "  \n"},
		"bad name":       {Name: "../x", Value: "x", Create: true},
	} {
		if r := post("/api/secrets/store", req); r.OK {
			t.Errorf("%s: accepted", name)
		}
	}

	// Replace the value.
	if r := post("/api/secrets/store", secretStoreReq{Name: "db", Value: "PGPASSWORD=new"}); !r.OK {
		t.Fatalf("replace: %s", r.Error)
	}
	if got := decryptBlob(t, id, blob); got != "PGPASSWORD=new\n" {
		t.Fatalf("after replace: %q", got)
	}

	// Policy: back to the global default ttl, format opaque.
	if r := post("/api/secrets/policy", map[string]any{"name": "db", "ttl": "", "format": "opaque"}); !r.OK {
		t.Fatalf("policy: %s", r.Error)
	}
	if r := post("/api/secrets/policy", map[string]any{"name": "db", "ttl": "forever"}); r.OK {
		t.Fatal("bad ttl accepted")
	}
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cfg.Secrets.scope("db"); ok {
		t.Fatalf("a policy entry with nothing left in it was kept: %+v", cfg.Secrets.Scopes)
	}

	// Delete.
	if r := post("/api/secrets/delete", map[string]any{"name": "db"}); !r.OK {
		t.Fatalf("delete: %s", r.Error)
	}
	if fileExists(blob) {
		t.Fatal("blob still there")
	}
	if log, _ := exec.Command("git", "-C", repo, "log", "--oneline").Output(); !strings.Contains(string(log), "remove secret db") {
		t.Fatalf("removal not committed: %s", log)
	}
}
