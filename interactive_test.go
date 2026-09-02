package main

import (
	"testing"
	"time"
)

// The shape `ssh-keygen -L` actually prints for a minted cert — principals sit
// on their own indented lines after the header, so the validity line has to be
// matched, not counted to.
const testCertListing = `/home/u/.ssh/sessions/demo-cert.pub:
        Type: ssh-ed25519-cert-v01@openssh.com user certificate
        Public key: ED25519-CERT SHA256:dUexampleexampleexampleexampleexampleexample
        Signing CA: ED25519 SHA256:BkexampleexampleexampleexampleexampleexampleX (using ssh-ed25519)
        Key ID: "user-demo-20260811T013612"
        Serial: 1786401372
        Valid: from 2026-08-11T01:35:00 to 2026-08-11T06:36:12
        Principals:
                demo-p
        Critical Options: (none)
        Extensions:
                permit-pty
`

func TestParseCertValidTo(t *testing.T) {
	got, ok := parseCertValidTo(testCertListing)
	if !ok {
		t.Fatal("parseCertValidTo found no validity window")
	}
	want := time.Date(2026, 8, 11, 6, 36, 12, 0, time.Local)
	if !got.Equal(want) {
		t.Errorf("parseCertValidTo = %v, want %v", got, want)
	}
}

func TestParseCertValidToRejects(t *testing.T) {
	// A cert with no expiry has nothing to count down to, and neither does
	// output that isn't a cert listing at all.
	for _, in := range []string{
		"        Valid: forever\n",
		"not a cert listing\n",
		"",
		"        Valid: from 2026-08-11T01:35:00 to not-a-timestamp\n",
	} {
		if _, ok := parseCertValidTo(in); ok {
			t.Errorf("parseCertValidTo(%q) reported a validity window", in)
		}
	}
}

func TestCertSummaryLine(t *testing.T) {
	if got := certSummaryLine(&Config{}); got != "(no scopes configured)" {
		t.Errorf("certSummaryLine with no scopes = %q", got)
	}
	// A scope whose cert file doesn't exist must read as not live, not error.
	cfg := &Config{SessionsDir: "/nonexistent-mintk-sessions", Scopes: []Scope{
		{Name: "a", Principal: "pa", TTL: "8h"},
		{Name: "b", Principal: "pb", TTL: "1h"},
	}}
	if got := certSummaryLine(cfg); got != "2 scope(s), 0 live" {
		t.Errorf("certSummaryLine = %q, want \"2 scope(s), 0 live\"", got)
	}
	if want := "2 configured — add one, or change its default mint time"; scopesSummaryLine(cfg) != want {
		t.Errorf("scopesSummaryLine = %q, want %q", scopesSummaryLine(cfg), want)
	}
}
