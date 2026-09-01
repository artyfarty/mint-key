package main

import (
	"strings"
	"testing"
)

func TestFirstPubKeyLine(t *testing.T) {
	// A terminal title escape landing in a ca.pub is the case this exists for.
	junk := "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQ= ca\n\x1b]0;~/work/somewhere\x07\n"

	cases := []struct {
		name, in, want string
		wantErr        bool
	}{
		{name: "plain", in: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 ca\n", want: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 ca"},
		{name: "escape junk after key", in: junk, want: "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQ= ca"},
		{name: "escape junk before key", in: "\x1b]0;title\x07\n\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5 ca\n",
			want: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 ca"},
		{name: "comments skipped", in: "# my CA\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5 ca\n", want: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 ca"},
		{name: "control chars inside the key line stripped", in: "ssh-ed25519\x00 AAAAC3NzaC1lZDI1NTE5 ca", want: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 ca"},
		{name: "not base64", in: "ssh-ed25519 not!base64! ca\n", wantErr: true},
		{name: "unknown type", in: "hunter2 AAAAC3NzaC1lZDI1NTE5 ca\n", wantErr: true},
		{name: "empty", in: "\n\n", wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := firstPubKeyLine(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatalf("want error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != c.want {
				t.Errorf("got  %q\nwant %q", got, c.want)
			}
		})
	}
}

// The principals file must be named after the account's canonical passwd name,
// not the (possibly aliased) name typed on the command line — sshd expands
// AuthorizedPrincipalsFile's %u to the former.
func TestTrustScriptCanonicalisesLoginUser(t *testing.T) {
	s := buildTrustScript("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 ca", "artyfarty", "machines")
	for _, want := range []string{
		`canon=$(id -un "$user"`,
		`user=$canon`,
		`touch "$princ_dir/$user"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("trust script is missing %q", want)
		}
	}
}
