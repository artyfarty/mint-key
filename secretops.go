package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// The secret edits shared by the CLI, `mintk i` and `mintk web`.
//
// Storing a value needs no card: a blob is encrypted to the *public* recipients.
// Only reading one back (a grant, `secret edit` of an existing secret) decrypts,
// and that is the step that needs the YubiKey. This is what lets the browser
// create and replace secrets write-only: the value goes in, the plaintext of an
// existing secret never comes out.

var secretFormats = []string{"env", "opaque"}

// storeSecret encrypts a value to the configured recipients, replaces the blob
// atomically, drops a live grant that now holds the old value, and commits.
// The plaintext only ever exists in memory and on age's stdin.
func (sess *secretSession) storeSecret(name string, plain []byte, push bool) error {
	if err := validScopeName(name); err != nil {
		return err
	}
	if len(bytes.TrimSpace(plain)) == 0 {
		return fmt.Errorf("refusing to store an empty secret")
	}
	blobPath, err := sess.sec.blobPath(name)
	if err != nil {
		return err
	}
	recipients, err := sess.sec.recipientList()
	if err != nil {
		return err
	}
	client, err := sess.ageClient()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(blobPath), 0o755); err != nil {
		return err
	}
	verb := "update"
	if !fileExists(blobPath) {
		verb = "add"
	}
	ct, err := client.encrypt(plain, recipients)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(blobPath, ct, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(outW, "%s: encrypted %s to %d recipient(s) → %s\n", prog, name, len(recipients), blobPath)

	// A live grant now holds the *old* value; drop it so nothing serves a stale
	// secret with a valid-looking deadline.
	if _, ok := sess.st.live(name); ok {
		sess.st.wipe(name, "")
		fmt.Fprintf(outW, "%s: revoked the live grant for %s (its value just changed)\n", prog, name)
	}
	return sess.commitBlob(blobPath, fmt.Sprintf("mintk: %s secret %s", verb, name), push)
}

// removeSecret revokes any live grant, deletes the blob and commits the removal.
// The local policy entry (ttl/format) goes too, so a later secret of the same
// name starts from the defaults.
func (sess *secretSession) removeSecret(name string, push bool) error {
	blobPath, err := sess.sec.blobPath(name)
	if err != nil {
		return err
	}
	if !fileExists(blobPath) {
		return fmt.Errorf("no blob for %q at %s", name, blobPath)
	}
	sess.st.wipe(name, "")
	if err := os.Remove(blobPath); err != nil {
		return err
	}
	fmt.Fprintf(outW, "%s: removed %s\n", prog, blobPath)
	if err := sess.commitBlob(blobPath, fmt.Sprintf("mintk: remove secret %s", name), push); err != nil {
		return err
	}
	if sc, ok := sess.sec.scope(name); ok && sc.File == "" {
		if err := setSecretPolicy(sess.cfg, name, ptr(""), ptr("")); err != nil {
			return err
		}
	}
	return nil
}

func ptr(s string) *string { return &s }

// setSecretPolicy sets a secret's default grant lifetime and/or its format in
// the local config (`secrets.scopes`). nil leaves a field alone; "" resets it to
// the default. An entry left with nothing in it is dropped.
func setSecretPolicy(cfg *Config, name string, ttl, format *string) error {
	if err := validScopeName(name); err != nil {
		return err
	}
	if cfg.Secrets == nil {
		return fmt.Errorf("no secrets: section in the config")
	}
	if ttl != nil {
		*ttl = strings.TrimSpace(*ttl)
		if *ttl != "" {
			if _, err := parseTTL(*ttl); err != nil {
				return err
			}
		}
	}
	if format != nil {
		*format = strings.TrimSpace(*format)
		if *format != "" && !validSecretFormat(*format) {
			return fmt.Errorf("format must be one of %s", strings.Join(secretFormats, ", "))
		}
	}

	sec := cfg.Secrets
	i := -1
	for j := range sec.Scopes {
		if sec.Scopes[j].Name == name {
			i = j
			break
		}
	}
	if i < 0 {
		sec.Scopes = append(sec.Scopes, SecretScope{Name: name})
		i = len(sec.Scopes) - 1
	}
	if ttl != nil {
		sec.Scopes[i].TTL = *ttl
	}
	if format != nil {
		sec.Scopes[i].Format = *format
	}
	if s := sec.Scopes[i]; s.TTL == "" && s.Format == "" && s.File == "" {
		sec.Scopes = append(sec.Scopes[:i], sec.Scopes[i+1:]...)
	}
	return cfg.save()
}

func validSecretFormat(f string) bool {
	for _, x := range secretFormats {
		if f == x {
			return true
		}
	}
	return false
}
