package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func secretCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secret",
		Short: "Grant scoped, time-limited access to credentials (the sibling of `key`)",
		Long: `Secret grants are cert minting's shape applied to credentials instead of hosts.
Secrets live as age-encrypted blobs, one per scope, in a git repo — so the host
storing them can never read them. ` + "`secret grant`" + ` costs one YubiKey interaction,
decrypts one scope, parks the plaintext on tmpfs (mode 0600) and records an
expiry; an independent wiper destroys it at TTL. For the life of the grant the
consumer reads a file, not the card.

Per-read auditing is impossible by construction — see docs/secrets.md.`,
	}
	cmd.AddCommand(secretInitCmd())
	cmd.AddCommand(secretGrantCmd())
	cmd.AddCommand(secretRunCmd())
	cmd.AddCommand(secretPathCmd())
	cmd.AddCommand(secretListCmd())
	cmd.AddCommand(secretRevokeCmd())
	cmd.AddCommand(secretPrintCmd())
	cmd.AddCommand(secretEditCmd())
	cmd.AddCommand(secretReencryptCmd())
	cmd.AddCommand(secretRmCmd())
	cmd.AddCommand(secretPullCmd())
	cmd.AddCommand(secretPushCmd())
	cmd.AddCommand(secretSweepCmd())
	cmd.AddCommand(secretReapCmd())
	return cmd
}

// secretSession is the config + tmpfs store every secret command needs.
type secretSession struct {
	cfg *Config
	sec *SecretsConfig
	st  *grantStore
}

// openSecrets loads the config, prepares the tmpfs store and sweeps anything
// already expired — so an expired grant is gone before any command can look at
// it, whether or not its own wiper ever ran.
func openSecrets() (*secretSession, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}
	sec, err := cfg.secretsConfig()
	if err != nil {
		return nil, err
	}
	st, err := newGrantStore(sec)
	if err != nil {
		return nil, err
	}
	st.sweep()
	return &secretSession{cfg: cfg, sec: sec, st: st}, nil
}

// --- grant -------------------------------------------------------------------

func secretGrantCmd() *cobra.Command {
	var ttl string
	cmd := &cobra.Command{
		Use:   "grant <scope> [<scope>...] [<ttl>]",
		Short: "Decrypt scope(s) to tmpfs for <ttl> — this is the tap",
		Long: `Decrypt each scope's blob and park the plaintext on tmpfs (mode 0600) until the
TTL runs out, when an independent wiper destroys it.

Granting several scopes at once is worth doing: a touch policy of ` + "`cached`" + ` serves
the whole burst from a single tap. A decrypt failure aborts the burst instead of
moving on — the PIV PIN is applet-wide, so three bad attempts would also block
the CA signing slot that ` + "`mintk key`" + ` needs.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			scopes, ttl := splitTrailingTTL(args, ttl)
			return runSecretGrant(scopes, ttl)
		},
	}
	cmd.Flags().StringVar(&ttl, "ttl", "", "grant lifetime (default: the scope's, else secrets.default_ttl)")
	return cmd
}

// splitTrailingTTL supports `grant <scope> <ttl>` alongside `--ttl`, mirroring
// `mintk key <scope> [<ttl>]`. Only a *last* argument that is unambiguously a
// duration and not itself a scope name is taken as the TTL.
func splitTrailingTTL(args []string, ttl string) ([]string, string) {
	if ttl != "" || len(args) < 2 {
		return args, ttl
	}
	last := args[len(args)-1]
	if _, err := parseTTL(last); err != nil {
		return args, ttl
	}
	return args[:len(args)-1], last
}

func runSecretGrant(names []string, ttlOverride string) error {
	sess, err := openSecrets()
	if err != nil {
		return err
	}

	// Resolve every scope (and read every blob) before touching the card, so a
	// typo can't cost a tap.
	type job struct {
		name string
		ttl  string
		d    time.Duration
		blob []byte
	}
	jobs := make([]job, 0, len(names))
	for _, name := range names {
		if err := validScopeName(name); err != nil {
			return err
		}
		ttl := ttlOverride
		if ttl == "" {
			ttl = sess.sec.scopeTTL(name)
		}
		d, err := parseTTL(ttl)
		if err != nil {
			return err
		}
		p, err := sess.sec.blobPath(name)
		if err != nil {
			return err
		}
		blob, err := os.ReadFile(p)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("unknown secret scope %q (no blob at %s)\n"+
					"  try: %s secret list   or create it: %s secret edit %s", name, p, prog, prog, name)
			}
			return err
		}
		jobs = append(jobs, job{name: name, ttl: ttl, d: d, blob: blob})
	}

	client, err := newAgeClient(sess.sec)
	if err != nil {
		return err
	}
	if len(jobs) > 1 {
		fmt.Printf("%s: granting %d scopes in one burst — a `cached` touch policy serves them from one tap\n",
			prog, len(jobs))
	}

	for _, j := range jobs {
		fmt.Printf("%s: granting %s  +%s  [YubiKey — PIN if needed + touch]\n", prog, j.name, j.ttl)
		plain, err := client.decrypt(j.blob)
		if err != nil {
			printPINWarning()
			return err
		}
		if len(plain) == 0 {
			return fmt.Errorf("scope %q decrypted to nothing — refusing to grant an empty secret", j.name)
		}
		g, err := sess.st.write(j.name, plain, j.ttl, j.d)
		if err != nil {
			return err
		}
		if err := sess.st.armWiper(g); err != nil {
			// An unwatched secret is worse than no secret: destroy it.
			sess.st.wipe(j.name, g.Serial)
			return fmt.Errorf("%s: %w (grant destroyed — nothing would have expired it)", j.name, err)
		}
		fmt.Printf("       %s  expires %s  (%s wiper)\n",
			sess.st.path(j.name), g.ExpiresAt.Format("15:04:05"), g.Wiper)
	}
	return nil
}

// printPINWarning is shown on any decrypt failure: the PIV PIN is shared with
// the CA slot, so blind retries are how you lock yourself out of both.
func printPINWarning() {
	fmt.Fprintf(os.Stderr, "\n%s: the decrypt failed and was NOT retried.\n", prog)
	fmt.Fprintf(os.Stderr, "  The PIV PIN is applet-wide: three wrong entries block the applet, which also\n")
	fmt.Fprintf(os.Stderr, "  kills `%s key` (the CA signing slot). Check the card is present and the PIN is\n", prog)
	fmt.Fprintf(os.Stderr, "  right before trying again — see docs/secrets.md.\n")
}

// --- run ---------------------------------------------------------------------

func secretRunCmd() *cobra.Command {
	var ttl string
	var noGrant bool
	cmd := &cobra.Command{
		Use:   "run <scope> [<scope>...] -- <command> [args...]",
		Short: "Run a command with the granted secret(s) in its environment",
		Long: `The consumption path that keeps plaintext out of your scrollback: the command
gets $MINTK_SECRET_<SCOPE> pointing at the granted file, and for scopes with
` + "`format: env`" + ` the blob's KEY=VALUE lines are injected as environment variables.
Scopes that aren't granted yet are granted first (one tap for the burst).`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			dash := cmd.ArgsLenAtDash()
			if dash < 1 || dash >= len(args) {
				return fmt.Errorf("separate the scopes from the command with `--`, e.g.\n"+
					"  %s secret run my-scope -- env", prog)
			}
			return runSecretRun(args[:dash], args[dash:], ttl, noGrant)
		},
	}
	cmd.Flags().StringVar(&ttl, "ttl", "", "lifetime for scopes granted by this call")
	cmd.Flags().BoolVar(&noGrant, "no-grant", false, "fail instead of granting a scope that isn't live")
	return cmd
}

func runSecretRun(names, argv []string, ttl string, noGrant bool) error {
	sess, err := openSecrets()
	if err != nil {
		return err
	}
	var missing []string
	for _, n := range names {
		if err := validScopeName(n); err != nil {
			return err
		}
		if _, ok := sess.st.live(n); !ok {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		if noGrant {
			return fmt.Errorf("no live grant for %s (--no-grant)", strings.Join(missing, ", "))
		}
		if err := runSecretGrant(missing, ttl); err != nil {
			return err
		}
	}

	env, err := sess.childEnv(names)
	if err != nil {
		return err
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		// Pass the child's exit status through unchanged.
		if ee, ok := err.(*exec.ExitError); ok {
			os.Exit(ee.ExitCode())
		}
		return err
	}
	return nil
}

// childEnv builds the environment for `secret run`: a path variable per scope,
// plus the parsed KEY=VALUE pairs of every `format: env` scope.
//
// Both the file and the child's environment are readable by anything running as
// this user (/proc/<pid>/environ) — the grant bounds *time*, not who on the box
// can look. That is the same bargain a minted cert in the agent makes.
func (sess *secretSession) childEnv(names []string) ([]string, error) {
	env := os.Environ()
	for _, n := range names {
		p := sess.st.path(n)
		env = append(env, "MINTK_SECRET_"+envSafe(n)+"="+p)
		if sess.sec.scopeFormat(n) != "env" {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		kv, err := parseDotenv(string(data))
		if err != nil {
			return nil, fmt.Errorf("scope %q (format: env): %w", n, err)
		}
		env = append(env, kv...)
	}
	if len(names) == 1 {
		env = append(env, "MINTK_SECRET_FILE="+sess.st.path(names[0]))
	}
	return env, nil
}

// envSafe turns a scope name into an environment-variable-safe suffix.
func envSafe(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range strings.ToUpper(s) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			out = append(out, r)
		} else {
			out = append(out, '_')
		}
	}
	return string(out)
}

// parseDotenv reads KEY=VALUE lines (an optional `export ` prefix, '#' comments,
// optional matching quotes around the value).
func parseDotenv(s string) ([]string, error) {
	var out []string
	for i, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			return nil, fmt.Errorf("line %d is not KEY=VALUE", i+1)
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		out = append(out, k+"="+v)
	}
	return out, nil
}

// --- path / list / revoke / print --------------------------------------------

func secretPathCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "path <scope>",
		Short: "Print the tmpfs path of a live grant (the path, never the secret)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sess, err := openSecrets()
			if err != nil {
				return err
			}
			if _, ok := sess.st.live(args[0]); !ok {
				return fmt.Errorf("no live grant for %q — run: %s secret grant %s", args[0], prog, args[0])
			}
			fmt.Println(sess.st.path(args[0]))
			return nil
		},
	}
}

func secretListCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List secret scopes and which of them are currently granted",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			sess, err := openSecrets()
			if err != nil {
				return err
			}
			scopes := sess.sec.listSecretScopes()
			if len(scopes) == 0 {
				fmt.Printf("no secret scopes in %s\n", sess.sec.blobDir())
				return nil
			}
			fmt.Printf("secret scopes (blobs in %s):\n", sess.sec.blobDir())
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "  SCOPE\tTTL\tFORMAT\tGRANT")
			for _, n := range scopes {
				state := "-"
				if g, ok := sess.st.live(n); ok {
					state = "expires in " + shortDuration(g.remaining())
				}
				fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n", n, sess.sec.scopeTTL(n), sess.sec.scopeFormat(n), state)
			}
			w.Flush()
			fmt.Printf("grants live on %s\n", sess.st.root)
			return nil
		},
	}
	return cmd
}

// shortDuration renders a remaining lifetime compactly (2h14m, 47s).
func shortDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	switch {
	case h > 0:
		return fmt.Sprintf("%dh%02dm", h, m)
	case m > 0:
		return fmt.Sprintf("%dm%02ds", m, s)
	default:
		return fmt.Sprintf("%ds", s)
	}
}

func secretRevokeCmd() *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:   "revoke [<scope>...]",
		Short: "Wipe grant(s) now instead of waiting for the TTL",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			sess, err := openSecrets()
			if err != nil {
				return err
			}
			if all {
				for _, g := range sess.st.list() {
					args = append(args, g.Scope)
				}
				sort.Strings(args)
			}
			if len(args) == 0 {
				return fmt.Errorf("name a scope, or pass --all")
			}
			for _, n := range args {
				if err := validScopeName(n); err != nil {
					return err
				}
				sess.st.wipe(n, "")
				fmt.Printf("%s: revoked %s\n", prog, n)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "revoke every live grant")
	return cmd
}

func secretPrintCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "print <scope>",
		Short: "Write a secret to stdout (escape hatch — prefer `secret run`/`secret path`)",
		Long: `Deliberately not the default consumption path: whatever is printed here lands in
your terminal scrollback, and in the transcript of any agent that ran the
command. Use ` + "`secret run`" + ` (env injection) or ` + "`secret path`" + ` (read the file) unless
you specifically need the bytes on stdout. Asks for confirmation when stdout is
a terminal.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sess, err := openSecrets()
			if err != nil {
				return err
			}
			name := args[0]
			if err := validScopeName(name); err != nil {
				return err
			}
			if _, ok := sess.st.live(name); !ok {
				if err := runSecretGrant([]string{name}, ""); err != nil {
					return err
				}
			}
			if isTerminal(os.Stdout) && !yes {
				if !isInteractive() {
					return fmt.Errorf("refusing to print to a terminal without confirmation; pass -y")
				}
				ok, err := promptYesNo(fmt.Sprintf("Print %q to this terminal (it stays in scrollback)?", name), false)
				if err != nil || !ok {
					return fmt.Errorf("aborted")
				}
			}
			data, err := os.ReadFile(sess.st.path(name))
			if err != nil {
				return err
			}
			_, err = os.Stdout.Write(data)
			return err
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "skip the terminal confirmation")
	return cmd
}

func isTerminal(f *os.File) bool { return term.IsTerminal(int(f.Fd())) }

// --- edit / rm ---------------------------------------------------------------

func secretEditCmd() *cobra.Command {
	var push bool
	var allowEmpty bool
	cmd := &cobra.Command{
		Use:   "edit <scope>",
		Short: "Decrypt a scope into $EDITOR on tmpfs, re-encrypt and commit",
		Long: `Decrypts the scope's blob into a 0700 workspace on tmpfs, opens $EDITOR on it,
re-encrypts the result to the configured recipients and commits the blob. The
plaintext never leaves tmpfs; the workspace is wiped on exit, on SIGINT/SIGTERM/
SIGHUP, and — if the process is killed outright — by the next command's sweep,
which drops any workspace whose owning process is gone. A reboot clears it
regardless. Creating a scope is just editing one that doesn't exist yet.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecretEdit(args[0], push, allowEmpty)
		},
	}
	cmd.Flags().BoolVar(&push, "push", false, "git push after committing")
	cmd.Flags().BoolVar(&allowEmpty, "allow-empty", false, "accept an empty secret (normally a mistake)")
	return cmd
}

func runSecretEdit(name string, push, allowEmpty bool) error {
	sess, err := openSecrets()
	if err != nil {
		return err
	}
	if err := validScopeName(name); err != nil {
		return err
	}
	blobPath, err := sess.sec.blobPath(name)
	if err != nil {
		return err
	}
	// Fail on anything we can check before the card is involved.
	recipients, err := sess.sec.recipientList()
	if err != nil {
		return err
	}
	client, err := newAgeClient(sess.sec)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(blobPath), 0o755); err != nil {
		return err
	}

	ws := filepath.Join(sess.st.editDir(), fmt.Sprintf("%s.%d", name, os.Getpid()))
	if err := os.MkdirAll(ws, 0o700); err != nil {
		return err
	}
	defer sess.st.wipeTree(ws)
	stop := wipeOnSignal(sess.st, ws)
	defer stop()

	work := filepath.Join(ws, name)
	var before []byte
	if fileExists(blobPath) {
		blob, err := os.ReadFile(blobPath)
		if err != nil {
			return err
		}
		fmt.Printf("%s: decrypting %s for editing  [YubiKey — PIN if needed + touch]\n", prog, name)
		if before, err = client.decrypt(blob); err != nil {
			printPINWarning()
			return err
		}
	} else {
		fmt.Printf("%s: %s doesn't exist yet — creating it\n", prog, name)
	}
	if err := os.WriteFile(work, before, 0o600); err != nil {
		return err
	}

	if err := runEditor(work); err != nil {
		return err
	}
	after, err := os.ReadFile(work)
	if err != nil {
		return err
	}
	if bytes.Equal(before, after) {
		fmt.Printf("%s: unchanged — nothing re-encrypted\n", prog)
		return nil
	}
	if len(bytes.TrimSpace(after)) == 0 && !allowEmpty {
		return fmt.Errorf("refusing to store an empty secret (pass --allow-empty if that's intended)")
	}

	ct, err := client.encrypt(after, recipients)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(blobPath, ct, 0o600); err != nil {
		return err
	}
	fmt.Printf("%s: encrypted %s to %d recipient(s) → %s\n", prog, name, len(recipients), blobPath)

	// A live grant now holds the *old* value; drop it so nothing serves a stale
	// secret with a valid-looking deadline.
	if _, ok := sess.st.live(name); ok {
		sess.st.wipe(name, "")
		fmt.Printf("%s: revoked the live grant for %s (its value just changed)\n", prog, name)
	}

	return sess.commitBlob(blobPath, fmt.Sprintf("mintk: update secret %s", name), push)
}

// wipeOnSignal destroys the edit workspace if we're interrupted while the editor
// has the terminal. Returns a function that unregisters the handler.
func wipeOnSignal(st *grantStore, ws string) func() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		if _, ok := <-ch; !ok {
			return
		}
		st.wipeTree(ws)
		os.Exit(130)
	}()
	return func() { signal.Stop(ch); close(ch) }
}

// runEditor opens $VISUAL/$EDITOR (else vi) on a file, terminal attached. The
// editor string is split on whitespace so "code --wait" works.
func runEditor(path string) error {
	ed := os.Getenv("VISUAL")
	if ed == "" {
		ed = os.Getenv("EDITOR")
	}
	if ed == "" {
		ed = "vi"
	}
	parts := strings.Fields(ed)
	args := append(parts[1:], path)
	if err := run(parts[0], args...); err != nil {
		return fmt.Errorf("editor %q failed: %w", ed, err)
	}
	return nil
}

// writeFileAtomic writes via a temp file in the same directory + rename, so a
// crash mid-write can't leave a truncated blob where a secret used to be.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".mintk-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func secretReencryptCmd() *cobra.Command {
	var all bool
	var push bool
	cmd := &cobra.Command{
		Use:   "reencrypt [<scope>...]",
		Short: "Re-encrypt blobs to the current recipient list (after adding/removing a key)",
		Long: `The recipient list is baked into a blob when it is written, so changing
recipients does NOT change who can read what already exists — those blobs still
carry the old set. This rewrites them: decrypt with a key that is already on the
blob, re-encrypt to the configured recipients, commit.

Run it after adding a YubiKey (or a break-glass recipient) to the list, and after
removing one — until you do, a removed key still opens every existing blob.
The plaintext is unchanged, so live grants are left alone.

Costs one card interaction per blob, served from the touch cache in a burst.`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecretReencrypt(args, all, push)
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "re-encrypt every scope in the repo")
	cmd.Flags().BoolVar(&push, "push", false, "git push after committing")
	return cmd
}

func runSecretReencrypt(names []string, all, push bool) error {
	sess, err := openSecrets()
	if err != nil {
		return err
	}
	if all {
		names = sess.sec.listSecretScopes()
	}
	if len(names) == 0 {
		return fmt.Errorf("name a scope, or pass --all")
	}
	recipients, err := sess.sec.recipientList()
	if err != nil {
		return err
	}
	client, err := newAgeClient(sess.sec)
	if err != nil {
		return err
	}

	// Resolve every blob before touching the card, as `grant` does.
	paths := make([]string, 0, len(names))
	for _, name := range names {
		p, err := sess.sec.blobPath(name)
		if err != nil {
			return err
		}
		if !fileExists(p) {
			return fmt.Errorf("no blob for %q at %s", name, p)
		}
		paths = append(paths, p)
	}

	fmt.Printf("%s: re-encrypting %d blob(s) to %d recipient(s)\n", prog, len(paths), len(recipients))
	for i, name := range names {
		blob, err := os.ReadFile(paths[i])
		if err != nil {
			return err
		}
		fmt.Printf("%s: %s  [YubiKey — PIN if needed + touch]\n", prog, name)
		plain, err := client.decrypt(blob)
		if err != nil {
			printPINWarning()
			return err
		}
		ct, err := client.encrypt(plain, recipients)
		if err != nil {
			return err
		}
		if err := writeFileAtomic(paths[i], ct, 0o600); err != nil {
			return err
		}
		if err := sess.commitBlob(paths[i], fmt.Sprintf("mintk: re-encrypt secret %s", name), false); err != nil {
			return err
		}
	}
	if push {
		dir, err := sess.gitDir()
		if err != nil {
			return err
		}
		fmt.Printf("%s: git push in %s\n", prog, dir)
		return run("git", "-C", dir, "push")
	}
	return nil
}

func secretRmCmd() *cobra.Command {
	var push bool
	var yes bool
	cmd := &cobra.Command{
		Use:   "rm <scope>",
		Short: "Delete a scope's blob from the repo (and revoke any live grant)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sess, err := openSecrets()
			if err != nil {
				return err
			}
			name := args[0]
			blobPath, err := sess.sec.blobPath(name)
			if err != nil {
				return err
			}
			if !fileExists(blobPath) {
				return fmt.Errorf("no blob for %q at %s", name, blobPath)
			}
			if !yes {
				if !isInteractive() {
					return fmt.Errorf("refusing to delete without confirmation; re-run with -y/--yes")
				}
				ok, err := promptYesNo(fmt.Sprintf("Delete the secret blob for %q?", name), false)
				if err != nil || !ok {
					fmt.Printf("%s: aborted\n", prog)
					return nil
				}
			}
			sess.st.wipe(name, "")
			if err := os.Remove(blobPath); err != nil {
				return err
			}
			fmt.Printf("%s: removed %s\n", prog, blobPath)
			return sess.commitBlob(blobPath, fmt.Sprintf("mintk: remove secret %s", name), push)
		},
	}
	cmd.Flags().BoolVar(&push, "push", false, "git push after committing")
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "skip the confirmation prompt")
	return cmd
}

// --- git sync ----------------------------------------------------------------

// secretsGitDir returns the blob repo, or an error if it isn't a git repo.
func (sess *secretSession) gitDir() (string, error) {
	dir := sess.sec.repoPath()
	if dir == "" {
		return "", fmt.Errorf("set secrets.repo to the git repo holding your blobs")
	}
	if !isGitRepo(dir) {
		return "", fmt.Errorf("%s is not a git repository — clone/init your secrets repo there first", dir)
	}
	return dir, nil
}

// commitBlob stages and commits just this blob (never whatever else the operator
// happens to have staged), and optionally pushes.
func (sess *secretSession) commitBlob(blobPath, msg string, push bool) error {
	dir, err := sess.gitDir()
	if err != nil {
		fmt.Printf("%s: note — %s; blob written but not committed\n", prog, err)
		return nil
	}
	if err := run("git", "-C", dir, "add", "--", blobPath); err != nil {
		return err
	}
	if exec.Command("git", "-C", dir, "diff", "--cached", "--quiet", "--", blobPath).Run() == nil {
		fmt.Printf("%s: nothing to commit (blob unchanged)\n", prog)
		return nil
	}
	if err := run("git", "-C", dir, "commit", "-m", msg, "--", blobPath); err != nil {
		return err
	}
	if push {
		fmt.Printf("%s: git push in %s\n", prog, dir)
		return run("git", "-C", dir, "push")
	}
	return nil
}

func secretPullCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "pull",
		Short: "git pull the secrets repo (sync the blobs down)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			sess, err := openSecrets()
			if err != nil {
				return err
			}
			dir, err := sess.gitDir()
			if err != nil {
				return err
			}
			fmt.Printf("%s: git pull in %s\n", prog, dir)
			return run("git", "-C", dir, "pull", "--ff-only")
		},
	}
}

func secretPushCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "push",
		Short: "git push the secrets repo",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			sess, err := openSecrets()
			if err != nil {
				return err
			}
			dir, err := sess.gitDir()
			if err != nil {
				return err
			}
			fmt.Printf("%s: git push in %s\n", prog, dir)
			return run("git", "-C", dir, "push")
		},
	}
}

// --- sweep / reap ------------------------------------------------------------

func secretSweepCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "sweep",
		Short: "Wipe expired grants, orphaned plaintext and abandoned edit workspaces",
		Long: `Idempotent backstop for the per-grant wipers: destroys anything past its
deadline, any plaintext with no grant record behind it, and any edit workspace
whose process is gone. Every secret command runs this first; it is also safe to
wire into a timer or a shell hook.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			sess, err := openSecrets() // openSecrets already sweeps
			if err != nil {
				return err
			}
			n := sess.st.sweep()
			fmt.Printf("%s: swept %s (%d item(s) removed in the second pass)\n", prog, sess.st.root, n)
			return nil
		},
	}
}

// secretReapCmd is the wiper's own entry point: the transient systemd unit and
// the detached fallback both re-exec mintk with this. Hidden — it isn't a UI.
//
// It takes the runtime dir as an argument and reads no config at all. That
// matters: a systemd --user unit runs in the user manager's environment, so it
// would not inherit $MINTK_CONFIG (nor anything else this shell has), and a
// wiper that can't find its config is a wiper that never fires.
func secretReapCmd() *cobra.Command {
	var root string
	cmd := &cobra.Command{
		Use:    "_reap --root <dir> <scope> <serial> [<delay-seconds>]",
		Short:  "internal: destroy a grant (optionally after a delay)",
		Hidden: true,
		Args:   cobra.RangeArgs(2, 3),
		RunE: func(cmd *cobra.Command, args []string) error {
			if root == "" {
				return fmt.Errorf("--root is required")
			}
			st := &grantStore{root: root}
			if len(args) == 3 {
				secs, err := strconv.ParseInt(args[2], 10, 64)
				if err != nil {
					return err
				}
				time.Sleep(time.Duration(secs) * time.Second)
			}
			st.wipe(args[0], args[1])
			st.sweep()
			return nil
		},
	}
	cmd.Flags().StringVar(&root, "root", "", "runtime dir holding the grant")
	return cmd
}
