package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

func secretInitCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Interactively add the `secrets:` block to the config (set up secret grants)",
		Long: `Bootstrap the secret-grant subsystem on this machine: pick how the age client
reaches the card, locate age + age-plugin-yubikey, read the identity off an
inserted YubiKey, and point at (or clone, or create) the git repo holding the
blobs.

Like ` + "`mintk init`" + `, this only ever *reads* the YubiKey — it asks which slot to use
and never generates a key or writes to the card. Creating an age identity in a
PIV retired slot is a deliberate, separate step; see docs/secrets.md.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSecretInit(force)
		},
	}
	// No backticks in the usage text: pflag reads a backquoted word as the
	// flag's value placeholder.
	cmd.Flags().BoolVar(&force, "force", false, "replace an existing secrets block in the config")
	return cmd
}

func runSecretInit(force bool) error {
	// Merge into the existing config when there is one, so a machine that
	// already mints certs just gains a secrets block. Checked before the
	// terminal requirement, so a scripted run gets the useful error.
	path := configPath()
	var cfg *Config
	if fileExists(path) {
		var err error
		if cfg, err = loadConfig(); err != nil {
			return err
		}
		if cfg.Secrets != nil && !force {
			return fmt.Errorf("%s already has a `secrets:` block\n"+
				"  edit it directly, or pass --force to redo the setup", path)
		}
	}
	if !isInteractive() {
		return fmt.Errorf("`secret init` needs a terminal")
	}
	if cfg != nil {
		fmt.Printf("%s: adding secret grants to %s\n", prog, path)
		fmt.Printf("       (note: rewriting the config drops any comments you added to it)\n")
	} else {
		cfg = &Config{path: path}
		cfg.applyDefaults()
		fmt.Printf("%s: no config yet — writing one with only the secrets block.\n", prog)
		fmt.Printf("       Run `%s init` too if you also want to mint certs.\n", prog)
	}
	s := &SecretsConfig{}

	// --- how the age client reaches the card ---
	modes := []string{secretModeNative, secretModeWSL, secretModeSoft}
	modeDesc := map[string]string{
		secretModeNative: "age + age-plugin-yubikey run HERE, card via pcscd (Linux/macOS)",
		secretModeWSL:    "WSL runs the Windows age.exe; the card stays on Windows (no usbipd/pcscd)",
		secretModeSoft:   "a plain age identity file — TESTING ONLY, no hardware, no tap",
	}
	rec := secretModeNative
	if inWSL() {
		rec = secretModeWSL
	}
	var modeOpts []string
	recIdx := 0
	for i, m := range modes {
		label := fmt.Sprintf("%-12s — %s", m, modeDesc[m])
		if m == rec {
			label += "  [recommended here]"
			recIdx = i
		}
		modeOpts = append(modeOpts, label)
	}
	mi, err := promptChoiceDefault("Card access — how the age client reaches the YubiKey", modeOpts, recIdx)
	if err != nil {
		return err
	}
	s.Mode = modes[mi]
	s.applyDefaults()

	// --- the age binary and the plugin directory ---
	if err := initAgeBinaries(s); err != nil {
		return err
	}

	// --- the identity (read off the card, or a software key file) ---
	recipient, err := initIdentity(s)
	if err != nil {
		return err
	}

	// --- the blob repo ---
	repo, err := initSecretsRepo()
	if err != nil {
		return err
	}
	s.Repo = repo
	if err := os.MkdirAll(s.blobDir(), 0o755); err != nil {
		return err
	}
	if err := initRecipientsFile(s, recipient); err != nil {
		return err
	}

	// --- lifetime ---
	ttl, err := promptString("Default grant lifetime", "8h")
	if err != nil {
		return err
	}
	if _, err := normalizeTTL(ttl); err != nil {
		return err
	}
	s.DefaultTTL = strings.TrimSpace(ttl)

	cfg.Secrets = s
	if err := cfg.save(); err != nil {
		return err
	}
	fmt.Printf("\n%s: wrote %s\n", prog, cfg.path)

	// Grants need tmpfs; say so now rather than at the first grant.
	if root, rerr := runtimeDirPath(s); rerr != nil {
		fmt.Printf("%s: warning — %s\n", prog, firstLine(rerr.Error()))
	} else if fs := mountFSType(nearestExistingDir(root)); !isEphemeralFS(fs) {
		fmt.Printf("%s: warning — grants would land on %s (%s), not tmpfs; set secrets.runtime_dir\n",
			prog, root, fsOrUnknown(fs))
	} else {
		fmt.Printf("%s: grants will live on %s (%s)\n", prog, root, fs)
	}

	fmt.Printf("\nNext:\n")
	fmt.Printf("  %s doctor                       # verify the wiring\n", prog)
	if len(s.listSecretScopes()) == 0 {
		fmt.Printf("  %s secret edit <scope>          # create your first secret\n", prog)
	} else {
		fmt.Printf("  %s secret list                  # %d scope(s) already in the repo\n", prog, len(s.listSecretScopes()))
	}
	fmt.Printf("  %s secret grant <scope> [<ttl>]  # the tap\n", prog)
	return nil
}

// initAgeBinaries locates the age client and the plugin directory, offering
// whatever autodetection each platform allows.
func initAgeBinaries(s *SecretsConfig) error {
	pluginName := "age-plugin-yubikey"
	ageName := "age"
	if s.Mode == secretModeWSL {
		pluginName += ".exe"
		ageName += ".exe"
	}
	var agePath string // where age actually is, for prefilling the plugin prompt

	// age itself.
	switch s.Mode {
	case secretModeWSL:
		cands := windowsBinCandidates(ageName)
		if len(cands) == 0 {
			fmt.Printf("%s: no %s found on the Windows side.\n", prog, ageName)
			fmt.Printf("       Install it from a Windows shell and re-run this:  %s\n", ageInstallHint)
			fmt.Printf("       (the shim lands in %%LOCALAPPDATA%%\\Microsoft\\WinGet\\Links, which is on PATH)\n")
		}
		p, err := promptPathFromCandidates("Windows age.exe (run from WSL through interop)",
			cands, wingetAgePath(ageName))
		if err != nil {
			return err
		}
		s.Age = p
		agePath = p
	default:
		if p, err := exec.LookPath(ageName); err == nil {
			fmt.Printf("%s: found age on PATH: %s\n", prog, p)
			s.Age = "age" // store the bare name; PATH resolves it at run time
			agePath = p
		} else {
			p, err := promptString("Path to the age binary (not on PATH)", "age")
			if err != nil {
				return err
			}
			s.Age = strings.TrimSpace(p)
			agePath = expandPath(s.Age)
		}
	}

	if s.Mode == secretModeSoft {
		return nil // no plugin involved
	}

	// The plugin directory. age refuses a plugin resolved through "." — the
	// directory has to be a real PATH entry, which is why this is a *directory*
	// setting and not a path to the binary.
	var cands []string
	if s.Mode == secretModeWSL {
		cands = windowsBinCandidates(pluginName)
	} else if p, err := exec.LookPath(pluginName); err == nil {
		cands = []string{p}
	}
	if len(cands) == 0 {
		// Unlike age, the plugin isn't packaged — it's a manual install.
		fmt.Printf("%s: no %s found — it isn't in winget/a package manager;\n", prog, pluginName)
		fmt.Printf("       download the build for this platform and unpack it somewhere stable.\n")
	}
	// Most likely it sits next to age, since both get unpacked to the same place.
	prefill := ""
	if d := filepath.Dir(agePath); d != "" && d != "." {
		prefill = filepath.Join(d, pluginName)
	}
	p, err := promptPathFromCandidates("age-plugin-yubikey (its DIRECTORY becomes a PATH entry)",
		cands, prefill)
	if err != nil {
		return err
	}
	s.PluginDir = filepath.Dir(expandPath(p))
	fmt.Printf("%s: plugin_dir = %s\n", prog, s.PluginDir)
	return nil
}

// initIdentity resolves the age identity file and the recipient blobs get
// encrypted to. For hardware modes it reads the connected YubiKey — never
// writes to it — and lets the operator pick the slot.
func initIdentity(s *SecretsConfig) (string, error) {
	if s.Mode == secretModeSoft {
		return initSoftwareIdentity(s)
	}

	var ids []cardIdentity
	runner, err := newPluginRunner(s.Mode, s.PluginDir)
	if err != nil {
		fmt.Printf("%s: %s\n", prog, err)
	} else if out, lerr := runner.run("--list"); lerr != nil {
		fmt.Printf("%s: could not read the card: %s\n", prog, firstLine(lerr.Error()))
		fmt.Printf("       → is the YubiKey inserted? does it have an age identity in a retired slot?\n")
		fmt.Printf("         (creating one is a separate, deliberate step — see docs/secrets.md)\n")
	} else {
		ids = parseYubikeyList(out)
		fmt.Printf("%s: %d age identity(ies) on the card\n", prog, len(ids))
	}

	if len(ids) == 0 {
		// Fall back to whatever the operator already has, like `mintk init`
		// falls back to paste/file when the token can't be read.
		return initIdentityManually(s)
	}

	var opts []string
	for _, id := range ids {
		label := fmt.Sprintf("slot %-3s %s", id.Slot, abbrev(id.Recipient))
		if id.Name != "" {
			label += "  (" + id.Name + ")"
		}
		if id.PinPolicy != "" || id.TouchPolicy != "" {
			label += fmt.Sprintf("  pin=%s touch=%s", orDash(id.PinPolicy), orDash(id.TouchPolicy))
		}
		if id.Serial != "" {
			label += fmt.Sprintf("  [serial %s]", id.Serial)
		}
		opts = append(opts, label)
	}
	manualIdx := len(opts)
	opts = append(opts, "None of these — enter an identity file by hand")
	idx, err := promptChoice("Which slot holds the age identity", opts)
	if err != nil {
		return "", err
	}
	if idx == manualIdx {
		return initIdentityManually(s)
	}
	chosen := ids[idx]
	warnIdentityPolicies(chosen)

	// Pull the identity stub for that slot. It names the card and slot; it is
	// not key material, so writing it to disk gives nothing away.
	args := []string{"--identity"}
	if chosen.Slot != "" {
		args = append(args, "--slot", chosen.Slot)
	}
	if chosen.Serial != "" {
		args = append(args, "--serial", chosen.Serial)
	}
	stub, err := runner.run(args...)
	if err != nil {
		return "", fmt.Errorf("read the identity for slot %s: %w", chosen.Slot, err)
	}
	if !hasIdentityStub(stub) {
		return "", fmt.Errorf("slot %s returned no AGE-PLUGIN-YUBIKEY identity", chosen.Slot)
	}

	dest, err := promptString("Write the identity file to", defaultIdentityPath(s))
	if err != nil {
		return "", err
	}
	dest = expandPath(strings.TrimSpace(dest))
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return "", err
	}
	// stub already had its \r stripped by pluginRunner: an identity file with
	// carriage returns left in fails with "unknown identity type".
	if err := os.WriteFile(dest, []byte(strings.TrimRight(stub, "\n")+"\n"), 0o600); err != nil {
		return "", err
	}
	s.Identity = dest
	fmt.Printf("%s: wrote the identity stub → %s\n", prog, dest)
	return chosen.Recipient, nil
}

// initIdentityManually is the escape hatch when the card can't be read.
func initIdentityManually(s *SecretsConfig) (string, error) {
	p, err := promptString("Path to an existing age identity file", defaultIdentityPath(s))
	if err != nil {
		return "", err
	}
	s.Identity = expandPath(strings.TrimSpace(p))
	if !fileExists(s.Identity) {
		fmt.Printf("%s: note — %s doesn't exist yet; create it before granting\n", prog, s.Identity)
	}
	r, err := promptString("Recipient blobs are encrypted to (age1... / age1yubikey1...)", "")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(r), nil
}

// initSoftwareIdentity wires up the testing mode: a plain X25519 key file, whose
// recipient can be derived locally.
func initSoftwareIdentity(s *SecretsConfig) (string, error) {
	fmt.Printf("%s: software mode — no hardware, no tap. Testing only.\n", prog)
	p, err := promptString("age identity file (create with `age-keygen -o <path>`)", defaultIdentityPath(s))
	if err != nil {
		return "", err
	}
	s.Identity = expandPath(strings.TrimSpace(p))
	if !fileExists(s.Identity) {
		return "", fmt.Errorf("%s does not exist — create it with `age-keygen -o %s` first", s.Identity, s.Identity)
	}
	if out, err := runOut("age-keygen", "-y", s.Identity); err == nil && out != "" {
		fmt.Printf("%s: derived recipient %s\n", prog, abbrev(out))
		return out, nil
	}
	r, err := promptString("Recipient for this identity", "")
	return strings.TrimSpace(r), err
}

// defaultIdentityPath keeps the identity where the client that reads it can
// reach it: on the Windows side under wsl-windows, so no path has to be
// translated and no UNC share is involved.
func defaultIdentityPath(s *SecretsConfig) string {
	if s.Mode == secretModeWSL {
		if wp := winUserProfile(); wp != "" {
			return filepath.Join(wp, ".mint-key", "age-identity.txt")
		}
	}
	return filepath.Join(configDir(), "age-identity.txt")
}

// initSecretsRepo points at the git repo holding the blobs — using one that's
// already there, cloning it, or creating it.
func initSecretsRepo() (string, error) {
	p, err := promptString("Secrets repo (git repo holding the age blobs)", "~/work/mint-secrets")
	if err != nil {
		return "", err
	}
	p = strings.TrimSpace(p)
	dir := expandPath(p)

	if isGitRepo(dir) {
		fmt.Printf("%s: using the existing git repo at %s\n", prog, dir)
		return p, nil
	}

	opts := []string{
		"Clone an existing repo here (git clone <url>)",
		"Create a new git repo here (git init)",
		"Use the directory as-is — no git (no pull/push, no auto-commit)",
	}
	idx, err := promptChoice(fmt.Sprintf("%s is not a git repo", dir), opts)
	if err != nil {
		return "", err
	}
	switch idx {
	case 0:
		url, err := promptString("git clone URL", "")
		if err != nil {
			return "", err
		}
		url = strings.TrimSpace(url)
		if url == "" {
			return "", fmt.Errorf("no URL given")
		}
		if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
			return "", err
		}
		if err := run("git", "clone", url, dir); err != nil {
			return "", fmt.Errorf("clone failed: %w", err)
		}
	case 1:
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", err
		}
		if err := run("git", "init", dir); err != nil {
			return "", fmt.Errorf("git init failed: %w", err)
		}
		fmt.Printf("%s: created %s — add a remote when you have one (`git -C %s remote add origin <url>`)\n", prog, dir, dir)
	default:
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", err
		}
		fmt.Printf("%s: no git in %s — `secret pull/push` and auto-commit will be unavailable\n", prog, dir)
	}
	return p, nil
}

// initRecipientsFile makes sure the chosen recipient is on the list, and invites
// a break-glass recipient — losing the only card that can decrypt loses every
// blob, and no amount of tooling fixes that after the fact.
func initRecipientsFile(s *SecretsConfig, recipient string) error {
	s.RecipientsFile = "recipients.txt"
	p := filepath.Join(s.repoPath(), s.RecipientsFile)

	var lines []string
	if data, err := os.ReadFile(p); err == nil {
		lines = strings.Split(strings.TrimRight(string(data), "\n"), "\n")
		fmt.Printf("%s: %s already lists %d recipient(s)\n", prog, p, len(parseRecipients(string(data))))
	} else {
		lines = []string{
			"# mint-key secret recipients — every blob is encrypted to all of these.",
			"# Keep a break-glass recipient whose identity is in your offline backup.",
		}
	}
	have := map[string]bool{}
	for _, r := range parseRecipients(strings.Join(lines, "\n")) {
		have[r] = true
	}
	added := 0
	if recipient != "" && !have[recipient] {
		lines = append(lines, recipient)
		have[recipient] = true
		added++
	}

	for {
		extra, err := promptString("Break-glass recipient to add (blank to finish)", "")
		if err != nil {
			return err
		}
		extra = strings.TrimSpace(extra)
		if extra == "" {
			break
		}
		if !strings.HasPrefix(extra, "age1") {
			fmt.Printf("%s: %q doesn't look like an age recipient (age1...)\n", prog, extra)
			continue
		}
		if have[extra] {
			fmt.Printf("%s: already listed\n", prog)
			continue
		}
		lines = append(lines, extra)
		have[extra] = true
		added++
	}

	if len(have) == 0 {
		return fmt.Errorf("no recipients — `secret edit` would have nothing to encrypt to")
	}
	if added == 0 {
		return nil
	}
	if err := os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Printf("%s: wrote %s (%d recipient(s))\n", prog, p, len(have))
	if isGitRepo(s.repoPath()) {
		if err := run("git", "-C", s.repoPath(), "add", "--", p); err == nil {
			if exec.Command("git", "-C", s.repoPath(), "diff", "--cached", "--quiet", "--", p).Run() != nil {
				_ = run("git", "-C", s.repoPath(), "commit", "-m", "mintk: update secret recipients", "--", p)
			}
		}
	}
	return nil
}

// --- reading the card (read-only) --------------------------------------------

// pluginRunner invokes age-plugin-yubikey directly for the read-only queries
// `secret init` makes. It never passes --generate: like `mintk init`, this reads
// the card and never writes to it.
type pluginRunner struct {
	bin  string
	mode string
	dir  string
}

func newPluginRunner(mode, pluginDir string) (*pluginRunner, error) {
	name := "age-plugin-yubikey"
	if mode == secretModeWSL {
		name += ".exe"
	}
	dir := expandPath(pluginDir)
	bin := ""
	if dir != "" && fileExists(filepath.Join(dir, name)) {
		bin = filepath.Join(dir, name)
	} else if mode != secretModeWSL {
		if p, err := exec.LookPath(name); err == nil {
			bin = p
		}
	}
	if bin == "" {
		return nil, fmt.Errorf("%s not found in %s", name, dir)
	}
	return &pluginRunner{bin: bin, mode: mode, dir: dir}, nil
}

func (p *pluginRunner) run(args ...string) (string, error) {
	cmd := exec.Command(p.bin, args...)
	cmd.Env = pluginEnv(p.mode, p.dir)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s", ageError(errb.String(), err))
	}
	// Windows binaries emit CRLF; anything captured as text gets it stripped.
	return stripCR(out.String()), nil
}

// cardIdentity is one age identity found on a connected YubiKey.
type cardIdentity struct {
	Recipient   string
	Slot        string
	Serial      string
	Name        string
	PinPolicy   string
	TouchPolicy string
}

// parseYubikeyList reads `age-plugin-yubikey --list` output. Each identity is a
// *block*: metadata in "# Key: Value" comment lines, then the recipient on a
// line of its own. Fields can share a comment line ("# Serial: N, Slot: N"), and
// values can carry a trailing parenthesised gloss, which is dropped.
//
//	#       Serial: 12345678, Slot: 1
//	#         Name: example
//	#   PIN policy: Once   (A PIN is required once per session, if set)
//	# Touch policy: Cached (A physical touch is required for decryption, ...)
//	age1yubikey1…
func parseYubikeyList(out string) []cardIdentity {
	var ids []cardIdentity
	pending := cardIdentity{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "":
			continue
		case strings.HasPrefix(line, "#"):
			absorbIdentityFields(&pending, strings.TrimPrefix(line, "#"))
		case strings.HasPrefix(line, "age1"):
			pending.Recipient = strings.Fields(line)[0]
			// A recipient line may also carry the metadata as a comment.
			if _, comment, ok := strings.Cut(line, "#"); ok {
				absorbIdentityFields(&pending, comment)
			}
			ids = append(ids, pending)
			pending = cardIdentity{}
		}
	}
	return ids
}

// absorbIdentityFields pulls "Key: Value" pairs out of one metadata line.
// Only "Serial" and "Slot" are ever paired on a line, so splitting on "," is
// safe for them while a Name containing a comma stays intact.
func absorbIdentityFields(id *cardIdentity, line string) {
	fields := []string{line}
	if strings.Contains(line, "Serial:") && strings.Contains(line, "Slot:") {
		fields = strings.Split(line, ",")
	}
	for _, field := range fields {
		k, v, ok := strings.Cut(field, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		// Drop the explanatory "(A PIN is required...)" tail on policy lines.
		if i := strings.Index(v, "("); i > 0 {
			v = strings.TrimSpace(v[:i])
		}
		switch strings.TrimSpace(k) {
		case "Slot":
			id.Slot = v
		case "Serial":
			id.Serial = v
		case "Name":
			id.Name = v
		case "PIN policy":
			id.PinPolicy = v
		case "Touch policy":
			id.TouchPolicy = v
		}
	}
}

// hasIdentityStub reports whether `--identity` output actually carries one.
func hasIdentityStub(s string) bool {
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "AGE-PLUGIN-YUBIKEY-1") {
			return true
		}
	}
	return false
}

// --- small helpers -----------------------------------------------------------

// promptPathFromCandidates offers what was autodetected, with a manual entry
// that is pre-filled — with the likeliest candidate, or with def (where the
// thing *would* be once installed) when autodetection came up empty.
func promptPathFromCandidates(label string, cands []string, def string) (string, error) {
	prefill := def
	if len(cands) > 0 {
		prefill = cands[0]
	}
	if len(cands) == 0 {
		p, err := promptString(label, prefill)
		if err != nil {
			return "", err
		}
		p = expandPath(strings.TrimSpace(p))
		if p == "" {
			return "", fmt.Errorf("no path given for %s", label)
		}
		return p, nil
	}
	opts := append([]string{}, cands...)
	manual := len(opts)
	opts = append(opts, "Enter a path by hand")
	idx, err := promptChoice(label, opts)
	if err != nil {
		return "", err
	}
	if idx < manual {
		return cands[idx], nil
	}
	p, err := promptString(label, prefill)
	return expandPath(strings.TrimSpace(p)), err
}

// winUserProfile resolves the Windows %USERPROFILE% as a WSL path, so defaults
// can point at the Windows side without hardcoding a username. Read-only.
func winUserProfile() string {
	if !inWSL() {
		return ""
	}
	cmd := exec.Command("cmd.exe", "/c", "echo %USERPROFILE%")
	cmd.Dir = "/mnt/c" // avoid cmd.exe's "UNC paths are not supported" warning
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	win := stripCR(strings.TrimSpace(string(out)))
	if win == "" || strings.Contains(win, "%") {
		return ""
	}
	p, err := exec.Command("wslpath", "-u", win).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(stripCR(string(p)))
}

// wingetLinksDir is where winget puts its shims; it is on the user's Windows
// PATH, so anything installed that way is found by winWhere too.
const wingetLinksDir = "AppData/Local/Microsoft/WinGet/Links"

// ageInstallHint is the one-liner that gets age onto the Windows side.
const ageInstallHint = "winget install FiloSottile.age"

// windowsBinCandidates looks for a Windows executable: first by asking Windows
// itself (`where.exe`, i.e. anything on the Windows PATH — winget/scoop/choco
// shims included), then in the usual install locations and one level below them,
// where release zips unpack to.
func windowsBinCandidates(name string) []string {
	var found []string
	seen := map[string]bool{}
	add := func(p string) {
		if p != "" && !seen[p] && fileExists(p) {
			seen[p] = true
			found = append(found, p)
		}
	}
	for _, p := range winWhere(name) {
		add(p)
	}

	var dirs []string
	if wp := winUserProfile(); wp != "" {
		for _, d := range []string{
			wingetLinksDir, "scoop/shims", ".cargo/bin",
			"age", "age-tools", "bin", ".local/bin", "AppData/Local/Programs", "Downloads",
		} {
			dirs = append(dirs, filepath.Join(wp, filepath.FromSlash(d)))
		}
	}
	dirs = append(dirs,
		"/mnt/c/Program Files/age",
		"/mnt/c/ProgramData/chocolatey/bin",
		"/mnt/c/tools",
	)
	for _, d := range dirs {
		matches, _ := filepath.Glob(filepath.Join(d, name))
		deeper, _ := filepath.Glob(filepath.Join(d, "*", name))
		for _, m := range append(matches, deeper...) {
			add(m)
		}
	}
	return found
}

// winWhere asks Windows where a command is, translating the results back to WSL
// paths. This is the detection that keeps working when the operator installs to
// somewhere we'd never guess — if it's on the Windows PATH, this finds it.
func winWhere(name string) []string {
	if !inWSL() {
		return nil
	}
	cmd := exec.Command("where.exe", name)
	cmd.Dir = "/mnt/c" // avoid cmd/where complaining about a UNC working directory
	out, err := cmd.Output()
	if err != nil {
		return nil // exit 1 simply means "not found"
	}
	var paths []string
	for _, line := range strings.Split(stripCR(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		p, err := exec.Command("wslpath", "-u", line).Output()
		if err != nil {
			continue
		}
		paths = append(paths, strings.TrimSpace(stripCR(string(p))))
	}
	return paths
}

// wingetAgePath is where `winget install FiloSottile.age` lands age.exe — used
// to pre-fill the prompt when nothing is installed yet.
func wingetAgePath(name string) string {
	wp := winUserProfile()
	if wp == "" {
		return ""
	}
	return filepath.Join(wp, filepath.FromSlash(wingetLinksDir), name)
}

// warnIdentityPolicies flags slot policies that make grants cost more than the
// design assumes: `touch always` taps per decrypt (so a burst is N taps), and a
// PIN policy of `always` prompts every time.
func warnIdentityPolicies(id cardIdentity) {
	if p := strings.ToLower(id.TouchPolicy); p != "" && p != "cached" {
		fmt.Printf("%s: note — touch policy is %q; only `cached` lets one tap cover a multi-scope grant\n",
			prog, id.TouchPolicy)
	}
	if p := strings.ToLower(id.PinPolicy); p == "always" {
		fmt.Printf("%s: note — PIN policy is `always`; every decrypt will prompt for the PIN\n", prog)
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// abbrev shortens a long key/recipient string for a menu line.
func abbrev(s string) string {
	if len(s) <= 28 {
		return s
	}
	return s[:16] + "…" + s[len(s)-8:]
}
