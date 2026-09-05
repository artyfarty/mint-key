package main

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func interactiveCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "interactive",
		Aliases: []string{"i"},
		Short:   "Menu-driven mintk: mint a cert, grant a secret, manage scopes, clean up",
		Long: `One menu for the things you do day to day, so nothing has to be remembered:
mint a cert for a scope, grant a secret (or create a new one), manage the scope
list, and clear out what's been minted. Every entry shows what is currently live
and how long it has left, so the menu doubles as the answer to "what do I have
right now?".

Everything here is the same code the individual commands run.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInteractive()
		},
	}
}

func runInteractive() error {
	if !isInteractive() {
		return fmt.Errorf("`interactive` needs a terminal")
	}
	// Name the tab while the menu owns it — with several terminals open it's
	// otherwise guesswork which one is waiting on a YubiKey tap.
	defer pushTermTitle(prog + " i")()
	for {
		// Reloaded every pass: a scope added or a secret created in the previous
		// action has to show up without restarting.
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		// Missing/unconfigured secrets are not an error here — plenty of setups
		// only mint certs. The entry is simply not offered.
		sess, secErr := openSecrets()

		type action struct {
			label string
			run   func() error
		}
		var actions []action

		actions = append(actions, action{
			label: fmt.Sprintf("Mint a cert          %s", certSummaryLine(cfg)),
			run:   func() error { return interactiveMint(cfg) },
		})
		if secErr == nil {
			actions = append(actions, action{
				label: fmt.Sprintf("Grant a secret       %s", grantSummaryLine(sess)),
				run:   func() error { return interactiveGrant(sess) },
			})
		}
		actions = append(actions, action{
			label: fmt.Sprintf("Manage scopes        %s", scopesSummaryLine(cfg)),
			run:   func() error { return interactiveScopes(cfg) },
		})
		actions = append(actions, action{
			label: "Clean up             wipe minted identities / revoke grants",
			run:   func() error { return interactiveCleanup(cfg, sess, secErr) },
		})

		opts := make([]string, 0, len(actions)+1)
		for _, a := range actions {
			opts = append(opts, a.label)
		}
		quit := len(opts)
		opts = append(opts, "[x] Quit")

		idx, err := promptChoice(prog, opts)
		if err != nil || idx == quit {
			return nil // Esc / Ctrl-C / Quit
		}
		if err := actions[idx].run(); err != nil {
			// A failed action shouldn't drop you out of the menu.
			fmt.Printf("%s: %s\n", prog, err)
		}
	}
}

// --- mint a cert -------------------------------------------------------------

func certSummaryLine(cfg *Config) string {
	if len(cfg.Scopes) == 0 {
		return "(no scopes configured)"
	}
	live := 0
	for _, s := range cfg.Scopes {
		if _, ok := certRemaining(cfg, s.Name); ok {
			live++
		}
	}
	return fmt.Sprintf("%d scope(s), %d live", len(cfg.Scopes), live)
}

func interactiveMint(cfg *Config) error {
	if len(cfg.Scopes) == 0 {
		return fmt.Errorf("no scopes configured — add one from the \"Manage scopes\" entry")
	}
	idx, ok := pickScopeInTree(cfg, "Mint a cert — pick a scope", func(s Scope) string {
		state := "—"
		if d, ok := certRemaining(cfg, s.Name); ok {
			state = "live " + shortDuration(d)
		}
		return fmt.Sprintf("%-18s principal=%-18s ttl=%-6s %s", s.Name, s.Principal, s.TTL, state)
	})
	if !ok {
		return nil
	}
	sc := cfg.Scopes[idx]
	ttl, err := promptTTL(fmt.Sprintf("Lifetime for %s", sc.Name), sc.TTL)
	if err != nil || ttl == "" {
		return nil
	}
	return runKey(sc.Name, ttl)
}

// certRemaining reports how long the cert already minted for a scope is still
// valid. Best-effort: no cert, an unparsable one or an expired one all read as
// "not live".
func certRemaining(cfg *Config, scope string) (time.Duration, bool) {
	path := fmt.Sprintf("%s/%s-cert.pub", cfg.sessionsDir(), scope)
	if !fileExists(path) {
		return 0, false
	}
	out, err := exec.Command("ssh-keygen", "-L", "-f", path).Output()
	if err != nil {
		return 0, false
	}
	until, ok := parseCertValidTo(string(out))
	if !ok {
		return 0, false
	}
	d := time.Until(until)
	if d <= 0 {
		return 0, false
	}
	return d, true
}

// certValidRe matches ssh-keygen -L's validity line:
//
//	Valid: from 2026-08-10T22:00:00 to 2026-08-11T06:00:00
var certValidRe = regexp.MustCompile(`Valid: from \S+ to (\S+)`)

// parseCertValidTo extracts the expiry from `ssh-keygen -L` output. A cert with
// no expiry ("forever") reports none — this is only used to show a countdown.
func parseCertValidTo(out string) (time.Time, bool) {
	m := certValidRe.FindStringSubmatch(out)
	if m == nil {
		return time.Time{}, false
	}
	t, err := time.ParseInLocation("2006-01-02T15:04:05", m[1], time.Local)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// --- grant a secret ----------------------------------------------------------

func grantSummaryLine(sess *secretSession) string {
	scopes := sess.sec.listSecretScopes()
	if len(scopes) == 0 {
		return "(no secrets yet)"
	}
	live := 0
	for _, n := range scopes {
		if _, ok := sess.st.live(n); ok {
			live++
		}
	}
	return fmt.Sprintf("%d secret(s), %d granted", len(scopes), live)
}

func interactiveGrant(sess *secretSession) error {
	scopes := sess.sec.listSecretScopes()
	var opts []string
	for _, n := range scopes {
		state := "—"
		if g, ok := sess.st.live(n); ok {
			state = "granted " + shortDuration(g.remaining())
		}
		opts = append(opts, fmt.Sprintf("%-18s ttl=%-6s %-7s %s",
			n, sess.sec.scopeTTL(n), sess.sec.scopeFormat(n), state))
	}
	add := len(opts)
	opts = append(opts, "[+] Add a new secret")
	back := len(opts)
	opts = append(opts, "[<] Back")

	idx, err := promptChoice("Grant a secret — pick a scope", opts)
	if err != nil || idx == back {
		return nil
	}
	if idx == add {
		name, err := promptString("Name for the new secret", "")
		if err != nil {
			return nil
		}
		name = strings.TrimSpace(name)
		if name == "" {
			return nil
		}
		if err := validScopeName(name); err != nil {
			return err
		}
		// `edit` creates it: $EDITOR on tmpfs, then encrypt + commit.
		return runSecretEdit(name, false, false)
	}

	name := scopes[idx]
	ttl, err := promptTTL(fmt.Sprintf("Lifetime for %s", name), sess.sec.scopeTTL(name))
	if err != nil || ttl == "" {
		return nil
	}
	return runSecretGrant([]string{name}, ttl)
}

// --- manage scopes -----------------------------------------------------------

func scopesSummaryLine(cfg *Config) string {
	if n := len(cfg.allGroups()); n > 0 {
		return fmt.Sprintf("%d in %d group(s) — add, regroup, or change default mint time", len(cfg.Scopes), n)
	}
	return fmt.Sprintf("%d configured — add one, or change its default mint time", len(cfg.Scopes))
}

// interactiveScopes is the scope editor reachable from the main menu. It walks
// the group tree: a group row descends into it, and additions land wherever you
// currently are. Unlike `scopes edit`, every change is written out as it's made
// rather than on exit: the main loop reloads the config on the next pass, so
// unsaved state here would silently be thrown away.
func interactiveScopes(cfg *Config) error {
	cur := ""
	for {
		m := buildScopeManageMenu(cfg, cur)

		idx, err := promptChoice(treeTitle("Scopes", cur), m.rows)
		if err != nil {
			return nil
		}
		switch {
		case idx == m.back:
			if cur == "" {
				return nil
			}
			cur = parentGroup(cur)
			continue
		case idx < len(m.groups):
			cur = joinGroup(cur, m.groups[idx])
			continue
		case idx < len(m.groups)+len(m.scopes):
			err = interactiveScopeEdit(cfg, &cfg.Scopes[m.scopes[idx-len(m.groups)]])
		case idx == m.addScope:
			err = interactiveScopeAdd(cfg, cur)
		case idx == m.addGroup:
			err = interactiveGroupAdd(cfg, cur)
		case idx == m.groupMenu:
			cur, err = interactiveGroupEdit(cfg, cur)
		}
		if err != nil {
			// Same rule as the main menu: a rejected name or a failed write
			// shouldn't throw you out of the scope list.
			fmt.Printf("%s: %s\n", prog, err)
		}
	}
}

// scopeManageMenu is one level of the "Manage scopes" tree: the browsable rows
// plus the action rows that act on wherever you currently are.
type scopeManageMenu struct {
	treeLevel
	addScope  int
	addGroup  int
	groupMenu int // -1 at the root: there is no group to rename or delete
	back      int
}

func buildScopeManageMenu(cfg *Config, cur string) scopeManageMenu {
	m := scopeManageMenu{treeLevel: buildTreeLevel(cfg, cur, formatScopeLine), groupMenu: -1}
	m.addScope = len(m.rows)
	m.rows = append(m.rows, "[+] Add a new scope here")
	m.addGroup = len(m.rows)
	m.rows = append(m.rows, "[+] Add a new group here")
	if cur != "" {
		m.groupMenu = len(m.rows)
		m.rows = append(m.rows, "[#] Rename / delete "+groupDisplay(cur))
	}
	m.back = len(m.rows)
	m.rows = append(m.rows, backRow(cur))
	return m
}

// interactiveGroupAdd creates a group under `parent`. The name may itself be a
// path, so a whole branch can be typed in one go.
func interactiveGroupAdd(cfg *Config, parent string) error {
	name, err := promptString("New group in "+groupDisplay(parent), "")
	if err != nil {
		return nil
	}
	path, err := normalizeGroup(joinGroup(parent, strings.TrimSpace(name)))
	if err != nil {
		return err
	}
	if path == "" || path == parent {
		return nil
	}
	if !cfg.addGroup(path) {
		return fmt.Errorf("group %s already exists", groupDisplay(path))
	}
	if err := cfg.saveScopes(); err != nil {
		return err
	}
	fmt.Printf("%s: added group %s (saved %s)\n", prog, groupDisplay(path), cfg.scopesDest())
	return nil
}

// interactiveGroupEdit renames or deletes the group being browsed. It returns
// where the browser should now stand: the new path after a rename, the parent
// after a delete.
func interactiveGroupEdit(cfg *Config, cur string) (string, error) {
	empty := cfg.groupScopeCount(cur) == 0 && len(cfg.childGroups(cur)) == 0
	del := "Delete this group"
	if !empty {
		del += " (only when empty)"
	}
	idx, err := promptChoice(groupDisplay(cur), []string{"Rename / move this group", del, "[<] Back"})
	if err != nil || idx == 2 {
		return cur, nil
	}
	if idx == 1 {
		if !empty {
			return cur, fmt.Errorf("group %s still holds scopes or subgroups — move them out first", groupDisplay(cur))
		}
		ok, _ := promptYesNo(fmt.Sprintf("Delete group %s?", groupDisplay(cur)), false)
		if !ok {
			return cur, nil
		}
		cfg.removeGroup(cur)
		if err := cfg.saveScopes(); err != nil {
			return parentGroup(cur), err
		}
		fmt.Printf("%s: deleted group %s (saved %s)\n", prog, groupDisplay(cur), cfg.scopesDest())
		return parentGroup(cur), nil
	}

	v, err := promptString("New path for "+groupDisplay(cur), cur)
	if err != nil {
		return cur, nil
	}
	to, err := normalizeGroup(v)
	if err != nil {
		return cur, err
	}
	if to == "" || to == cur {
		return cur, nil
	}
	if strings.HasPrefix(to, cur+groupSep) {
		return cur, fmt.Errorf("cannot move %s into itself", groupDisplay(cur))
	}
	cfg.renameGroup(cur, to)
	if err := cfg.saveScopes(); err != nil {
		return to, err
	}
	fmt.Printf("%s: %s → %s (saved %s)\n", prog, groupDisplay(cur), groupDisplay(to), cfg.scopesDest())
	return to, nil
}

func interactiveScopeAdd(cfg *Config, group string) error {
	name, err := promptString("New scope name", "")
	if err != nil {
		return nil
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	// The name becomes a filename under sessions_dir, so it gets the same
	// constraints as a secret scope.
	if err := validScopeName(name); err != nil {
		return err
	}
	if _, exists := cfg.scope(name); exists {
		return fmt.Errorf("scope %q already exists", name)
	}
	principal, err := promptString("Principal (what target hosts must list)", name)
	if err != nil {
		return nil
	}
	principal = strings.TrimSpace(principal)
	if principal == "" {
		return nil
	}
	ttl, err := promptTTL("Default mint time", "8h")
	if err != nil || ttl == "" {
		return nil
	}
	cfg.Scopes = append(cfg.Scopes, Scope{Name: name, Principal: principal, TTL: ttl, Group: cleanGroupPath(group)})
	sortScopes(cfg)
	if err := cfg.saveScopes(); err != nil {
		return err
	}
	fmt.Printf("%s: added scope %s → principal=%s ttl=%s group=%s (saved %s)\n",
		prog, name, principal, ttl, groupDisplay(group), cfg.scopesDest())
	return nil
}

// interactiveScopeEdit is the per-scope submenu: the default mint time and which
// group the scope lives in — the two things that get retuned day to day.
// Principal edits and deletion stay in `mintk scopes edit`, where they're less
// likely to be hit by accident.
func interactiveScopeEdit(cfg *Config, s *Scope) error {
	for {
		opts := []string{
			fmt.Sprintf("Default mint time: %s", s.TTL),
			fmt.Sprintf("Group: %s", groupDisplay(s.Group)),
			"[<] Back",
		}
		idx, err := promptChoice(formatScopeLine(*s), opts)
		if err != nil || idx == 2 {
			return nil
		}
		if idx == 1 {
			g, ok := promptGroup(cfg, fmt.Sprintf("Group for %s", s.Name), s.Group)
			if !ok || g == s.Group {
				continue
			}
			s.Group = g
			if err := cfg.saveScopes(); err != nil {
				return err
			}
			fmt.Printf("%s: %s → group %s (saved %s)\n", prog, s.Name, groupDisplay(g), cfg.scopesDest())
			// Moving the scope out from under the browser's feet: the caller's
			// listing no longer holds it.
			return nil
		}
		ttl, err := promptTTL(fmt.Sprintf("Default mint time for %s", s.Name), s.TTL)
		if err != nil {
			return nil
		}
		if ttl == "" || ttl == s.TTL {
			continue
		}
		s.TTL = ttl
		if err := cfg.saveScopes(); err != nil {
			return err
		}
		fmt.Printf("%s: %s ttl=%s (saved %s)\n", prog, s.Name, ttl, cfg.scopesDest())
	}
}

// --- clean up ----------------------------------------------------------------

func interactiveCleanup(cfg *Config, sess *secretSession, secErr error) error {
	type item struct {
		label string
		run   func() error
	}
	items := []item{{
		label: "Wipe minted identities (session keys + certs)",
		run:   func() error { return runCleanKeys(cfg, false) },
	}}
	if secErr == nil {
		items = append(items, item{
			label: fmt.Sprintf("Revoke all secret grants (%d live)", len(sess.st.list())),
			run: func() error {
				grants := sess.st.list()
				if len(grants) == 0 {
					fmt.Printf("%s: no live grants\n", prog)
					return nil
				}
				for _, g := range grants {
					sess.st.wipe(g.Scope, "")
					fmt.Printf("%s: revoked %s\n", prog, g.Scope)
				}
				return nil
			},
		})
	}

	var opts []string
	for _, it := range items {
		opts = append(opts, it.label)
	}
	back := len(opts)
	opts = append(opts, "[<] Back")

	idx, err := promptChoice("Clean up", opts)
	if err != nil || idx == back {
		return nil
	}
	return items[idx].run()
}

// --- shared ------------------------------------------------------------------

// promptTTL asks for a lifetime and re-asks until it parses. Returns "" if the
// prompt was cancelled.
func promptTTL(label, def string) (string, error) {
	for {
		v, err := promptString(label+" (e.g. 8h, 30m, 1d)", def)
		if err != nil {
			return "", err
		}
		v = strings.TrimSpace(v)
		if v == "" {
			return "", nil
		}
		if _, err := normalizeTTL(v); err != nil {
			fmt.Printf("%s: %s\n", prog, err)
			continue
		}
		return v, nil
	}
}
