package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

func scopesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scopes",
		Short: "Manage scopes (name → principal → default ttl) in the config",
	}
	cmd.AddCommand(scopesListCmd())
	cmd.AddCommand(scopesAddCmd())
	cmd.AddCommand(scopesDeleteCmd())
	cmd.AddCommand(scopesEditCmd())
	cmd.AddCommand(scopesPullCmd())
	cmd.AddCommand(scopesPushCmd())
	return cmd
}

// scopesGitDir returns the git repo directory backing the external scopes file,
// or an error if scopes aren't kept in an external file.
func scopesGitDir(cfg *Config) (string, error) {
	if cfg.ScopesFile == "" {
		return "", fmt.Errorf("scopes are inline; set scopes_file (a git repo) to use pull/push")
	}
	dir := filepath.Dir(cfg.scopesFilePath())
	if !isGitRepo(dir) {
		return "", fmt.Errorf("%s is not a git repository — clone/init your scopes repo there first", dir)
	}
	return dir, nil
}

func scopesPullCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "pull",
		Short: "git pull the scopes repo (sync the shared scope list down)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			dir, err := scopesGitDir(cfg)
			if err != nil {
				return err
			}
			fmt.Printf("%s: git pull in %s\n", prog, dir)
			return run("git", "-C", dir, "pull", "--ff-only")
		},
	}
}

func scopesPushCmd() *cobra.Command {
	var msg string
	cmd := &cobra.Command{
		Use:   "push",
		Short: "Commit + git push the scopes file (share local changes)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			dir, err := scopesGitDir(cfg)
			if err != nil {
				return err
			}
			file := cfg.scopesFilePath()
			if err := run("git", "-C", dir, "add", file); err != nil {
				return err
			}
			// Commit only if something is actually staged.
			if exec.Command("git", "-C", dir, "diff", "--cached", "--quiet").Run() == nil {
				fmt.Printf("%s: nothing to push (scopes file unchanged)\n", prog)
				return nil
			}
			if err := run("git", "-C", dir, "commit", "-m", msg); err != nil {
				return err
			}
			fmt.Printf("%s: git push in %s\n", prog, dir)
			return run("git", "-C", dir, "push")
		},
	}
	cmd.Flags().StringVarP(&msg, "message", "m", "mintk: update scopes", "commit message")
	return cmd
}

func scopesListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List configured scopes",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			printScopes(cfg)
			return nil
		},
	}
}

func printScopes(cfg *Config) {
	if len(cfg.Scopes) == 0 {
		fmt.Printf("no scopes configured in %s\n", cfg.path)
		return
	}
	fmt.Printf("configured scopes (from %s):\n", cfg.path)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "  NAME\tPRINCIPAL\tTTL")
	printScopeTree(cfg, w, "", "  ")
	w.Flush()
}

// printScopeTree prints one group level: its subgroups (recursively), then the
// scopes sitting directly in it. Without groups this is the old flat listing.
func printScopeTree(cfg *Config, w io.Writer, group, indent string) {
	for _, g := range cfg.childGroups(group) {
		fmt.Fprintf(w, "%s%s\t\t\n", indent, g+groupSep)
		printScopeTree(cfg, w, joinGroup(group, g), indent+"  ")
	}
	for _, i := range cfg.scopeIndexes(group) {
		s := cfg.Scopes[i]
		fmt.Fprintf(w, "%s%s\t%s\t%s\n", indent, s.Name, s.Principal, s.TTL)
	}
}

func scopesAddCmd() *cobra.Command {
	var group string
	cmd := &cobra.Command{
		Use:   "add <name> <principal> [<ttl>]",
		Short: "Add a scope (default ttl 8h)",
		Args:  cobra.RangeArgs(2, 3),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			ttl := "8h"
			if len(args) == 3 {
				ttl = args[2]
			}
			if _, err := normalizeTTL(ttl); err != nil {
				return err
			}
			g, err := normalizeGroup(group)
			if err != nil {
				return err
			}
			name := args[0]
			if _, exists := cfg.scope(name); exists {
				return fmt.Errorf("scope %q already exists (use `scopes edit` to change it)", name)
			}
			cfg.Scopes = append(cfg.Scopes, Scope{Name: name, Principal: args[1], TTL: ttl, Group: g})
			sortScopes(cfg)
			if err := cfg.saveScopes(); err != nil {
				return err
			}
			fmt.Printf("%s: added scope %s → principal=%s ttl=%s group=%s\n",
				prog, name, args[1], ttl, groupDisplay(g))
			return nil
		},
	}
	cmd.Flags().StringVarP(&group, "group", "g", "", "group path to file the scope under (e.g. infra/prod)")
	return cmd
}

func scopesDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a scope",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			if !removeScope(cfg, args[0]) {
				return fmt.Errorf("unknown scope %q", args[0])
			}
			if err := cfg.saveScopes(); err != nil {
				return err
			}
			fmt.Printf("%s: deleted scope %s\n", prog, args[0])
			return nil
		},
	}
}

func scopesEditCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "edit",
		Short: "Interactively add/edit/delete scopes",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			if !isInteractive() {
				return fmt.Errorf("`scopes edit` needs a terminal; use `scopes add`/`delete` non-interactively")
			}
			return runScopesEdit(cfg)
		},
	}
}

// runScopesEdit is the interactive editor loop (mirrors wg-hop's runEditConfig):
// pick a scope to edit, or add/delete, accumulate changes, write on exit.
func runScopesEdit(cfg *Config) error {
	changed := false
	for {
		var options []string
		for _, s := range cfg.Scopes {
			options = append(options, formatScopeLineFlat(s))
		}
		addIdx := len(options)
		options = append(options, "[+] Add new scope")
		doneIdx := len(options)
		options = append(options, "[x] Done")

		idx, err := promptChoice("Scopes", options)
		if err != nil {
			break // Esc/Ctrl-C: stop the loop, keep what's saved so far
		}
		switch {
		case idx == doneIdx:
			if changed {
				if err := cfg.saveScopes(); err != nil {
					return err
				}
				fmt.Printf("%s: saved %s\n", prog, cfg.scopesDest())
			}
			return nil
		case idx == addIdx:
			if addScopeInteractive(cfg) {
				changed = true
			}
		default:
			if editScopeInteractive(cfg, &cfg.Scopes[idx]) {
				changed = true
			}
		}
	}
	if changed {
		if err := cfg.saveScopes(); err != nil {
			return err
		}
		fmt.Printf("%s: saved %s\n", prog, cfg.scopesDest())
	}
	return nil
}

func addScopeInteractive(cfg *Config) bool {
	name, err := promptString("New scope name", "")
	if err != nil || strings.TrimSpace(name) == "" {
		return false
	}
	name = strings.TrimSpace(name)
	if _, exists := cfg.scope(name); exists {
		fmt.Printf("scope %q already exists\n", name)
		return false
	}
	principal, err := promptString("Principal (what hosts must list)", name)
	if err != nil {
		return false
	}
	ttl, err := promptString("Default ttl", "8h")
	if err != nil {
		return false
	}
	if _, err := normalizeTTL(ttl); err != nil {
		fmt.Printf("%s\n", err)
		return false
	}
	// Only worth a prompt once there is a tree to file it into.
	group := ""
	if len(cfg.allGroups()) > 0 {
		if g, ok := promptGroup(cfg, "Group for "+name, ""); ok {
			group = g
		}
	}
	cfg.Scopes = append(cfg.Scopes, Scope{
		Name:      name,
		Principal: strings.TrimSpace(principal),
		TTL:       strings.TrimSpace(ttl),
		Group:     group,
	})
	sortScopes(cfg)
	return true
}

// editScopeInteractive opens an action submenu for a single scope.
func editScopeInteractive(cfg *Config, s *Scope) bool {
	for {
		actions := []string{
			fmt.Sprintf("Principal: %s", s.Principal),
			fmt.Sprintf("TTL: %s", s.TTL),
			fmt.Sprintf("Group: %s", groupDisplay(s.Group)),
			"Delete scope",
			"Back",
		}
		idx, err := promptChoice(formatScopeLine(*s), actions)
		if err != nil {
			return false
		}
		switch idx {
		case 0:
			v, err := promptString("Principal", s.Principal)
			if err == nil && strings.TrimSpace(v) != "" {
				s.Principal = strings.TrimSpace(v)
				return true
			}
		case 1:
			v, err := promptString("TTL", s.TTL)
			if err == nil {
				if _, e := normalizeTTL(v); e != nil {
					fmt.Printf("%s\n", e)
					continue
				}
				s.TTL = strings.TrimSpace(v)
				return true
			}
		case 2:
			g, ok := promptGroup(cfg, fmt.Sprintf("Group for %s", s.Name), s.Group)
			if ok && g != s.Group {
				s.Group = g
				return true
			}
		case 3:
			ok, _ := promptYesNo(fmt.Sprintf("Delete scope %q?", s.Name), false)
			if ok {
				removeScope(cfg, s.Name)
				return true
			}
		default:
			return false
		}
	}
}

func formatScopeLine(s Scope) string {
	return fmt.Sprintf("%-18s principal=%-18s ttl=%s", s.Name, s.Principal, s.TTL)
}

// formatScopeLineFlat is formatScopeLine for a listing with no tree around it,
// where the scope's group has to be spelled out rather than implied.
func formatScopeLineFlat(s Scope) string {
	if s.Group == "" {
		return formatScopeLine(s)
	}
	return formatScopeLine(s) + "  group=" + groupDisplay(s.Group)
}

func removeScope(cfg *Config, name string) bool {
	for i := range cfg.Scopes {
		if cfg.Scopes[i].Name == name {
			cfg.Scopes = append(cfg.Scopes[:i], cfg.Scopes[i+1:]...)
			return true
		}
	}
	return false
}

func sortScopes(cfg *Config) {
	sort.Slice(cfg.Scopes, func(i, j int) bool { return cfg.Scopes[i].Name < cfg.Scopes[j].Name })
}
