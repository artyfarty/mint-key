package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/spf13/cobra"
)

func cleanKeysCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "clean-keys",
		Short: "Remove all minted identities (session keys + certs) from sessions_dir",
		Long: `Deletes every throwaway per-scope key and minted certificate under
sessions_dir (the ` + "`mintk key`" + ` output). The private keys there never
leave this host and minting re-creates them on demand, so wiping them only forces
the next ` + "`mintk key`" + ` to tap/sign again — useful for cleanup or before
handing the machine off.

Asks for confirmation before deleting; pass -y/--yes to skip the prompt (e.g. in
scripts). Only the files inside sessions_dir are removed; the directory itself is
kept.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			return runCleanKeys(cfg, yes)
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false,
		"Delete without the interactive confirmation prompt")
	return cmd
}

func runCleanKeys(cfg *Config, yes bool) error {
	dir := cfg.sessionsDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("%s: sessions_dir %s does not exist — nothing to clean.\n", prog, dir)
			return nil
		}
		return err
	}

	// Collect the regular files to delete (leave any subdirectories alone).
	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		files = append(files, e.Name())
	}
	if len(files) == 0 {
		fmt.Printf("%s: no minted identities in %s — nothing to clean.\n", prog, dir)
		return nil
	}
	sort.Strings(files)

	fmt.Printf("%s: will remove %d file(s) from %s:\n", prog, len(files), dir)
	for _, name := range files {
		fmt.Printf("  - %s\n", name)
	}

	if !yes {
		if !isInteractive() {
			return fmt.Errorf("refusing to delete without confirmation; re-run with -y/--yes")
		}
		ok, err := promptYesNo(fmt.Sprintf("Delete these %d file(s)?", len(files)), false)
		if err != nil {
			return err
		}
		if !ok {
			fmt.Printf("%s: aborted — nothing removed.\n", prog)
			return nil
		}
	}

	var removed int
	for _, name := range files {
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			fmt.Printf("%s: warning — could not remove %s: %s\n", prog, name, err)
			continue
		}
		removed++
	}
	fmt.Printf("%s: removed %d of %d file(s) from %s.\n", prog, removed, len(files), dir)
	return nil
}
