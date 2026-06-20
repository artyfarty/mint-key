package main

import (
	"fmt"
	"os/exec"

	"github.com/spf13/cobra"
)

func cleanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "clean",
		Short: "Purge stale CA certs from the Windows store after a YubiKey swap (WSL+agent path)",
		Long: `Multiple YubiKeys carrying the same CA key each enroll a cert (identical
pubkey) into Windows CurrentUser\My; the agent can then try a container whose
card isn't plugged in → "agent refused operation". clean purges every such cert,
then asks you to unplug + re-plug the YubiKey you want — Windows re-enrolls only
its (linked) cert.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			return runClean(cfg)
		},
	}
}

func runClean(cfg *Config) error {
	if !inWSL() {
		return fmt.Errorf("`clean` applies to the WSL + Windows-agent setup")
	}
	if cfg.CACertCN == "" {
		return fmt.Errorf("set ca_cert_cn (the CA cert subject CN, e.g. ssh-user-ca-mintkey)")
	}

	fmt.Printf("%s: purging all %q certs from Windows CurrentUser\\My...\n", prog, cfg.CACertCN)
	psCmd := fmt.Sprintf(
		"Get-ChildItem Cert:\\CurrentUser\\My | Where-Object { $_.Subject -like '*%s*' } | Remove-Item",
		cfg.CACertCN)
	if err := exec.Command("powershell.exe", "-NoProfile", "-Command", psCmd).Run(); err != nil {
		return fmt.Errorf("could not purge the cert store: %w", err)
	}

	fmt.Printf("%s: purged. Now UNPLUG + RE-PLUG the YubiKey you want to mint with — Windows\n", prog)
	fmt.Printf("       re-enrolls only its (linked) cert. Then re-run your mint.\n")
	return nil
}
