package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

const prog = "mintk"

func main() {
	root := &cobra.Command{
		Use:           prog,
		Short:         "Issue short-lived, scope-limited OpenSSH user certs from a YubiKey-held CA",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(initCmd())
	root.AddCommand(keyCmd())
	root.AddCommand(scopesCmd())
	root.AddCommand(cleanCmd())
	root.AddCommand(deployCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", prog, err)
		os.Exit(1)
	}
}
