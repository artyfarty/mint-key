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
	root.AddCommand(doctorCmd())
	root.AddCommand(keyCmd())
	root.AddCommand(scopesCmd())
	root.AddCommand(cleanCmd())
	root.AddCommand(cleanKeysCmd())
	root.AddCommand(deployCmd())

	// Print the command's full help when its arguments or flags don't validate,
	// so a mistake shows usage instead of just a terse error.
	root.SetFlagErrorFunc(func(c *cobra.Command, err error) error {
		_ = c.Help()
		return err
	})
	helpOnArgError(root)

	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", prog, err)
		os.Exit(1)
	}
}

// helpOnArgError wraps each command's positional-args validator so a validation
// failure prints that command's help before the error bubbles up. FlagErrorFunc
// (set on the root) is inherited by subcommands and covers flag-parsing errors.
func helpOnArgError(cmd *cobra.Command) {
	if cmd.Args != nil {
		orig := cmd.Args
		cmd.Args = func(c *cobra.Command, args []string) error {
			if err := orig(c, args); err != nil {
				_ = c.Help()
				fmt.Fprintln(os.Stderr)
				return err
			}
			return nil
		}
	}
	for _, sub := range cmd.Commands() {
		helpOnArgError(sub)
	}
}
