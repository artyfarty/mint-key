package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

// `mintk web service` runs the browser UI as a systemd *user* unit, so it is up
// whenever the machine (or the WSL distro) is, with no terminal holding it.
//
// What makes that simple: the UI is unlocked by a YubiKey tap, so the unit has
// no token to hand out, and the ssh-agent socket is only dialled when an action
// runs (each mint spawns ssh-keygen / ssh-add) — the unit doesn't have to start
// after whatever creates the socket, it only needs to know the path.

const webUnitName = "mintk-web.service"

func webServiceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "service",
		Short: "Run `mintk web` as a systemd user unit (install | uninstall | status)",
		Long: `Manages ` + webUnitName + `, a systemd *user* unit running ` + "`mintk web --no-open`" + `.
Linux and WSL (with systemd=true in /etc/wsl.conf) only for now.

install writes ~/.config/systemd/user/` + webUnitName + `, pointing at this binary,
with the current SSH_AUTH_SOCK (and MINTK_CONFIG, if set) baked in, then enables and
(re)starts it. Re-run it after moving the binary or changing the agent socket.
` + "`make install`" + ` restarts a running unit, so a rebuilt binary is picked up.`,
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "install",
		Short: "Write, enable and start the systemd user unit",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, args []string) error { return webServiceInstall() },
	}, &cobra.Command{
		Use:   "uninstall",
		Short: "Stop, disable and remove the systemd user unit",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, args []string) error { return webServiceUninstall() },
	}, &cobra.Command{
		Use:   "status",
		Short: "Show the unit's status and recent log",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireSystemdUser(); err != nil {
				return err
			}
			_ = run("systemctl", "--user", "--no-pager", "status", webUnitName)
			return nil
		},
	})
	return cmd
}

func requireSystemdUser() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("`web service` manages a systemd user unit — Linux/WSL only for now (on macOS run `%s web` in a terminal)", prog)
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return fmt.Errorf("systemctl not found — no systemd here")
	}
	if out, err := exec.Command("systemctl", "--user", "is-system-running").Output(); err != nil && len(out) == 0 {
		hint := ""
		if inWSL() {
			hint = "\n  under WSL, enable it with [boot] systemd=true in /etc/wsl.conf, then `wsl --shutdown`"
		}
		return fmt.Errorf("no systemd user manager is running%s", hint)
	}
	return nil
}

func webUnitPath() string {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		base = filepath.Join(home(), ".config")
	}
	return filepath.Join(base, "systemd", "user", webUnitName)
}

// sdQuote quotes one word for a unit file: double quotes with \ and " escaped,
// and % doubled (systemd expands %-specifiers inside quotes too).
func sdQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, `%`, `%%`)
	return `"` + s + `"`
}

// webUnitText renders the unit. env is written in order, empty values skipped.
func webUnitText(exe string, env [][2]string) string {
	var b strings.Builder
	b.WriteString("# Written by `mintk web service install` — re-run that to update it.\n")
	b.WriteString("[Unit]\n")
	b.WriteString("Description=mintk web — browser UI for mintk (unlocked with a YubiKey tap)\n\n")
	b.WriteString("[Service]\n")
	b.WriteString("Type=simple\n")
	fmt.Fprintf(&b, "ExecStart=%s web --no-open\n", sdQuote(exe))
	for _, kv := range env {
		if kv[1] != "" {
			fmt.Fprintf(&b, "Environment=%s\n", sdQuote(kv[0]+"="+kv[1]))
		}
	}
	b.WriteString("Restart=on-failure\n")
	b.WriteString("RestartSec=5\n\n")
	b.WriteString("[Install]\n")
	b.WriteString("WantedBy=default.target\n")
	return b.String()
}

func webServiceInstall() error {
	if err := requireSystemdUser(); err != nil {
		return err
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	port, err := webPort(cfg, "")
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	if strings.HasPrefix(exe, os.TempDir()) || strings.Contains(exe, "/go-build") {
		return fmt.Errorf("refusing to point the unit at %s — install the binary first (`make install`)", exe)
	}

	sock := os.Getenv("SSH_AUTH_SOCK")
	switch {
	case sock == "" && cfg.Mode == "agent":
		return fmt.Errorf("SSH_AUTH_SOCK is not set, and mode=agent signs through the agent — run this from a shell that has it")
	case strings.HasPrefix(sock, "/tmp/ssh-"):
		fmt.Printf("%s: warning — SSH_AUTH_SOCK=%s looks like a per-session ssh-agent socket;\n"+
			"  the unit will keep using this path after that agent is gone. A fixed path is better.\n", prog, sock)
	}
	mcfg := ""
	if os.Getenv("MINTK_CONFIG") != "" {
		mcfg = configPath()
	}

	path := webUnitPath()
	text := webUnitText(exe, [][2]string{{"SSH_AUTH_SOCK", sock}, {"MINTK_CONFIG", mcfg}})
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := writeFileAtomic(path, []byte(text), 0o644); err != nil {
		return err
	}
	fmt.Printf("%s: wrote %s\n", prog, path)

	// A foreground `mintk web` would hold the port; the unit would then crash-loop.
	if webRunning(port) && !unitActive() {
		fmt.Printf("%s: note — something already serves port %d (a `%s web` in a terminal?); stop it, then `systemctl --user restart %s`\n",
			prog, port, prog, webUnitName)
	}
	for _, args := range [][]string{
		{"--user", "daemon-reload"},
		{"--user", "enable", webUnitName},
		{"--user", "restart", webUnitName},
	} {
		if err := run("systemctl", args...); err != nil {
			return fmt.Errorf("systemctl %s: %w", strings.Join(args, " "), err)
		}
	}
	fmt.Printf("%s: %s enabled and started — %s\n", prog, webUnitName, webBaseURL(port))
	creds, _ := (&credStore{path: webCredentialsPath(cfg)}).load()
	if len(creds) == 0 {
		fmt.Printf("%s: no security key registered yet — run `%s web enroll`\n", prog, prog)
	}
	fmt.Printf("%s: logs: journalctl --user -u %s\n", prog, webUnitName)
	return nil
}

func unitActive() bool {
	return exec.Command("systemctl", "--user", "is-active", "--quiet", webUnitName).Run() == nil
}

func webServiceUninstall() error {
	if err := requireSystemdUser(); err != nil {
		return err
	}
	_ = run("systemctl", "--user", "disable", "--now", webUnitName)
	path := webUnitPath()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	_ = run("systemctl", "--user", "daemon-reload")
	fmt.Printf("%s: removed %s\n", prog, path)
	return nil
}
