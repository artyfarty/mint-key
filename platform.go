package main

import (
	"os"
	"os/exec"
	"strings"
)

// inWSL reports whether we're running under WSL (the agent/clean/wsl-delegate
// paths only make sense there).
func inWSL() bool {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return false
	}
	v := strings.ToLower(string(data))
	return strings.Contains(v, "microsoft") || strings.Contains(v, "wsl")
}

// ykcs11Candidates are the usual PKCS#11 module locations across Linux/macOS,
// libykcs11 (Yubico) preferred over opensc-pkcs11 (OpenSC).
var ykcs11Candidates = []string{
	// Yubico libykcs11
	"/usr/lib/x86_64-linux-gnu/libykcs11.so",
	"/usr/lib/libykcs11.so",
	"/usr/local/lib/libykcs11.so",
	"/usr/local/lib/libykcs11.dylib",    // macOS (Intel brew / pkg)
	"/opt/homebrew/lib/libykcs11.dylib", // macOS (Apple-silicon brew)
	// OpenSC
	"/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
	"/usr/lib/opensc-pkcs11.so",
	"/usr/local/lib/opensc-pkcs11.so",
	"/opt/homebrew/lib/opensc-pkcs11.so",
	"/Library/OpenSC/lib/opensc-pkcs11.so", // macOS OpenSC.pkg installer
}

// detectYKCS11 returns the first PKCS#11 module that exists, or "" if none.
func detectYKCS11() string {
	for _, p := range ykcs11Candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// toWinPath converts an MSYS/Cygwin path form for Git-Bash tools that choke on
// C:\ backslash args: /mnt/c/x -> /c/x ; other paths pass through unchanged.
func toWinPath(p string) string {
	if len(p) >= 6 && strings.HasPrefix(p, "/mnt/") && p[6] == '/' {
		return "/" + p[5:6] + p[6:]
	}
	return p
}

// toWin converts to native-Windows path form (/mnt/c/x -> C:\x) for .exe tools
// like ykman.exe, using wslpath when available.
func toWin(p string) string {
	if _, err := exec.LookPath("wslpath"); err == nil {
		out, err := exec.Command("wslpath", "-w", p).Output()
		if err == nil {
			return strings.TrimSpace(string(out))
		}
	}
	return p
}

// winSystemExes are the Windows binaries mintk runs through interop, by their
// usual place in the Windows directory.
var winSystemExes = map[string]string{
	"cmd.exe":        `C:\Windows\System32\cmd.exe`,
	"where.exe":      `C:\Windows\System32\where.exe`,
	"powershell.exe": `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
	"explorer.exe":   `C:\Windows\explorer.exe`,
}

// winExe resolves one of winSystemExes without depending on PATH. A login shell
// under WSL has the Windows directories in PATH (appendWindowsPath), but a systemd
// unit — `mintk web service` — or a cron job does not, and a bare "cmd.exe" then
// fails with "executable file not found". wslpath maps the Windows path through
// whatever automount root this distro uses.
func winExe(name string) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	if win, ok := winSystemExes[name]; ok {
		if out, err := exec.Command("wslpath", "-u", win).Output(); err == nil {
			if p := strings.TrimSpace(string(out)); isExecutable(p) {
				return p
			}
		}
	}
	return name // let exec report it as not found
}
