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
// libykcs11 preferred over opensc-pkcs11.
var ykcs11Candidates = []string{
	"/usr/lib/x86_64-linux-gnu/libykcs11.so",
	"/usr/lib/libykcs11.so",
	"/usr/local/lib/libykcs11.so",
	"/usr/local/lib/libykcs11.dylib",
	"/opt/homebrew/lib/libykcs11.dylib",
	"/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
	"/usr/lib/opensc-pkcs11.so",
	"/usr/local/lib/opensc-pkcs11.so",
	"/opt/homebrew/lib/opensc-pkcs11.so",
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
