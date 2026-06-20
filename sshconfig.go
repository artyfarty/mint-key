package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// resolveSSHTarget runs `ssh -G <target>` to resolve the effective login user
// and hostname, honouring ~/.ssh/config aliases (so `mintk deploy <scope> myalias`
// works the same as a full user@host). `ssh -G` only prints config; it never
// connects. Falls back to a literal user@host parse if `ssh -G` is unavailable.
func resolveSSHTarget(target string) (user, hostname string) {
	out, err := runOut("ssh", "-G", target)
	if err == nil {
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			switch strings.ToLower(f[0]) {
			case "user":
				if user == "" {
					user = f[1]
				}
			case "hostname":
				if hostname == "" {
					hostname = f[1]
				}
			}
		}
	}
	// Fallbacks if ssh -G gave nothing useful.
	if u, h, ok := splitTarget(target); ok {
		if user == "" {
			user = u
		}
		if hostname == "" {
			hostname = h
		}
	}
	if hostname == "" {
		hostname = aliasOf(target)
	}
	if user == "" {
		user = currentUser()
	}
	return user, hostname
}

// aliasOf returns the host token a user would type for `ssh <token>`: the part
// after any `user@`.
func aliasOf(target string) string {
	if _, h, ok := splitTarget(target); ok {
		return h
	}
	return target
}

// splitTarget parses user@host. host may itself contain no '@'.
func splitTarget(target string) (user, host string, ok bool) {
	i := strings.LastIndex(target, "@")
	if i <= 0 || i == len(target)-1 {
		return "", "", false
	}
	return target[:i], target[i+1:], true
}

// ensureSSHConfigHost adds or edits a `Host <alias>` block in ~/.ssh/config so
// that connecting to <alias> uses the minted cert: it sets IdentityFile to the
// scope's session key and IdentitiesOnly yes. For an existing block only those
// two directives are managed (HostName/User/etc. are left untouched); a new
// block is created with HostName/User filled from the resolved target.
//
// Returns a short description of what changed (empty if already correct).
func ensureSSHConfigHost(path, alias, hostname, user, identityFile string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	lines := []string{}
	if len(data) > 0 {
		lines = strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	}

	start, end := findHostBlock(lines, alias)
	var out []string
	var change string

	if start < 0 {
		// Append a fresh block.
		block := []string{"", "Host " + alias}
		if hostname != "" && hostname != alias {
			block = append(block, "    HostName "+hostname)
		}
		if user != "" {
			block = append(block, "    User "+user)
		}
		block = append(block,
			"    IdentityFile "+identityFile,
			"    IdentitiesOnly yes",
		)
		out = append(lines, block...)
		change = fmt.Sprintf("added Host %s (IdentityFile %s, IdentitiesOnly yes)", alias, identityFile)
	} else {
		body := lines[start+1 : end]
		indent := blockIndent(body)
		// Replace the managed directives in place (preserving order so a re-run
		// is a no-op); drop duplicate IdentityFile lines.
		var newBody []string
		seenID, seenIO := false, false
		for _, l := range body {
			switch firstToken(l) {
			case "identityfile":
				if !seenID {
					newBody = append(newBody, indent+"IdentityFile "+identityFile)
					seenID = true
				}
			case "identitiesonly":
				if !seenIO {
					newBody = append(newBody, indent+"IdentitiesOnly yes")
					seenIO = true
				}
			default:
				newBody = append(newBody, l)
			}
		}
		var prefix []string
		if !seenID {
			prefix = append(prefix, indent+"IdentityFile "+identityFile)
		}
		if !seenIO {
			prefix = append(prefix, indent+"IdentitiesOnly yes")
		}
		newBody = append(prefix, newBody...)
		out = append(out, lines[:start+1]...)
		out = append(out, newBody...)
		out = append(out, lines[end:]...)
		if seenID || seenIO {
			change = fmt.Sprintf("updated Host %s (IdentityFile %s, IdentitiesOnly yes)", alias, identityFile)
		} else {
			change = fmt.Sprintf("set IdentityFile/IdentitiesOnly on existing Host %s", alias)
		}
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	content := strings.Join(out, "\n") + "\n"
	if string(data) == content {
		return "", nil
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return "", err
	}
	return change, nil
}

// findHostBlock returns the [start, end) line range of the Host block whose
// pattern list contains alias exactly, or (-1, -1) if none. start is the index
// of the `Host` line; end is the index of the next Host/Match line (or len).
func findHostBlock(lines []string, alias string) (int, int) {
	start := -1
	for i, l := range lines {
		if firstToken(l) == "host" {
			if start >= 0 {
				return start, i
			}
			for _, pat := range strings.Fields(l)[1:] {
				if pat == alias {
					start = i
					break
				}
			}
		} else if start >= 0 && firstToken(l) == "match" {
			return start, i
		}
	}
	if start >= 0 {
		return start, len(lines)
	}
	return -1, -1
}

// blockIndent returns the leading whitespace used by a block's body lines, or
// four spaces as a default.
func blockIndent(body []string) string {
	for _, l := range body {
		if strings.TrimSpace(l) == "" {
			continue
		}
		return l[:len(l)-len(strings.TrimLeft(l, " \t"))]
	}
	return "    "
}

// firstToken returns the lowercased first whitespace-delimited token of a line
// (SSH config keys are case-insensitive), or "" for blank/comment lines.
func firstToken(l string) string {
	t := strings.TrimSpace(l)
	if t == "" || strings.HasPrefix(t, "#") {
		return ""
	}
	f := strings.Fields(t)
	return strings.ToLower(f[0])
}
