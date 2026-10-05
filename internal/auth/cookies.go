package auth

import (
	"fmt"
	"strings"
)

// ParseSessionCookies reduces a browser Cookie header to the two cookies Monarch's
// session needs; every other cookie (Cloudflare clearance, analytics) is discarded.
// Errors name missing cookies and never echo the input.
func ParseSessionCookies(header string) (sessionID, csrfToken string, err error) {
	header = strings.TrimSpace(header)
	if name, rest, ok := strings.Cut(header, ":"); ok && strings.EqualFold(strings.TrimSpace(name), "cookie") {
		header = rest
	}

	found := map[string]string{}
	for _, pair := range strings.Split(header, ";") {
		name, value, ok := strings.Cut(strings.TrimSpace(pair), "=")
		name = strings.TrimSpace(name)
		if !ok || (name != "session_id" && name != "csrftoken") {
			continue
		}
		if _, seen := found[name]; !seen {
			found[name] = strings.Trim(strings.TrimSpace(value), `"`)
		}
	}

	var missing []string
	for _, name := range []string{"session_id", "csrftoken"} {
		if found[name] == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return "", "", fmt.Errorf("cookie header is missing %s", strings.Join(missing, " and "))
	}
	return found["session_id"], found["csrftoken"], nil
}
