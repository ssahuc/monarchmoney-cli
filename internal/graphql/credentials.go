package graphql

import "net/http"

type Credentials interface {
	Apply(req *http.Request)
}

type TokenAuth string

func (t TokenAuth) Apply(req *http.Request) {
	if t != "" {
		req.Header.Set("Authorization", "Token "+string(t))
	}
}

type SessionAuth struct {
	SessionID string
	CSRFToken string
}

const webAppOrigin = "https://app.monarch.com"

var sessionCookieHosts = map[string]bool{"api.monarch.com": true}

// Apply sends the browser-session cookies only over HTTPS to Monarch's API host, so a
// misconfigured endpoint never receives them. Monarch's CSRF check needs the csrftoken
// cookie echoed in X-CSRFToken and the web-app Origin.
func (s SessionAuth) Apply(req *http.Request) {
	if req.URL.Scheme != "https" || !sessionCookieHosts[req.URL.Hostname()] {
		return
	}
	req.AddCookie(&http.Cookie{Name: "session_id", Value: s.SessionID})
	req.AddCookie(&http.Cookie{Name: "csrftoken", Value: s.CSRFToken})
	req.Header.Set("X-CSRFToken", s.CSRFToken)
	req.Header.Set("Origin", webAppOrigin)
}
