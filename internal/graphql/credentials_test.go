package graphql

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	clierrors "github.com/thedavidweng/monarchmoney-cli/internal/errors"
	"github.com/thedavidweng/monarchmoney-cli/internal/testutil"
)

const (
	sentinelSessionID = "SENTINEL_SID_x9f2"
	sentinelCSRF      = "SENTINEL_CSRF_x9f2"
)

var sentinelSession = SessionAuth{SessionID: sentinelSessionID, CSRFToken: sentinelCSRF}

func TestSessionAuthSendsOnlyMinimalCredentials(t *testing.T) {
	req := httptest.NewRequest("POST", "https://api.monarch.com/graphql", http.NoBody)
	req.Header.Del("Cookie")
	sentinelSession.Apply(req)

	cookies := req.Cookies()
	if len(cookies) != 2 {
		t.Fatalf("cookies = %v, want exactly session_id and csrftoken", cookies)
	}
	got := map[string]string{}
	for _, c := range cookies {
		got[c.Name] = c.Value
	}
	if got["session_id"] != sentinelSessionID || got["csrftoken"] != sentinelCSRF {
		t.Fatalf("cookies = %v", got)
	}
	if h := req.Header.Get("X-CSRFToken"); h != sentinelCSRF {
		t.Errorf("X-CSRFToken = %q, want the csrftoken cookie value", h)
	}
	if h := req.Header.Get("Origin"); h != "https://app.monarch.com" {
		t.Errorf("Origin = %q", h)
	}
	for _, name := range []string{"Authorization", "Device-UUID", "Monarch-Client", "Monarch-Client-Version"} {
		if h := req.Header.Get(name); h != "" {
			t.Errorf("%s = %q, want unset", name, h)
		}
	}
}

func TestSessionAuthWithholdsCookiesFromOtherHosts(t *testing.T) {
	for _, target := range []string{
		"http://api.monarch.com/graphql",
		"https://example.invalid/graphql",
		"https://api.monarch.com.evil.example/graphql",
	} {
		req := httptest.NewRequest("POST", target, http.NoBody)
		req.Header.Del("Cookie")
		sentinelSession.Apply(req)
		if len(req.Header) != 0 {
			t.Errorf("%s received headers %v, want none", target, req.Header)
		}
	}
}

func TestTokenAuth(t *testing.T) {
	req := httptest.NewRequest("POST", "https://api.monarch.com/graphql", http.NoBody)
	TokenAuth("abc").Apply(req)
	if h := req.Header.Get("Authorization"); h != "Token abc" {
		t.Errorf("Authorization = %q", h)
	}
	if len(req.Cookies()) != 0 {
		t.Errorf("token auth sent cookies %v", req.Cookies())
	}

	empty := httptest.NewRequest("POST", "https://api.monarch.com/graphql", http.NoBody)
	TokenAuth("").Apply(empty)
	if h := empty.Header.Get("Authorization"); h != "" {
		t.Errorf("empty token sent Authorization %q", h)
	}
}

func sessionClient(status int, body string, calls *int, seen **http.Request) *Client {
	client := NewClient("https://api.monarch.com/graphql", sentinelSession, time.Second)
	client.HTTP = &http.Client{Transport: testutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
		*calls++
		*seen = req
		return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewBufferString(body))}, nil
	})}
	return client
}

func TestDoWithSessionAuth(t *testing.T) {
	var calls int
	var seen *http.Request
	client := sessionClient(200, `{"data":{"me":{"id":"1"}}}`, &calls, &seen)

	if err := client.Do(context.Background(), &Request{OperationName: "GetIdentity", Query: GetIdentityQuery}, &struct{}{}); err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	if seen.Header.Get("X-CSRFToken") != sentinelCSRF || seen.Header.Get("Authorization") != "" {
		t.Fatalf("request headers = %v", seen.Header)
	}
	if c, err := seen.Cookie("session_id"); err != nil || c.Value != sentinelSessionID {
		t.Fatalf("session_id cookie = %v, %v", c, err)
	}
}

func TestDoClassifiesForbidden(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		wantCode clierrors.Code
		wantMsg  string
	}{
		{"session rejected", `{"detail":"Authentication credentials were not provided."}`, clierrors.AuthSessionExpired, "Monarch rejected the session: Authentication credentials were not provided."},
		{"csrf failed", `{"detail":"CSRF Failed: CSRF token missing."}`, clierrors.AuthSessionExpired, "CSRF Failed"},
		{"edge block json", `{"detail":"The site owner has blocked access based on your browser's signature.","error_code":1010}`, clierrors.APIError, "edge protection"},
		{"edge block html", `<html><title>Access denied | api.monarch.com used Cloudflare to restrict access</title></html>`, clierrors.APIError, "edge protection"},
		{"unexplained", ``, clierrors.APIError, "API returned status 403"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls int
			var seen *http.Request
			client := sessionClient(403, tt.body, &calls, &seen)

			err := client.Do(context.Background(), &Request{Query: GetIdentityQuery}, &struct{}{})

			cliErr, ok := err.(*clierrors.Error)
			if !ok || cliErr.Code != tt.wantCode || !strings.Contains(cliErr.Message, tt.wantMsg) {
				t.Fatalf("error = %v, want %s containing %q", err, tt.wantCode, tt.wantMsg)
			}
			if calls != 1 {
				t.Errorf("calls = %d, want 1 (403 must not retry)", calls)
			}
			for _, secret := range []string{sentinelSessionID, sentinelCSRF, "<html"} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("error %q leaks %q", err.Error(), secret)
				}
			}
		})
	}
}
