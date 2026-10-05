package auth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thedavidweng/monarchmoney-cli/internal/graphql"
)

const (
	sentinelSessionID = "SENTINEL_SID_q7"
	sentinelCSRF      = "SENTINEL_CSRF_q7"
)

func TestParseSessionCookiesKeepsOnlySessionCookies(t *testing.T) {
	headers := []string{
		"cf_clearance=CFSECRET; __cf_bm=BMSECRET; session_id=" + sentinelSessionID + "; _ga=GA1.1; csrftoken=" + sentinelCSRF,
		"Cookie: session_id=" + sentinelSessionID + ";csrftoken=" + sentinelCSRF,
		"  cookie:  csrftoken=\"" + sentinelCSRF + "\" ;  session_id = " + sentinelSessionID + "  \n",
		"session_id=" + sentinelSessionID + "; csrftoken=" + sentinelCSRF + "; session_id=SECOND",
	}
	for _, header := range headers {
		sid, csrf, err := ParseSessionCookies(header)
		if err != nil {
			t.Fatalf("ParseSessionCookies() error = %v", err)
		}
		if sid != sentinelSessionID || csrf != sentinelCSRF {
			t.Errorf("got %q/%q, want the session cookies", sid, csrf)
		}
	}
}

func TestParseSessionCookiesRejectsIncompleteHeaders(t *testing.T) {
	tests := map[string]string{
		"cf_clearance=CFSECRET; csrftoken=" + sentinelCSRF:       "missing session_id",
		"session_id=" + sentinelSessionID + "; __cf_bm=BMSECRET": "missing csrftoken",
		"session_id=; csrftoken=":                                "missing session_id and csrftoken",
		"":                                                       "missing session_id and csrftoken",
	}
	for header, want := range tests {
		_, _, err := ParseSessionCookies(header)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want containing %q", err, want)
			continue
		}
		for _, secret := range []string{sentinelSessionID, sentinelCSRF, "CFSECRET", "BMSECRET"} {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("error %q leaks %q", err.Error(), secret)
			}
		}
	}
}

func TestBrowserSessionRoundTripAndCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	store := NewStore(path)
	if err := store.Save(&Session{Profile: "default", Email: "a@example.com", AuthMethod: AuthMethodBrowserSession, SessionID: sentinelSessionID, CSRFToken: sentinelCSRF}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	assertFilePerms(t, path, 0o600)

	raw, _ := os.ReadFile(path)
	var stored map[string]any
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatalf("session file is not JSON: %v", err)
	}
	if _, ok := stored["token"]; ok {
		t.Errorf("browser session stored a token field: %v", stored)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	want := graphql.SessionAuth{SessionID: sentinelSessionID, CSRFToken: sentinelCSRF}
	if got := loaded.Credentials(); got != want {
		t.Errorf("Credentials() = %#v, want %#v", got, want)
	}
}

func TestLegacyTokenSessionStillYieldsTokenAuth(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.json")
	if err := os.WriteFile(path, []byte(`{"profile":"default","email":"a@example.com","token":"legacy-token"}`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	loaded, err := NewStore(path).Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got := loaded.Credentials(); got != graphql.TokenAuth("legacy-token") {
		t.Errorf("Credentials() = %#v, want TokenAuth(legacy-token)", got)
	}
}

func TestBrowserSessionResolvesEnvIndirection(t *testing.T) {
	t.Setenv("MM_TEST_SID", sentinelSessionID)
	t.Setenv("MM_TEST_CSRF", sentinelCSRF)
	path := filepath.Join(t.TempDir(), "session.json")
	if err := os.WriteFile(path, []byte(`{"auth_method":"browser_session","session_id":"env:MM_TEST_SID","csrf_token":"env:MM_TEST_CSRF"}`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	loaded, err := NewStore(path).Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if loaded.SessionID != sentinelSessionID || loaded.CSRFToken != sentinelCSRF {
		t.Errorf("loaded %q/%q, want resolved env values", loaded.SessionID, loaded.CSRFToken)
	}

	t.Setenv("MM_TEST_CSRF", "")
	if _, err := NewStore(path).Load(); err == nil || !strings.Contains(err.Error(), "MM_TEST_CSRF") {
		t.Errorf("Load() error = %v, want unset-variable error naming MM_TEST_CSRF", err)
	}
}
