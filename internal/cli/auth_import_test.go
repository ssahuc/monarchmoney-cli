package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thedavidweng/monarchmoney-cli/internal/auth"
	clierrors "github.com/thedavidweng/monarchmoney-cli/internal/errors"
	"github.com/thedavidweng/monarchmoney-cli/internal/graphql"
)

const (
	importSentinelSID  = "SENTINEL_SID_cli_4d"
	importSentinelCSRF = "SENTINEL_CSRF_cli_4d"
	importSentinelCF   = "SENTINEL_CF_cli_4d"
)

var importSentinels = []string{importSentinelSID, importSentinelCSRF, importSentinelCF}

type importHarness struct {
	sessionPath string
	exitCode    int
	validated   []graphql.Credentials
	prompts     int
}

func newImportHarness(t *testing.T, terminal, jsonOutput bool) *importHarness {
	t.Helper()
	h := &importHarness{sessionPath: filepath.Join(t.TempDir(), "session.json"), exitCode: -1}
	t.Cleanup(withAuthTestDefaults(t, h.sessionPath))
	oldTerminal, oldReadStdin := stdinIsTerminal, readStdin
	t.Cleanup(func() { stdinIsTerminal, readStdin = oldTerminal, oldReadStdin })

	jsonMode = jsonOutput
	stdinIsTerminal = func() bool { return terminal }
	readStdin = func() ([]byte, error) { return nil, errors.New("unexpected stdin read") }
	exitFunc = func(code int) { h.exitCode = code }
	fetchIdentity = func(_ context.Context, creds graphql.Credentials) (*identityResult, error) {
		h.validated = append(h.validated, creds)
		return &identityResult{Email: "a@example.com"}, nil
	}
	return h
}

func (h *importHarness) answerPrompts(values ...string) {
	readPassword = func(int) ([]byte, error) {
		h.prompts++
		return []byte(values[h.prompts-1]), nil
	}
}

func (h *importHarness) run(t *testing.T) string {
	t.Helper()
	out := captureStdout(t, func() { importSessionCmd.Run(importSessionCmd, nil) })
	for _, secret := range importSentinels {
		if strings.Contains(out, secret) {
			t.Fatalf("output leaks %q: %s", secret, out)
		}
	}
	return out
}

func (h *importHarness) stored(t *testing.T) (sess *auth.Session, raw string) {
	t.Helper()
	data, err := os.ReadFile(h.sessionPath)
	if err != nil {
		t.Fatalf("session file not written: %v", err)
	}
	sess, err = auth.NewStore(h.sessionPath).Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	return sess, string(data)
}

func wantBrowserSession(t *testing.T, h *importHarness) {
	t.Helper()
	want := graphql.SessionAuth{SessionID: importSentinelSID, CSRFToken: importSentinelCSRF}
	if len(h.validated) != 1 || h.validated[0] != want {
		t.Fatalf("validated with %#v, want one validation with %#v", h.validated, want)
	}
	sess, raw := h.stored(t)
	if sess.AuthMethod != auth.AuthMethodBrowserSession || sess.SessionID != importSentinelSID || sess.CSRFToken != importSentinelCSRF || sess.Email != "a@example.com" {
		t.Fatalf("stored session = %#v", sess)
	}
	if strings.Contains(raw, importSentinelCF) || strings.Contains(raw, "cf_clearance") || strings.Contains(raw, `"token"`) {
		t.Fatalf("session file kept more than the session cookies: %s", strings.NewReplacer(importSentinelSID, "<sid>", importSentinelCSRF, "<csrf>").Replace(raw))
	}
}

func TestImportSessionInteractive(t *testing.T) {
	h := newImportHarness(t, true, false)
	h.answerPrompts(" session_id="+importSentinelSID+"\n", `"`+importSentinelCSRF+`"`)

	out := h.run(t)

	if h.prompts != 2 || !strings.Contains(out, "session_id (hidden): ") || !strings.Contains(out, "csrftoken (hidden): ") {
		t.Fatalf("prompts = %d, out = %q", h.prompts, out)
	}
	if !strings.Contains(out, "Monarch browser session saved for a@example.com.") {
		t.Fatalf("out = %q, want saved message", out)
	}
	wantBrowserSession(t, h)
}

func TestImportSessionFromStdinKeepsOnlySessionCookies(t *testing.T) {
	h := newImportHarness(t, false, true)
	readStdin = func() ([]byte, error) {
		return []byte("cf_clearance=" + importSentinelCF + "; session_id=" + importSentinelSID + "; _ga=x; csrftoken=" + importSentinelCSRF + "\n"), nil
	}

	out := h.run(t)

	var env struct {
		OK   bool           `json:"ok"`
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &env); err != nil || !env.OK {
		t.Fatalf("envelope = %q (%v)", out, err)
	}
	if env.Data["auth_method"] != "browser_session" || env.Data["email"] != "a@example.com" || env.Data["session_path"] != h.sessionPath {
		t.Fatalf("data = %v", env.Data)
	}
	if h.prompts != 0 {
		t.Fatalf("prompted %d times while reading stdin", h.prompts)
	}
	wantBrowserSession(t, h)
}

func TestImportSessionJSONOnTerminalRefusesToPrompt(t *testing.T) {
	h := newImportHarness(t, true, true)

	out := h.run(t)

	if h.exitCode != 2 || h.prompts != 0 || len(h.validated) != 0 || !strings.Contains(out, string(clierrors.InvalidArguments)) {
		t.Fatalf("exit=%d prompts=%d validations=%d out=%q", h.exitCode, h.prompts, len(h.validated), out)
	}
}

func TestImportSessionMissingCookieIsNotSentToMonarch(t *testing.T) {
	h := newImportHarness(t, false, true)
	readStdin = func() ([]byte, error) {
		return []byte("cf_clearance=" + importSentinelCF + "; csrftoken=" + importSentinelCSRF), nil
	}

	out := h.run(t)

	if h.exitCode != 2 || len(h.validated) != 0 || !strings.Contains(out, "missing session_id") {
		t.Fatalf("exit=%d validations=%d out=%q", h.exitCode, len(h.validated), out)
	}
	if _, err := os.Stat(h.sessionPath); !os.IsNotExist(err) {
		t.Fatalf("session file written for an invalid import: %v", err)
	}
}

func TestImportSessionRejectedByMonarchKeepsExistingSession(t *testing.T) {
	h := newImportHarness(t, false, true)
	existing := &auth.Session{Profile: "default", Email: "old@example.com", Token: "old-token", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := auth.NewStore(h.sessionPath).Save(existing); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	readStdin = func() ([]byte, error) {
		return []byte("session_id=" + importSentinelSID + "; csrftoken=" + importSentinelCSRF), nil
	}
	fetchIdentity = func(context.Context, graphql.Credentials) (*identityResult, error) {
		return nil, clierrors.New(clierrors.AuthSessionExpired, "Monarch rejected the session: Authentication credentials were not provided.", clierrors.CatAuth, false, nil)
	}

	out := h.run(t)

	if h.exitCode != 3 || !strings.Contains(out, string(clierrors.AuthRequired)) || !strings.Contains(out, "nothing was saved") {
		t.Fatalf("exit=%d out=%q", h.exitCode, out)
	}
	if strings.Contains(out, "old@example.com") {
		t.Fatalf("rejection was reported against the stored session: %q", out)
	}
	sess, _ := h.stored(t)
	if sess.Token != "old-token" || sess.AuthMethod != "" {
		t.Fatalf("existing session was replaced: %#v", sess)
	}
}

func saveBrowserSession(t *testing.T, path string) {
	t.Helper()
	if err := auth.NewStore(path).Save(&auth.Session{
		Profile: "default", Email: "a@example.com", CreatedAt: time.Now(), UpdatedAt: time.Now(),
		AuthMethod: auth.AuthMethodBrowserSession, SessionID: importSentinelSID, CSRFToken: importSentinelCSRF,
	}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
}

func TestStatusForBrowserSession(t *testing.T) {
	h := newImportHarness(t, false, true)
	saveBrowserSession(t, h.sessionPath)

	out := captureStdout(t, func() { statusCmd.Run(statusCmd, nil) })

	if !strings.Contains(out, `"auth_method":"browser_session"`) {
		t.Fatalf("status = %q, want auth_method browser_session", out)
	}
	if len(h.validated) != 1 || h.validated[0] != (graphql.SessionAuth{SessionID: importSentinelSID, CSRFToken: importSentinelCSRF}) {
		t.Fatalf("status validated with %#v", h.validated)
	}
	for _, secret := range importSentinels {
		if strings.Contains(out, secret) {
			t.Fatalf("status leaks %q", secret)
		}
	}
}

func TestExpiredBrowserSessionPointsToImport(t *testing.T) {
	h := newImportHarness(t, false, true)
	saveBrowserSession(t, h.sessionPath)
	fetchIdentity = func(context.Context, graphql.Credentials) (*identityResult, error) {
		return nil, clierrors.New(clierrors.AuthSessionExpired, "Monarch rejected the session: CSRF Failed", clierrors.CatAuth, false, nil)
	}

	out := captureStdout(t, func() { statusCmd.Run(statusCmd, nil) })

	if h.exitCode != 3 || !strings.Contains(out, "Monarch browser session for a@example.com") || !strings.Contains(out, "monarch auth import-session") {
		t.Fatalf("exit=%d out=%q", h.exitCode, out)
	}
	if strings.Contains(out, "MFA") || strings.Contains(out, "auth login") {
		t.Fatalf("expired browser session suggested MFA or password login: %q", out)
	}
}

func TestLogoutBrowserSessionIsLocalOnly(t *testing.T) {
	h := newImportHarness(t, false, false)
	saveBrowserSession(t, h.sessionPath)

	out := captureStdout(t, func() { logoutCmd.Run(logoutCmd, nil) })

	if _, err := os.Stat(h.sessionPath); !os.IsNotExist(err) {
		t.Fatalf("session file still present: %v", err)
	}
	if !strings.Contains(out, "your Monarch browser session is still active") {
		t.Fatalf("out = %q, want browser-session note", out)
	}
}

func TestDataCommandsUseStoredBrowserSession(t *testing.T) {
	h := newImportHarness(t, false, true)
	saveBrowserSession(t, h.sessionPath)
	oldCfg := cfgFile
	cfgFile = filepath.Join(t.TempDir(), "config.yaml")
	t.Cleanup(func() { cfgFile = oldCfg })

	deps, ok := newDeps(nil, "accounts.list", time.Now())
	if !ok {
		t.Fatal("newDeps() failed for a stored browser session")
	}
	client, isClient := deps.Service.Client.(*graphql.Client)
	if !isClient || client.Auth != (graphql.SessionAuth{SessionID: importSentinelSID, CSRFToken: importSentinelCSRF}) {
		t.Fatalf("client auth = %#v", deps.Service.Client)
	}
}
