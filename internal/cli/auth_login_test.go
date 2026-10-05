package cli

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thedavidweng/monarchmoney-cli/internal/auth"
	clierrors "github.com/thedavidweng/monarchmoney-cli/internal/errors"
)

type loginHarness struct {
	calls    []string
	prompts  int
	exitCode int
	stdout   string
}

func runLogin(t *testing.T, jsonOutput bool, results ...error) *loginHarness {
	t.Helper()
	restore := withAuthTestDefaults(t, filepath.Join(t.TempDir(), "session.json"))
	t.Cleanup(restore)
	for _, name := range []string{"MONARCH_EMAIL", "MONARCH_PASSWORD", "MONARCH_MFA_CODE", "MONARCH_MFA_SECRET"} {
		t.Setenv(name, "")
	}
	jsonMode = jsonOutput
	_ = loginCmd.Flags().Set("email", "a@example.com")
	_ = loginCmd.Flags().Set("password", "secret")
	_ = loginCmd.Flags().Set("mfa-code", "")
	_ = loginCmd.Flags().Set("mfa-secret", "")

	h := &loginHarness{exitCode: -1}
	scanInput = func(args ...any) (int, error) {
		h.prompts++
		if p, ok := args[0].(*string); ok {
			*p = "654321"
		}
		return 1, nil
	}
	exitFunc = func(code int) { h.exitCode = code }
	authenticateSession = func(email, password, mfaCode, mfaSecret string) (*auth.Session, error) {
		h.calls = append(h.calls, mfaCode)
		if err := results[len(h.calls)-1]; err != nil {
			return nil, err
		}
		return &auth.Session{Email: email, Token: "token", CreatedAt: time.Now(), UpdatedAt: time.Now()}, nil
	}

	h.stdout = captureStdout(t, func() { loginCmd.Run(loginCmd, nil) })
	return h
}

func TestLoginNonMFARejectionsNeverPromptForMFA(t *testing.T) {
	for _, jsonOutput := range []bool{false, true} {
		t.Run(fmt.Sprintf("json=%v", jsonOutput), func(t *testing.T) {
			rejection := clierrors.New(clierrors.AuthRequired, "Monarch rejected the login: Please update to the latest version of the app to continue login.", clierrors.CatAuth, false, nil)
			h := runLogin(t, jsonOutput, rejection)

			if h.prompts != 0 || strings.Contains(h.stdout, "MFA Code:") {
				t.Fatalf("prompted for MFA on a non-MFA rejection (prompts=%d, stdout=%q)", h.prompts, h.stdout)
			}
			if len(h.calls) != 1 {
				t.Fatalf("authenticate calls = %d, want 1", len(h.calls))
			}
			if h.exitCode != 3 {
				t.Fatalf("exit code = %d, want 3", h.exitCode)
			}
		})
	}
}

func TestLoginRepromptsOnlyForMFAChallenge(t *testing.T) {
	challenge := clierrors.New(clierrors.AuthMFARequired, "MFA code required", clierrors.CatAuth, false, nil)
	h := runLogin(t, false, challenge, nil)

	if h.prompts != 1 || !strings.Contains(h.stdout, "MFA Code:") {
		t.Fatalf("prompts = %d, stdout = %q, want one MFA prompt", h.prompts, h.stdout)
	}
	if len(h.calls) != 2 || h.calls[0] != "" || h.calls[1] != "654321" {
		t.Fatalf("authenticate mfa codes = %q, want [\"\" \"654321\"]", h.calls)
	}
	if !strings.Contains(h.stdout, "Successfully logged in as a@example.com.") {
		t.Fatalf("stdout = %q, want success", h.stdout)
	}
}

func TestLoginJSONModeDoesNotPromptOnMFAChallenge(t *testing.T) {
	challenge := clierrors.New(clierrors.AuthMFARequired, "MFA code required", clierrors.CatAuth, false, nil)
	h := runLogin(t, true, challenge)

	if h.prompts != 0 || len(h.calls) != 1 || h.exitCode != 3 {
		t.Fatalf("prompts=%d calls=%d exit=%d, want 0/1/3", h.prompts, len(h.calls), h.exitCode)
	}
}

func TestLoginFromEnvironmentDoesNotPrompt(t *testing.T) {
	restore := withAuthTestDefaults(t, filepath.Join(t.TempDir(), "session.json"))
	defer restore()
	t.Setenv("MONARCH_EMAIL", "env@example.com")
	t.Setenv("MONARCH_PASSWORD", "env-secret")
	t.Setenv("MONARCH_MFA_CODE", "")
	t.Setenv("MONARCH_MFA_SECRET", "")
	_ = loginCmd.Flags().Set("email", "")
	_ = loginCmd.Flags().Set("password", "")

	var gotEmail, gotPassword string
	authenticateSession = func(email, password, _, _ string) (*auth.Session, error) {
		gotEmail, gotPassword = email, password
		return &auth.Session{Email: email, Token: "token", CreatedAt: time.Now(), UpdatedAt: time.Now()}, nil
	}

	out := captureStdout(t, func() { loginCmd.Run(loginCmd, nil) })

	if gotEmail != "env@example.com" || gotPassword != "env-secret" {
		t.Fatalf("authenticate got %q/%q, want env values", gotEmail, gotPassword)
	}
	if !strings.Contains(out, "Successfully logged in as env@example.com.") {
		t.Fatalf("stdout = %q, want success", out)
	}
}
