package auth

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"

	clierrors "github.com/thedavidweng/monarchmoney-cli/internal/errors"
	"github.com/thedavidweng/monarchmoney-cli/internal/testutil"
)

const (
	sentinelPassword = "SENTINEL_PASSWORD_7f3a"
	sentinelSecret   = "JBSWY3DPEHPK3PXP"
)

func stubLoginResponse(t *testing.T, status int, body string) *[]byte {
	t.Helper()
	originalClientFactory := newLoginHTTPClient
	t.Cleanup(func() { newLoginHTTPClient = originalClientFactory })

	var sent []byte
	newLoginHTTPClient = func() *http.Client {
		return &http.Client{Transport: testutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
			sent, _ = io.ReadAll(req.Body)
			return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewBufferString(body))}, nil
		})}
	}
	return &sent
}

func TestLoginFailureClassification(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		body       string
		mfaCode    string
		mfaSecret  string
		wantCode   clierrors.Code
		wantDetail string
	}{
		{"mfa required error code", 403, `{"detail":"Multi-Factor Auth Required","error_code":"MFA_REQUIRED"}`, "", "", clierrors.AuthMFARequired, "MFA code required"},
		{"mfa required detail only", 403, `{"detail":"Two-factor authentication required"}`, "", "", clierrors.AuthMFARequired, "MFA code required"},
		{"mfa code rejected", 403, `{"detail":"Invalid MFA code"}`, "123456", "", clierrors.AuthMFAInvalid, "Invalid MFA code"},
		{"mfa secret code rejected", 401, `{"error_code":"MFA_REQUIRED"}`, "", sentinelSecret, clierrors.AuthMFAInvalid, "MFA code rejected"},
		{"update app gate without error code", 403, `{"detail":"Please update to the latest version of the app to continue login.","error_code":null}`, "", "", clierrors.AuthRequired, "Please update to the latest version of the app"},
		{"update app gate with email otp code", 403, `{"detail":"Please update to the latest version of the app to continue login.","error_code":"EMAIL_OTP_REQUIRED"}`, "", "", clierrors.AuthRequired, "Please update to the latest version"},
		{"email otp", 403, `{"detail":"Retrieve the code from your email to continue login.","error_code":"EMAIL_OTP_REQUIRED"}`, "", "", clierrors.AuthRequired, "Retrieve the code from your email"},
		{"cloudflare signature block json", 403, `{"detail":"The site owner has blocked access based on your browser's signature.","error_code":1010}`, "", "", clierrors.AuthRequired, "browser's signature"},
		{"cloudflare signature block html", 403, `<!DOCTYPE html><html><title>Access denied | api.monarch.com used Cloudflare to restrict access</title><span>Error code 1010</span></html>`, "", "", clierrors.AuthRequired, "HTTP 403"},
		{"captcha", 403, `{"error_code":"CAPTCHA_REQUIRED"}`, "", "", clierrors.AuthRequired, "CAPTCHA_REQUIRED"},
		{"invalid credentials", 401, `{"detail":"Unable to log in with provided credentials."}`, "", "", clierrors.AuthRequired, "Unable to log in with provided credentials."},
		{"invalid credentials with mfa code supplied", 401, `{"detail":"Unable to log in with provided credentials."}`, "123456", "", clierrors.AuthRequired, "Unable to log in"},
		{"empty 401", 401, ``, "", "", clierrors.AuthRequired, "HTTP 401"},
		{"empty 403", 403, ``, "", "", clierrors.AuthRequired, "HTTP 403"},
		{"server error keeps api error", 500, `{"detail":"Server Error"}`, "", "", clierrors.APIError, "Server Error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stubLoginResponse(t, tt.status, tt.body)

			_, err := Authenticate("a@example.com", sentinelPassword, tt.mfaCode, tt.mfaSecret)

			cliErr, ok := err.(*clierrors.Error)
			if !ok {
				t.Fatalf("error = %#v, want *errors.Error", err)
			}
			if cliErr.Code != tt.wantCode {
				t.Errorf("code = %s, want %s", cliErr.Code, tt.wantCode)
			}
			if !strings.Contains(cliErr.Message, tt.wantDetail) {
				t.Errorf("message = %q, want containing %q", cliErr.Message, tt.wantDetail)
			}
			for _, secret := range []string{sentinelPassword, sentinelSecret, "<html", "DOCTYPE"} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("error %q leaks %q", err.Error(), secret)
				}
			}
		})
	}
}

func TestAuthenticateSuccessWithoutMFAOmitsTOTP(t *testing.T) {
	sent := stubLoginResponse(t, 200, `{"token":"token-no-mfa"}`)

	sess, err := Authenticate("a@example.com", sentinelPassword, "", "")
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if sess.Token != "token-no-mfa" {
		t.Errorf("Token = %q, want %q", sess.Token, "token-no-mfa")
	}
	if strings.Contains(string(*sent), `"totp"`) {
		t.Errorf("request body sent a totp field without MFA: %s", strings.ReplaceAll(string(*sent), sentinelPassword, "<redacted>"))
	}
}
