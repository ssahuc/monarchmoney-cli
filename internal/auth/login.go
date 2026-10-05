package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/thedavidweng/monarchmoney-cli/internal/errors"
	"github.com/thedavidweng/monarchmoney-cli/internal/graphql"
)

var (
	loginEndpoint        = "https://api.monarch.com/auth/login/"
	maxLoginResponseSize = int64(1 << 20)
	newLoginHTTPClient   = func() *http.Client {
		return &http.Client{
			Timeout:       10 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
)

type loginRequest struct {
	Username      string `json:"username"`
	Password      string `json:"password"`
	SupportsMFA   bool   `json:"supports_mfa"`
	TrustedDevice bool   `json:"trusted_device"`
	TOTP          string `json:"totp,omitempty"`
}

type loginResponse struct {
	Token string `json:"token"`
}

// Authenticate logs in through Monarch's REST endpoint, not GraphQL.
// Monarch answers unrelated rejections (app-version gate, edge block, CAPTCHA, email OTP) with 401/403,
// so MFA is reported only when the response body names an MFA challenge.
func Authenticate(email, password, mfaCode, mfaSecret string) (*Session, error) {
	if mfaSecret != "" {
		code, err := totp.GenerateCode(mfaSecret, time.Now())
		if err != nil {
			return nil, errors.New(errors.InternalError, "failed to generate MFA code", errors.CatInternal, false, err)
		}
		mfaCode = code
	}

	reqBody := loginRequest{
		Username:      email,
		Password:      password,
		SupportsMFA:   true,
		TrustedDevice: true,
		TOTP:          mfaCode,
	}
	body, _ := json.Marshal(reqBody)

	req, err := http.NewRequest("POST", loginEndpoint, bytes.NewBuffer(body))
	if err != nil {
		return nil, errors.New(errors.InternalError, "failed to create login request", errors.CatInternal, false, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Client-Platform", "web")
	req.Header.Set("User-Agent", graphql.UserAgent())

	client := newLoginHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New(errors.NetworkUnreachable, "failed to reach Monarch API", errors.CatNetwork, true, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, loginFailure(resp, mfaCode != "")
	}

	var loginResp loginResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxLoginResponseSize)).Decode(&loginResp); err != nil {
		return nil, errors.New(errors.APISchemaChanged, "failed to parse login response", errors.CatAPI, false, err)
	}

	return &Session{
		Email:     email,
		Token:     loginResp.Token,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}, nil
}

var mfaChallenge = regexp.MustCompile(`(?i)\bmfa\b|multi.?factor|two.?factor|\b2fa\b|\btotp\b`)

func loginFailure(resp *http.Response, mfaSupplied bool) *errors.Error {
	var apiErr struct {
		Detail    string `json:"detail"`
		ErrorCode any    `json:"error_code"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, maxLoginResponseSize)).Decode(&apiErr)
	code := ""
	if apiErr.ErrorCode != nil {
		code = fmt.Sprint(apiErr.ErrorCode)
	}

	if resp.StatusCode != 401 && resp.StatusCode != 403 {
		if apiErr.Detail != "" {
			return errors.New(errors.APIError, apiErr.Detail, errors.CatAPI, false, nil)
		}
		return errors.New(errors.APIError, fmt.Sprintf("API returned status %d", resp.StatusCode), errors.CatAPI, false, nil)
	}

	if code == "MFA_REQUIRED" || mfaChallenge.MatchString(apiErr.Detail) {
		if mfaSupplied {
			return errors.New(errors.AuthMFAInvalid, firstNonEmpty(apiErr.Detail, "MFA code rejected"), errors.CatAuth, false, nil)
		}
		return errors.New(errors.AuthMFARequired, "MFA code required", errors.CatAuth, false, nil)
	}

	reason := firstNonEmpty(apiErr.Detail, code, fmt.Sprintf("HTTP %d", resp.StatusCode))
	return errors.New(errors.AuthRequired, "Monarch rejected the login: "+reason, errors.CatAuth, false, nil)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
