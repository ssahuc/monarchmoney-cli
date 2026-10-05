package graphql

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/thedavidweng/monarchmoney-cli/internal/errors"
)

const DefaultUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36"

func UserAgent() string {
	if ua := os.Getenv("MONARCH_USER_AGENT"); ua != "" {
		return ua
	}
	return DefaultUserAgent
}

const (
	maxResponseBody  = 10 << 20
	maxForbiddenBody = 64 << 10
	maxRetries       = 3
	maxRetryWait     = 10 * time.Second
)

type Request struct {
	OperationName string         `json:"operationName"`
	Query         string         `json:"query"`
	Variables     map[string]any `json:"variables"`
}

type Client struct {
	Endpoint string
	Auth     Credentials
	HTTP     *http.Client
}

func (c *Client) ApplyAuth(req *http.Request) {
	if c.Auth != nil {
		c.Auth.Apply(req)
	}
}

func NewClient(endpoint string, auth Credentials, timeout time.Duration) *Client {
	httpClient := &http.Client{
		Timeout:       timeout,
		CheckRedirect: rejectRedirects,
	}
	if transport, ok := http.DefaultTransport.(*http.Transport); ok {
		cloned := transport.Clone()
		cloned.MaxIdleConns = 16
		cloned.MaxIdleConnsPerHost = 8
		cloned.MaxConnsPerHost = 8
		cloned.IdleConnTimeout = 90 * time.Second
		httpClient.Transport = cloned
	}
	return &Client{
		Endpoint: endpoint,
		Auth:     auth,
		HTTP:     httpClient,
	}
}

// forbidden separates Monarch's edge block (Cloudflare 1010, HTML or JSON) from the API's own
// 403, which it returns when a session is missing, expired, or fails the CSRF check.
func forbidden(resp *http.Response) *errors.Error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxForbiddenBody))
	var apiErr struct {
		Detail    string `json:"detail"`
		ErrorCode any    `json:"error_code"`
	}
	isJSON := json.Unmarshal(body, &apiErr) == nil
	if fmt.Sprint(apiErr.ErrorCode) == "1010" || bytes.Contains(bytes.ToLower(body), []byte("cloudflare")) {
		return errors.New(errors.APIError, "request blocked by Monarch's edge protection (HTTP 403)", errors.CatAPI, false, nil)
	}
	if isJSON && apiErr.Detail != "" {
		return errors.New(errors.AuthSessionExpired, "Monarch rejected the session: "+apiErr.Detail, errors.CatAuth, false, nil)
	}
	return errors.New(errors.APIError, "API returned status 403", errors.CatAPI, false, nil)
}

func rejectRedirects(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

func (c *Client) Do(ctx context.Context, reqBody *Request, result any) error {
	return c.doWithAttempts(ctx, reqBody, result, maxRetries+1)
}

// DoMutation executes a single attempt without retry. A transport failure can
// occur after Monarch already accepted the mutation, making its outcome
// ambiguous to the client; retrying would risk duplicating the write.
func (c *Client) DoMutation(ctx context.Context, reqBody *Request, result any) error {
	return c.doWithAttempts(ctx, reqBody, result, 1)
}

func (c *Client) doWithAttempts(ctx context.Context, reqBody *Request, result any, attempts int) error {
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			retryAfter := time.Duration(0)
			if e, ok := lastErr.(*errors.Error); ok && e.RetryAfterMS > 0 {
				retryAfter = time.Duration(e.RetryAfterMS) * time.Millisecond
			}
			if retryAfter > maxRetryWait {
				return lastErr
			}
			delay := retryAfter
			if delay <= 0 {
				delay = time.Duration(1<<uint(attempt-1))*500*time.Millisecond + time.Duration(attempt)*37*time.Millisecond
			}
			select {
			case <-ctx.Done():
				return errors.New(errors.NetworkTimeout, "request canceled during retry backoff", errors.CatNetwork, false, ctx.Err())
			case <-time.After(delay):
			}
		}

		lastErr = c.doOnce(ctx, reqBody, result)
		if lastErr == nil {
			return nil
		}

		if e, ok := lastErr.(*errors.Error); ok && e.Retryable && attempt+1 < attempts {
			continue
		}
		return lastErr
	}
	return lastErr
}

func (c *Client) doOnce(ctx context.Context, reqBody *Request, result any) error {
	body, err := json.Marshal(reqBody)
	if err != nil {
		return errors.New(errors.InternalError, "failed to marshal request", errors.CatInternal, false, err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.Endpoint, bytes.NewBuffer(body))
	if err != nil {
		return errors.New(errors.InternalError, "failed to create request", errors.CatInternal, false, err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Client-Platform", "web")
	req.Header.Set("User-Agent", UserAgent())
	c.ApplyAuth(req)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return errors.New(errors.NetworkUnreachable, "failed to reach Monarch API", errors.CatNetwork, true, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return errors.New(errors.AuthSessionExpired, "session token expired or invalid; run `monarch auth login` again", errors.CatAuth, true, nil)
	}

	if resp.StatusCode == 403 {
		return forbidden(resp)
	}

	if resp.StatusCode == 429 {
		retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
		return errors.NewWithRetryAfter(errors.RateLimited, "Monarch rate limit exceeded", errors.CatAPI, true, retryAfter, nil)
	}

	if resp.StatusCode >= 500 {
		retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
		return errors.NewWithRetryAfter(errors.APIError, fmt.Sprintf("Monarch returned HTTP %d", resp.StatusCode), errors.CatAPI, true, retryAfter, nil)
	}

	if resp.StatusCode != 200 {
		return errors.New(errors.APIError, fmt.Sprintf("API returned status %d", resp.StatusCode), errors.CatAPI, false, nil)
	}

	respData, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return errors.New(errors.InternalError, "failed to read response body", errors.CatInternal, false, err)
	}

	var gqlResp struct {
		Data   any `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	gqlResp.Data = result

	if err := json.Unmarshal(respData, &gqlResp); err != nil {
		return errors.New(errors.APISchemaChanged, "failed to parse GraphQL response", errors.CatAPI, false, err)
	}

	if len(gqlResp.Errors) > 0 {
		msgs := make([]string, len(gqlResp.Errors))
		for i, e := range gqlResp.Errors {
			msgs[i] = e.Message
		}
		return errors.New(errors.APIError, strings.Join(msgs, "; "), errors.CatAPI, false, nil)
	}

	return nil
}

func parseRetryAfter(value string) time.Duration {
	value = strings.TrimSpace(value)
	if seconds, err := strconv.ParseUint(value, 10, 64); err == nil {
		if seconds > uint64(maxRetryWait/time.Second) {
			return maxRetryWait
		}
		return time.Duration(seconds) * time.Second
	}
	if when, err := http.ParseTime(value); err == nil {
		if duration := time.Until(when); duration > 0 {
			if duration > maxRetryWait {
				return maxRetryWait
			}
			return duration
		}
	}
	return 0
}
