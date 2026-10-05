package auth

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/thedavidweng/monarchmoney-cli/internal/testutil"
)

func TestStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(filepath.Join(dir, "session", "session.json"))
	now := time.Date(2026, 5, 8, 12, 0, 0, 0, time.UTC)
	sess := &Session{
		Profile:   "default",
		Email:     "a@example.com",
		CreatedAt: now,
		UpdatedAt: now,
		Token:     "token-123",
	}

	if err := store.Save(sess); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	assertFilePerms(t, store.Path, 0o600)

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if loaded.Token != sess.Token {
		t.Errorf("Token = %q, want %q", loaded.Token, sess.Token)
	}
	if loaded.Profile != sess.Profile {
		t.Errorf("Profile = %q, want %q", loaded.Profile, sess.Profile)
	}
	if loaded.Email != sess.Email {
		t.Errorf("Email = %q, want %q", loaded.Email, sess.Email)
	}
	if !loaded.CreatedAt.Equal(sess.CreatedAt) {
		t.Errorf("CreatedAt = %v, want %v", loaded.CreatedAt, sess.CreatedAt)
	}
	if !loaded.UpdatedAt.Equal(sess.UpdatedAt) {
		t.Errorf("UpdatedAt = %v, want %v", loaded.UpdatedAt, sess.UpdatedAt)
	}

	assertNoForbiddenFields(t, store.Path)

	if err := store.Delete(); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := os.Stat(store.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Stat() error = %v, want os.ErrNotExist", err)
	}
}

func assertFilePerms(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("perms = %v, want %v", got, want)
	}
}

func assertNoForbiddenFields(t *testing.T, path string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	for _, forbidden := range []string{"user_id", "household_id", "expires_at", "cookies"} {
		if strings.Contains(string(raw), forbidden) {
			t.Errorf("session file contains forbidden field %q", forbidden)
		}
	}
}

func TestStoreSaveReplacesExistingSession(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(filepath.Join(dir, "session.json"))

	first := &Session{Profile: "default", Email: "old@example.com", Token: "old-token"}
	if err := store.Save(first); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	second := &Session{Profile: "default", Email: "new@example.com", Token: "new-token"}
	if err := store.Save(second); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if loaded.Email != second.Email || loaded.Token != second.Token {
		t.Fatalf("Load() = %#v, want %#v", loaded, second)
	}
}

func TestStoreDeleteMissing(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "missing.json"))
	if err := store.Delete(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Delete() error = %v, want os.ErrNotExist", err)
	}
}

func TestStoreSaveReturnsMkdirError(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocked")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	store := NewStore(filepath.Join(blocker, "session.json"))
	if err := store.Save(&Session{Profile: "default"}); err == nil {
		t.Fatal("Save() error = nil, want failure")
	}
}

func TestStoreLoadReturnsDecodeError(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "session.json"))
	if err := os.WriteFile(store.Path, []byte("not-json"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	if _, err := store.Load(); err == nil {
		t.Fatal("Load() error = nil, want failure")
	}
}

func TestStoreLoadReturnsMissingFileError(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "missing.json"))
	if _, err := store.Load(); err == nil {
		t.Fatal("Load() error = nil, want failure")
	}
}

func TestStoreSaveReturnsWriteError(t *testing.T) {
	original := writeSessionFile
	writeSessionFile = func(string, []byte, os.FileMode) error {
		return errors.New("write failed")
	}
	defer func() { writeSessionFile = original }()

	store := NewStore(filepath.Join(t.TempDir(), "session.json"))
	if err := store.Save(&Session{Profile: "default"}); err == nil {
		t.Fatal("Save() error = nil, want failure")
	}
}

func TestStoreSaveReturnsMarshalError(t *testing.T) {
	original := marshalSession
	marshalSession = func(any, string, string) ([]byte, error) {
		return nil, errors.New("marshal failed")
	}
	defer func() { marshalSession = original }()

	store := NewStore(filepath.Join(t.TempDir(), "session.json"))
	if err := store.Save(&Session{Profile: "default"}); err == nil {
		t.Fatal("Save() error = nil, want failure")
	}
}

func TestAuthenticate(t *testing.T) {
	originalEndpoint := loginEndpoint
	originalClientFactory := newLoginHTTPClient
	defer func() {
		loginEndpoint = originalEndpoint
		newLoginHTTPClient = originalClientFactory
	}()

	testAuthenticateInputValidation(t)
	testAuthenticateFailureResponses(t)
	testAuthenticateSuccessResponses(t)
}

func mustErrContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %v, want containing %q", err, want)
	}
}

func testAuthenticateInputValidation(t *testing.T) {
	t.Helper()

	t.Run("invalid mfa secret", func(t *testing.T) {
		_, err := Authenticate("a@example.com", "password", "", "not-base32")
		mustErrContains(t, err, "failed to generate MFA code")
	})

	t.Run("request creation error", func(t *testing.T) {
		loginEndpoint = "://"
		_, err := Authenticate("a@example.com", "password", "", "")
		mustErrContains(t, err, "failed to create login request")
		loginEndpoint = "https://api.monarch.com/auth/login/"
	})
}

func testAuthenticateFailureResponses(t *testing.T) {
	t.Helper()

	t.Run("network unreachable", func(t *testing.T) {
		newLoginHTTPClient = func() *http.Client {
			return &http.Client{Transport: testutil.RoundTripFunc(func(*http.Request) (*http.Response, error) {
				return nil, errors.New("network down")
			})}
		}
		_, err := Authenticate("a@example.com", "password", "", "")
		mustErrContains(t, err, "failed to reach Monarch API")
	})

	t.Run("api error", func(t *testing.T) {
		newLoginHTTPClient = func() *http.Client {
			return &http.Client{Transport: testutil.RoundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 500, Body: io.NopCloser(bytes.NewBufferString(""))}, nil
			})}
		}
		_, err := Authenticate("a@example.com", "password", "123456", "")
		mustErrContains(t, err, "API returned status 500")
	})

	t.Run("schema changed", func(t *testing.T) {
		newLoginHTTPClient = func() *http.Client {
			return &http.Client{Transport: testutil.RoundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewBufferString("not-json"))}, nil
			})}
		}
		_, err := Authenticate("a@example.com", "password", "123456", "")
		mustErrContains(t, err, "failed to parse login response")
	})
}

func testAuthenticateSuccessResponses(t *testing.T) {
	t.Helper()

	t.Run("success", func(t *testing.T) {
		newLoginHTTPClient = func() *http.Client {
			return &http.Client{Transport: testutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
				body, _ := io.ReadAll(req.Body)
				if !strings.Contains(string(body), `"username":"a@example.com"`) {
					t.Fatalf("request body = %q, want username", string(body))
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewBufferString(`{"token":"token-123"}`))}, nil
			})}
		}
		sess, err := Authenticate("a@example.com", "password", "123456", "")
		if err != nil {
			t.Fatalf("Authenticate() error = %v", err)
		}
		if sess == nil {
			t.Fatal("Authenticate() session = nil")
		}
		if sess.Email != "a@example.com" {
			t.Errorf("Email = %q, want %q", sess.Email, "a@example.com")
		}
		if sess.Token != "token-123" {
			t.Errorf("Token = %q, want %q", sess.Token, "token-123")
		}
		if sess.CreatedAt.IsZero() || sess.UpdatedAt.IsZero() {
			t.Error("CreatedAt/UpdatedAt should not be zero")
		}
	})

	t.Run("success with mfa secret", func(t *testing.T) {
		newLoginHTTPClient = func() *http.Client {
			return &http.Client{Transport: testutil.RoundTripFunc(func(req *http.Request) (*http.Response, error) {
				body, _ := io.ReadAll(req.Body)
				if !strings.Contains(string(body), `"totp"`) {
					t.Fatalf("request body = %q, want totp", string(body))
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewBufferString(`{"token":"token-456"}`))}, nil
			})}
		}
		sess, err := Authenticate("a@example.com", "password", "", "JBSWY3DPEHPK3PXP")
		if err != nil {
			t.Fatalf("Authenticate() error = %v", err)
		}
		if sess == nil {
			t.Fatal("Authenticate() session = nil")
		}
		if sess.Token != "token-456" {
			t.Errorf("Token = %q, want %q", sess.Token, "token-456")
		}
	})
}
