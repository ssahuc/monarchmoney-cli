package auth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/thedavidweng/monarchmoney-cli/internal/config"
	"github.com/thedavidweng/monarchmoney-cli/internal/graphql"
)

const AuthMethodBrowserSession = "browser_session"

type Session struct {
	Profile    string    `json:"profile"`
	Email      string    `json:"email,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	Token      string    `json:"token,omitempty"`
	AuthMethod string    `json:"auth_method,omitempty"`
	SessionID  string    `json:"session_id,omitempty"`
	CSRFToken  string    `json:"csrf_token,omitempty"`
}

func (s *Session) Credentials() graphql.Credentials {
	if s.AuthMethod == AuthMethodBrowserSession {
		return graphql.SessionAuth{SessionID: s.SessionID, CSRFToken: s.CSRFToken}
	}
	return graphql.TokenAuth(s.Token)
}

type Store struct {
	Path string
}

var (
	marshalSession   = json.MarshalIndent
	writeSessionFile = writeFileAtomic
	readSessionFile  = os.ReadFile
)

func NewStore(path string) *Store {
	return &Store{Path: path}
}

func (s *Store) Save(sess *Session) error {
	dir := filepath.Dir(s.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	data, err := marshalSession(sess, "", "  ")
	if err != nil {
		return err
	}

	return writeSessionFile(s.Path, data, 0o600)
}

func (s *Store) Load() (*Session, error) {
	data, err := readSessionFile(s.Path)
	if err != nil {
		return nil, err
	}

	var sess Session
	if err := json.Unmarshal(data, &sess); err != nil {
		return nil, err
	}

	// Stored secrets may use the "env:NAME" indirection form; resolve them here,
	// at the single point where the session becomes usable credentials.
	for _, secret := range []*string{&sess.Token, &sess.SessionID, &sess.CSRFToken} {
		resolved, err := config.ResolveSecret(*secret)
		if err != nil {
			return nil, err
		}
		*secret = resolved
	}

	return &sess, nil
}

func (s *Store) Delete() error {
	return os.Remove(s.Path)
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
