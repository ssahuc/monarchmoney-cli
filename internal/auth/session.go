package auth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/thedavidweng/monarchmoney-cli/internal/config"
)

type Session struct {
	Profile   string    `json:"profile"`
	Email     string    `json:"email,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Token     string    `json:"token,omitempty"`
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

	// The stored token may use the "env:NAME" indirection form; resolve it to
	// the real secret here, at the single point where the session becomes
	// usable credentials. A literal token is returned unchanged.
	token, err := config.ResolveSecret(sess.Token)
	if err != nil {
		return nil, err
	}
	sess.Token = token

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
