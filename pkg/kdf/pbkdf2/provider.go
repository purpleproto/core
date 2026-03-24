package pbkdf2

import (
	"crypto/pbkdf2"
	"crypto/sha256"
)

type Provider struct {
	Iterations uint32
}

func (p Provider) Name() string { return "pbkdf2-sha256" }

func (p Provider) Derive(password string, salt []byte, keyLen uint32) ([]byte, error) {
	return pbkdf2.Key(sha256.New, password, salt, int(p.Iterations), int(keyLen))
}
