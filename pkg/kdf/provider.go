package kdf

import "errors"

var ErrUnknownProvider = errors.New("unknown kdf provider")

type Provider interface {
	Name() string
	Derive(password string, salt []byte, keyLen uint32) ([]byte, error)
}
