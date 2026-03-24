package config

import (
	"errors"
	"time"

	"github.com/purpleproto/core/pkg/domain"
)

const (
	defaultHeaderSize    = 16
	defaultSessionKeyLen = 32
	defaultKDFIterations = 600000
)

type KDFConfig struct {
	Iterations uint32
	KeyLen     uint32

	// Argon2id params
	Time    uint32
	Memory  uint32
	Threads uint8
}

type Config struct {
	MasterPassword       string
	HTTPFallback         []byte
	HeaderSize           int
	Window               domain.TimestampWindow
	KDF                  KDFConfig
	HandshakeMinDuration time.Duration
	Strategies           []domain.StrategyName
}

func Default(masterPassword string) Config {
	return Config{
		MasterPassword: masterPassword,
		HTTPFallback:   []byte("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"),
		HeaderSize:     defaultHeaderSize,
		Window: domain.TimestampWindow{
			Past:   30 * time.Second,
			Future: 30 * time.Second,
		},
		KDF: KDFConfig{
			Iterations: defaultKDFIterations,
			KeyLen:     defaultSessionKeyLen,
			Time:       1,
			Memory:     64 * 1024,
			Threads:    4,
		},
		HandshakeMinDuration: 5 * time.Millisecond,
		Strategies: []domain.StrategyName{
			domain.StrategyNoise,
		},
	}
}

func (c Config) Validate() error {
	if c.MasterPassword == "" {
		return errors.New("master password required")
	}

	if c.HeaderSize <= 0 {
		return errors.New("header size must be positive")
	}

	if c.KDF.KeyLen == 0 {
		return errors.New("argon2 key length must be positive")
	}

	if c.KDF.Iterations == 0 {
		return errors.New("kdf iterations must be positive")
	}

	if c.KDF.Time == 0 {
		return errors.New("kdf argon2id time must be positive")
	}

	if c.KDF.Memory == 0 {
		return errors.New("kdf argon2id memory must be positive")
	}

	if c.KDF.Threads == 0 {
		return errors.New("kdf argon2id threads must be positive")
	}

	if c.Window.Past < 0 || c.Window.Future < 0 {
		return errors.New("timestamp window must be non-negative")
	}

	if c.HandshakeMinDuration < 0 {
		return errors.New("handshake min duration must be non-negative")
	}

	return nil
}
