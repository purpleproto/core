package config

import (
	"errors"
	"time"

	"github.com/purpleproto/core/pkg/domain"
)

const (
	defaultHeaderSize = 16
	defaultKeyLen     = 32
)

type Argon2Config struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	KeyLen  uint32
}

type Config struct {
	MasterPassword string
	HTTPFallback   []byte
	HeaderSize     int
	Window         domain.TimestampWindow
	Argon2         Argon2Config
	Strategies     []domain.StrategyName
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
		Argon2: Argon2Config{
			Time:   1,
			Memory: 64 * 1024,
			KeyLen: defaultKeyLen,
		},
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

	if c.Argon2.KeyLen == 0 {
		return errors.New("argon2 key length must be positive")
	}

	if c.Window.Past < 0 || c.Window.Future < 0 {
		return errors.New("timestamp window must be non-negative")
	}

	return nil
}
