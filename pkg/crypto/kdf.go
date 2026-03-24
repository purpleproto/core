package crypto

import (
	"github.com/purpleproto/core/pkg/config"
	"github.com/purpleproto/core/pkg/kdf"
	"github.com/purpleproto/core/pkg/kdf/argon2id"
	legacy "github.com/purpleproto/core/pkg/kdf/pbkdf2"
)

func DeriveSessionKey(password string, salt []byte, cfg config.KDFConfig) []byte {
	provider := kdf.MigrationProvider{
		Preferred: argon2id.Provider{
			Time:    cfg.Time,
			Memory:  cfg.Memory,
			Threads: cfg.Threads,
		},
		Legacy: legacy.Provider{
			Iterations: cfg.Iterations,
		},
	}

	key, err := provider.Derive(password, salt, cfg.KeyLen)
	if err != nil {
		panic("invalid KDF configuration: " + err.Error())
	}

	return key
}
