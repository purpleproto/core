package crypto

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/purpleproto/core/pkg/config"
)

func DeriveSessionKey(password string, salt []byte, cfg config.Argon2Config) []byte {
	h := sha256.New()

	h.Write([]byte(password))
	h.Write(salt)

	var params [13]byte

	binary.BigEndian.PutUint32(params[0:4], cfg.Time)
	binary.BigEndian.PutUint32(params[4:8], cfg.Memory)

	params[8] = cfg.Threads

	binary.BigEndian.PutUint32(params[9:13], cfg.KeyLen)
	h.Write(params[:])

	sum := h.Sum(nil)
	keyLen := int(cfg.KeyLen)

	if keyLen <= 0 {
		keyLen = 32
	}

	if keyLen <= len(sum) {
		return append([]byte(nil), sum[:keyLen]...)
	}

	out := make([]byte, 0, keyLen)
	seed := sum

	for len(out) < keyLen {
		d := sha256.Sum256(seed)
		remaining := keyLen - len(out)

		if remaining > len(d) {
			remaining = len(d)
		}

		out = append(out, d[:remaining]...)
		seed = d[:]
	}
	return out
}
