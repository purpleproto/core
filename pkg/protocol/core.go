package protocol

import (
	"fmt"
	"time"

	"github.com/purpleproto/core/pkg/config"
	pcrypto "github.com/purpleproto/core/pkg/crypto"
	"github.com/purpleproto/core/pkg/domain"
	"github.com/purpleproto/core/pkg/handshake"
	"github.com/purpleproto/core/pkg/strategy"
)

type Core struct {
	cfg       config.Config
	handshake *handshake.Service
	chain     strategy.Chain
}

func New(cfg config.Config, strategies ...strategy.Strategy) (*Core, error) {
	hs, err := handshake.NewService(cfg)
	if err != nil {
		return nil, fmt.Errorf("create handshake service: %w", err)
	}

	return &Core{
		cfg:       cfg,
		handshake: hs,
		chain:     strategy.NewChain(strategies...),
	}, nil
}

func (c *Core) InspectHandshake(header []byte, observedAt time.Time) handshake.Result {
	return c.handshake.Inspect(domain.HandshakeAttempt{
		ObservedAt: observedAt,
		Header:     header,
	})
}

func (c *Core) Seal(sessionSalt, payload, aad []byte) (domain.Frame, error) {
	key := pcrypto.DeriveSessionKey(c.cfg.MasterPassword, sessionSalt, c.cfg.KDF)
	nonce, ciphertext, err := pcrypto.SealFrame(key, payload, aad)
	if err != nil {
		return domain.Frame{}, err
	}

	return c.chain.Apply(domain.Frame{Nonce: nonce, Ciphertext: ciphertext})
}

func (c *Core) Open(sessionSalt []byte, frame domain.Frame, aad []byte) ([]byte, error) {
	key := pcrypto.DeriveSessionKey(c.cfg.MasterPassword, sessionSalt, c.cfg.KDF)
	return pcrypto.OpenFrame(key, frame.Nonce, frame.Ciphertext, aad)
}
