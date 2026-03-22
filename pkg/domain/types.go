package domain

import "time"

type Mode string

const (
	ModeFallback Mode = "fallback"
	ModeTunnel   Mode = "tunnel"
)

type StrategyName string

const (
	StrategyHTTPPost StrategyName = "HTTP_POST"
	StrategyTLSFake  StrategyName = "TLS_FAKE"
	StrategyNoise    StrategyName = "NOISE"
)

type TimestampWindow struct {
	Past   time.Duration
	Future time.Duration
}

type HandshakeAttempt struct {
	ObservedAt time.Time
	Header     []byte
}

type Frame struct {
	Nonce      []byte
	Ciphertext []byte
	Padding    []byte
}
