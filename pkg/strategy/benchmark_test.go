package strategy

import (
	"testing"

	"github.com/purpleproto/core/pkg/domain"
)

func BenchmarkHTTPPostWrap(b *testing.B) {
	strat := HTTPPost{
		Host:      "test.example.org",
		Path:      "/api/v1/get",
		UserAgent: "Mozilla/5.0",
	}

	frame := domain.Frame{
		Nonce:      make([]byte, 12),
		Ciphertext: make([]byte, 1024),
		Padding:    make([]byte, 128),
	}

	for b.Loop() {
		strat.Wrap(frame)
	}
}

func BenchmarkTLSFakeWrap(b *testing.B) {
	strat := TLSFake{}

	frame := domain.Frame{
		Nonce:      make([]byte, 12),
		Ciphertext: make([]byte, 1024),
		Padding:    make([]byte, 128),
	}

	for b.Loop() {
		strat.Wrap(frame)
	}
}
